#if os(macOS)
import Diagnostics
import Foundation
import GPCore
import Network

/// What a `TunnelHost` hands back to whoever owns the session: HIP reports,
/// re-auth, cookie saves, state and log lines. `PacketFlowHost` and
/// `UtunHost` both take one.
public struct HostHooks: Sendable {
    public var hipReport: @Sendable (HIPContext) async throws -> String?
    public var reauthenticate: @Sendable () async throws -> AuthCookie
    public var saveCookie: @Sendable (AuthCookie?) -> Void
    public var stateChanged: @Sendable (SessionState) -> Void
    public var log: @Sendable (String) -> Void

    public init(hipReport: @escaping @Sendable (HIPContext) async throws -> String?,
                reauthenticate: @escaping @Sendable () async throws -> AuthCookie,
                saveCookie: @escaping @Sendable (AuthCookie?) -> Void,
                stateChanged: @escaping @Sendable (SessionState) -> Void,
                log: @escaping @Sendable (String) -> Void) {
        self.hipReport = hipReport
        self.reauthenticate = reauthenticate
        self.saveCookie = saveCookie
        self.stateChanged = stateChanged
        self.log = log
    }
}

/// A `TunnelHost` that also moves packets between the OS and a runner.
public protocol PacketHost: TunnelHost {
    /// Sends what the OS hands the tunnel through `runner`, in order.
    func pumpPackets(to runner: SessionRunner)
    /// The physical network changed.
    func pathChanged()
    /// Undoes whatever the host changed. Called once, after the session ends.
    func shutdown()
    /// Addresses to dial the gateway at instead of looking it up, if any.
    var gatewayAddresses: GatewayAddressBook? { get }
}

extension PacketHost {
    public var gatewayAddresses: GatewayAddressBook? { nil }
}

extension UtunHost: PacketHost {}

/// One tunnel session for one profile: login (or a saved cookie), the
/// session runner, diagnostics, cookie and password storage, re-auth. The
/// packet tunnel extension and the root helper both run their tunnel through
/// it; each supplies its own `PacketHost` and HIP reports.
public final class TunnelController: @unchecked Sendable {
    public struct Configuration: Sendable {
        public var profile: Profile
        /// The password the user just typed, or nil to use the saved one.
        public var password: String?
        public var diagnostics: DiagnosticsSettings
        public var diagnosticsDirectory: URL
        /// Where passwords and cookies are kept.
        public var keychain: KeychainStore
        /// Pin gateway connections to the physical interface (albi-cli's
        /// --pin-interface). Off: the host route to the gateway is enough.
        public var pinInterface: Bool

        public init(profile: Profile, password: String?, diagnostics: DiagnosticsSettings = DiagnosticsSettings(),
                    diagnosticsDirectory: URL = DiagnosticsSettings.systemDirectory, keychain: KeychainStore,
                    pinInterface: Bool = false) {
            self.profile = profile
            self.password = password
            self.diagnostics = diagnostics
            self.diagnosticsDirectory = diagnosticsDirectory
            self.keychain = keychain
            self.pinInterface = pinInterface
        }
    }

    /// What the controller reports while it works.
    public enum Event: Sendable {
        /// Logging in (the first login, or a re-auth).
        case authenticating
        /// The challenge went out with the profile's fixed answer ("1" asks
        /// for a push) and the gateway is waiting on the user's phone.
        case waitingForPush
        /// The gateway wants a code and the profile asks each time.
        case needsSecondFactor(prompt: String)
        case state(SessionState)
        case log(String)
    }

    /// What the app shows about the session.
    public struct Snapshot: Sendable {
        public var gateway: String?
        public var settings: TunnelSettings?
        public var connectedSince: Date?
        public var cookieExpiry: Date?
        public var hipRequested = false
        public var hipLastSent: Date?
        public var lastIncident: String?
    }

    public typealias MakeHost = @Sendable (_ hooks: HostHooks, _ gateway: String, _ watcher: PathWatcher) throws -> any PacketHost

    public let configuration: Configuration
    private let hipReport: @Sendable (HIPContext) async throws -> String?
    private let askSecondFactor: (@Sendable (String) async throws -> String)?
    private let makeHost: MakeHost
    private let onEvent: @Sendable (Event) -> Void

    private let lock = NSLock()
    private var runner: SessionRunner?
    private var host: (any PacketHost)?
    private var watcher: PathWatcher?
    private var diagnostics: Diagnostics?
    private var cookies: CookieStore?
    private var snapshotValue = Snapshot()
    private var loggedInAt: Date?
    private var logoutOnStop = false
    private var stopped = false

    public init(_ configuration: Configuration,
                hipReport: @escaping @Sendable (HIPContext) async throws -> String?,
                askSecondFactor: (@Sendable (String) async throws -> String)? = nil,
                makeHost: @escaping MakeHost,
                onEvent: @escaping @Sendable (Event) -> Void) {
        self.configuration = configuration
        self.hipReport = hipReport
        self.askSecondFactor = askSecondFactor
        self.makeHost = makeHost
        self.onEvent = onEvent
    }

    /// What the app shows: the gateway's settings, times, HIP, the newest
    /// incident file.
    public func snapshot() async -> Snapshot {
        await refreshSettings()
        var s = lock.withLock { snapshotValue }
        s.lastIncident = lock.withLock { diagnostics }?.lastIncident?.path
        return s
    }

    public var state: SessionState {
        get async { await lock.withLock({ runner })?.state ?? .idle }
    }

    /// The keychain account a profile's saved password lives under.
    public static func passwordAccount(_ p: Profile) -> String { "password:\(p.username)@\(p.server)" }

    /// The password the user typed this time, else the saved one.
    var password: String? {
        configuration.password ??
            configuration.keychain.get(Self.passwordAccount(configuration.profile)).map { String(decoding: $0, as: UTF8.self) }
    }

    /// Logs in (or picks up the saved cookie) and starts the session. Returns
    /// once the session is running; `waitUntilConnected` waits for the tunnel.
    public func start() async throws {
        let profile = configuration.profile
        let keychain = configuration.keychain
        if let pw = configuration.password {
            keychain.set(Self.passwordAccount(profile), profile.savePassword ? Data(pw.utf8) : nil)
        }
        let password = password
        let clock = ContinuousSessionClock()
        var client = ClientInfo(computer: ProcessInfo.processInfo.hostName)
        let log: @Sendable (String) -> Void = { [onEvent] in onEvent(.log($0)) }

        // Diagnostics mode: record the session and write a redacted incident
        // file when an outage isn't recovered. The connector is wrapped
        // before login so the setup exchanges are recorded too.
        var diag: Diagnostics?
        if configuration.diagnostics.enabled {
            let d = Diagnostics(settings: configuration.diagnostics, directory: configuration.diagnosticsDirectory, clock: clock,
                                secrets: KnownSecrets(password: password, servers: [profile.server], computer: client.computer)) { _, line in
                log("diagnostics: \(line)")
            }
            d.start()
            diag = d
            lock.withLock { diagnostics = d }
        }

        let watcherBox = RunnerRef()
        let watcher = PathWatcher { usable in watcherBox.pathChanged(usable: usable) }
        watcher.start()
        lock.withLock { self.watcher = watcher }

        var pin: (@Sendable () -> NWInterface?)?
        if configuration.pinInterface { pin = { [watcher] in watcher.primaryInterface } }
        // The host, made after login, fills this in.
        let book = BookRef()
        let base = NWGatewayConnector(trust: profile.trust, requiredInterface: pin,
                                      address: { book.value?.address(for: $0) })
        let connector: any GatewayConnector = diag.map { RecordingConnector(base, recorder: $0.recorder, clock: clock) } ?? base

        // A saved cookie lets the tunnel come back after a disconnect, sleep
        // or restart without a new login (and without a push). If the
        // gateway rejects it, the session logs in again.
        let cookies = CookieStore(store: keychain, username: profile.username, server: profile.server)
        lock.withLock { self.cookies = cookies }
        var cookie: AuthCookie?
        var gateway: String?
        var hipInterval: Double?
        if let saved = cookies.load(mode: profile.mode, clearedAt: profile.cookiesClearedAt) {
            log("reusing the saved cookie for \(saved.gateway)")
            cookie = saved.cookie
            gateway = saved.gateway
            hipInterval = saved.hipInterval
            if let v = saved.appVersion { client.appVersion = v }
            lock.withLock { loggedInAt = saved.savedAt }
        }
        if cookie == nil {
            guard let password else { throw ControllerError("no saved password: log in from the app") }
            onEvent(.authenticating)
            let r = try await Login(transport: connector, credentials: credentials(password: password), client: client,
                                    username: profile.username)
                .run(profile.target)
            cookie = r.cookie
            gateway = r.gateway
            if let v = r.portal?.version { client.appVersion = v }
            diag?.recorder.setInfo("portal-version", r.portal?.version)
            hipInterval = r.portal?.hipReportInterval.map(Double.init)
            saveCookie(r.cookie, gateway: r.gateway, appVersion: client.appVersion, hipInterval: hipInterval)
        }
        guard let cookie, let gateway else { throw ControllerError("login gave no cookie") }
        lock.withLock { snapshotValue.gateway = gateway }
        diag?.updateSecrets {
            $0.cookies.append(cookie)
            $0.servers.append(gateway)
        }

        var policy = SessionPolicy()
        policy.canReauthenticate = password != nil && (profile.secondFactor != nil || askSecondFactor != nil)

        let clientInfo = client
        let interval = hipInterval
        let hooks = HostHooks(
            hipReport: { [weak self, hipReport] ctx in
                self?.lock.withLock { self?.snapshotValue.hipRequested = true }
                let report = try await hipReport(ctx)
                if report != nil { self?.lock.withLock { self?.snapshotValue.hipLastSent = Date() } }
                return report
            },
            reauthenticate: { [weak self] in
                guard let self else { throw CancellationError() }
                guard let pw = self.password else { throw StoredCredentials.NeedsUser() }
                self.onEvent(.authenticating)
                let r = try await Login(transport: connector, credentials: self.credentials(password: pw), client: clientInfo,
                                        username: profile.username)
                    .run(profile.target)
                // The session keeps talking to the gateway it started with.
                self.lock.withLock { self.loggedInAt = Date() }
                return r.cookie
            },
            saveCookie: { [weak self] c in
                guard let self else { return }
                if let c {
                    self.saveCookie(c, gateway: gateway, appVersion: clientInfo.appVersion, hipInterval: interval)
                } else {
                    cookies.remove(gateway: gateway)
                }
            },
            stateChanged: { [weak self] s in self?.stateChanged(s) },
            log: log
        )
        let host = try makeHost(hooks, gateway, watcher)
        book.value = host.gatewayAddresses
        let runner = SessionRunner(server: gateway, client: client,
                                   session: Session(cookie: cookie, policy: policy, hipInterval: hipInterval),
                                   io: connector, host: host, clock: clock, recorder: diag?.recorder)
        let wasStopped = lock.withLock { () -> Bool in
            self.host = host
            self.runner = runner
            return stopped
        }
        watcherBox.set(runner, host)
        if wasStopped {
            host.shutdown()
            throw CancellationError()
        }
        await runner.start()
        host.pumpPackets(to: runner)
    }

    /// Waits until the tunnel is up the first time. Throws if the session
    /// ends or needs a login first.
    public func waitUntilConnected() async throws {
        guard let runner = lock.withLock({ runner }) else { throw ControllerError("not started") }
        while true {
            switch await runner.state {
            case .connected: return
            case .needsLogin(let why), .stopped(let why): throw ControllerError(why)
            default: try await Task.sleep(for: .milliseconds(100))
            }
        }
    }

    /// Waits until the session ends and returns how it ended.
    public func waitUntilFinished() async -> SessionState {
        guard let runner = lock.withLock({ runner }) else { return .stopped(reason: "not started") }
        return await runner.waitUntilFinished()
    }

    /// Stops the session. Nothing logs out, Disconnect included: the cookie
    /// stays saved so the next connect skips the login while the gateway
    /// still takes it. Only `clearCookies()` while connected logs out here.
    public func stop() async {
        let (runner, host, watcher, diag, logout) = lock.withLock {
            stopped = true
            return (self.runner, self.host, self.watcher, diagnostics, logoutOnStop)
        }
        watcher?.stop()
        await runner?.stop(logout: logout)
        diag?.stop()
        host?.shutdown()
    }

    public func sleep() async { await lock.withLock({ runner })?.post(.sleep) }
    public func wake() async { await lock.withLock({ runner })?.post(.wake) }

    /// "Save diagnostics now".
    public func saveDiagnosticsNow() {
        lock.withLock { diagnostics }?.saveNow()
    }

    /// "Clear stored cookies" while connected: forget the cookie now and log
    /// out when the session stops.
    public func clearCookies() {
        let (cookies, gateway) = lock.withLock {
            logoutOnStop = true
            return (self.cookies, snapshotValue.gateway)
        }
        cookies?.remove(gateway: gateway)
    }

    /// The gateway config the session has now, as tunnel settings.
    private func refreshSettings() async {
        guard let runner = lock.withLock({ runner }), let config = await runner.config else { return }
        lock.withLock {
            guard let gateway = snapshotValue.gateway else { return }
            snapshotValue.settings = TunnelSettings(config: config, remoteAddress: gateway)
            if let lifetime = config.lifetime {
                let start = loggedInAt ?? snapshotValue.connectedSince ?? Date()
                snapshotValue.cookieExpiry = start.addingTimeInterval(Double(lifetime))
            }
        }
    }

    private func stateChanged(_ s: SessionState) {
        if s == .connected {
            lock.withLock {
                if snapshotValue.connectedSince == nil { snapshotValue.connectedSince = Date() }
                if loggedInAt == nil { loggedInAt = Date() }
            }
        }
        onEvent(.state(s))
    }

    private func saveCookie(_ c: AuthCookie, gateway: String, appVersion: String, hipInterval: Double?) {
        let now = Date()
        lock.withLock {
            loggedInAt = loggedInAt ?? now
            return cookies
        }?.save(SavedCookie(cookie: c, gateway: gateway, appVersion: appVersion, hipInterval: hipInterval, savedAt: now))
    }

    /// Answers the login's prompts from the profile, the password, and (for
    /// a profile that asks each time) the user, through `askSecondFactor`.
    func credentials(password: String) -> ControllerCredentials {
        ControllerCredentials(username: configuration.profile.username, password: password,
                              secondFactor: configuration.profile.secondFactor, ask: askSecondFactor, onEvent: onEvent)
    }
}

struct ControllerCredentials: CredentialProvider {
    var username: String
    var password: String
    var secondFactor: String?
    var ask: (@Sendable (String) async throws -> String)?
    var onEvent: @Sendable (TunnelController.Event) -> Void

    func answer(_ prompt: CredentialPrompt) async throws -> String {
        switch prompt {
        case .username:
            return username
        case .password(_, _, _, false):
            return password
        case .password(_, _, _, true):
            throw GPError.badCredentials("the gateway rejected the username or password")
        case .challenge(let message):
            if let secondFactor {
                if secondFactor == "1" || secondFactor.lowercased() == "push" { onEvent(.waitingForPush) }
                return secondFactor
            }
            guard let ask else { throw StoredCredentials.NeedsUser() }
            onEvent(.needsSecondFactor(prompt: message))
            let code = try await ask(message)
            onEvent(.authenticating)
            return code
        }
    }
}

final class BookRef: @unchecked Sendable {
    private let lock = NSLock()
    private var book: GatewayAddressBook?
    var value: GatewayAddressBook? {
        get { lock.withLock { book } }
        set { lock.withLock { book = newValue } }
    }
}

/// Lets the path watcher, made before the runner, reach it once it exists.
final class RunnerRef: @unchecked Sendable {
    private let lock = NSLock()
    private var runner: SessionRunner?
    private var host: (any PacketHost)?

    func set(_ r: SessionRunner, _ h: any PacketHost) { lock.withLock { runner = r; host = h } }

    func pathChanged(usable: Bool) {
        let (r, h) = lock.withLock { (runner, host) }
        h?.pathChanged()
        guard let r else { return }
        Task { await r.post(.pathChanged(usable: usable)) }
    }
}

public struct ControllerError: LocalizedError, CustomStringConvertible {
    public var message: String
    public init(_ m: String) { message = m }
    public var errorDescription: String? { message }
    public var description: String { message }
}
#endif
