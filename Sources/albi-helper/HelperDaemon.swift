#if os(macOS)
import Diagnostics
import Foundation
import GPCore
import GPMac
import os

private let log = Logger(subsystem: "com.github.njvack.albi", category: "helper")

enum HelperDaemon {
    /// Identifies this binary: its size and modification time. The app
    /// compares it with the helper in its own bundle to spot a helper that
    /// launchd is still running from before a rebuild.
    static var build: String {
        executable.flatMap { HelperBuild.id(ofExecutableAt: $0.path) } ?? "unknown"
    }

    /// This process's binary. Not Bundle.main: inside the app, that is the
    /// app's own executable.
    static var executable: URL? {
        var size: UInt32 = 0
        _ = _NSGetExecutablePath(nil, &size)
        var buf = [CChar](repeating: 0, count: Int(size) + 1)
        guard _NSGetExecutablePath(&buf, &size) == 0 else { return nil }
        return URL(fileURLWithPath: String(cString: buf)).resolvingSymlinksInPath()
    }

    static func main() {
        signal(SIGPIPE, SIG_IGN)
        let removed = NetConfig.sweep { log.notice("\($0, privacy: .public)") }
        if !removed.isEmpty { log.notice("startup sweep removed \(removed.count) route(s)") }

        let core = HelperCore()
        let listener = NSXPCListener(machServiceName: AlbiHelper.label)
        let delegate = ListenerDelegate(core: core)
        listener.delegate = delegate
        listener.resume()
        log.notice("albi-helper started (build \(build, privacy: .public), pid \(getpid()))")

        // launchd sends SIGTERM to stop us (unload, shutdown, unregister).
        // Take the tunnel down without logging out and without touching the
        // desired state, so the next start reconnects.
        var sources: [DispatchSourceSignal] = []
        for sig in [SIGTERM, SIGINT] {
            signal(sig, SIG_IGN)
            let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            src.setEventHandler {
                log.notice("signal \(sig): stopping")
                Task {
                    await core.shutdown()
                    exit(0)
                }
            }
            src.resume()
            sources.append(src)
        }
        Task { await core.start() }
        withExtendedLifetime((listener, delegate, sources)) { dispatchMain() }
    }
}

final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    let core: HelperCore

    init(core: HelperCore) { self.core = core }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        // Phase 4 checks the caller's code signature here.
        c.exportedInterface = AlbiHelper.interface()
        c.exportedObject = Exported(core: core)
        c.remoteObjectInterface = AlbiHelper.clientInterface()
        let client = HelperClient(c)
        c.invalidationHandler = { [core] in Task { await core.remove(client) } }
        c.interruptionHandler = { [core] in Task { await core.remove(client) } }
        Task { await core.add(client) }
        c.resume()
        return true
    }
}

final class HelperClient: @unchecked Sendable, Hashable {
    let connection: NSXPCConnection
    init(_ c: NSXPCConnection) { connection = c }

    func send(_ data: Data) {
        (connection.remoteObjectProxyWithErrorHandler { _ in } as? AlbiHelperClientXPC)?.statusChanged(data)
    }

    static func == (a: HelperClient, b: HelperClient) -> Bool { a === b }
    func hash(into h: inout Hasher) { h.combine(ObjectIdentifier(self)) }
}

final class Exported: NSObject, AlbiHelperXPC {
    let core: HelperCore
    init(core: HelperCore) { self.core = core }

    func call(_ request: Data, reply: @escaping @Sendable (Data) -> Void) {
        let req: HelperRequest
        do {
            req = try HelperCoding.decode(HelperRequest.self, request)
        } catch {
            reply(HelperCoding.encode(HelperReply(error: "albi-helper could not read the request: \(error)")))
            return
        }
        Task {
            let r = await core.handle(req)
            reply(HelperCoding.encode(r))
        }
    }
}

/// The helper's state: profiles, the desired state, the running tunnel and
/// the clients watching it.
actor HelperCore {
    private var stored = HelperProfiles()
    private var desired = HelperDesiredState(profile: nil, wantConnected: false)
    private var controller: TunnelController?
    /// Bumped for each connect, so a stale task's results are ignored.
    private var generation = 0
    private var status = HelperStatus()
    private var clients: Set<HelperClient> = []
    private var codeWaiter: CheckedContinuation<String, Error>?
    private var power: PowerWatcher?
    private let keychain = KeychainStore(service: "com.github.njvack.albi.helper")
    private let hip = BundledHIP(executable: HelperCore.hipreport())

    /// The hipreport beside this binary: albi-hipreport in the app (the
    /// extension's sandboxed hipreport can't run outside a sandbox), or
    /// hipreport in a SwiftPM build directory.
    static func hipreport() -> URL? {
        guard let dir = HelperDaemon.executable?.deletingLastPathComponent() else { return nil }
        return ["albi-hipreport", "hipreport"].map { dir.appendingPathComponent($0) }
            .first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }

    /// Reads the saved files, before the listener takes requests.
    init() {
        stored = Self.read(HelperProfiles.self, AlbiHelper.profilesFile) ?? HelperProfiles()
        desired = Self.read(HelperDesiredState.self, AlbiHelper.stateFile)
            ?? HelperDesiredState(profile: nil, wantConnected: false)
    }

    /// Watches sleep and wake, and reconnects if the saved state says so.
    func start() {
        let p = PowerWatcher { [weak self] e in
            Task { await self?.powerEvent(e) }
        }
        if !p.start() { log.error("could not watch for sleep and wake") }
        power = p
        if desired.wantConnected, let id = desired.profile, stored.profiles.contains(where: { $0.id == id }) {
            log.notice("reconnecting, as the saved state asks")
            connect(id, password: nil)
        }
    }

    func shutdown() async {
        power?.stop()
        await controller?.stop()
        controller = nil
    }

    func add(_ c: HelperClient) { clients.insert(c) }
    func remove(_ c: HelperClient) { clients.remove(c) }

    // MARK: Requests

    func handle(_ req: HelperRequest) async -> HelperReply {
        switch req {
        case .hello:
            return HelperReply(version: AlbiHelper.protocolVersion, build: HelperDaemon.build)
        case .loadProfiles:
            return HelperReply(profiles: stored.profiles)
        case .saveProfile(let p):
            if let i = stored.profiles.firstIndex(where: { $0.id == p.id }) {
                let old = stored.profiles[i].profile
                if old.username != p.profile.username || old.server != p.profile.server || !p.profile.savePassword {
                    keychain.set(TunnelController.passwordAccount(old), nil)
                }
                stored.profiles[i] = p
            } else {
                stored.profiles.append(p)
            }
            return saveProfiles()
        case .deleteProfile(let id):
            if let p = stored.profiles.first(where: { $0.id == id }) {
                keychain.set(TunnelController.passwordAccount(p.profile), nil)
            }
            stored.profiles.removeAll { $0.id == id }
            if desired.profile == id { setDesired(HelperDesiredState(profile: nil, wantConnected: false)) }
            return saveProfiles()
        case .hasSavedPassword(let id):
            guard let p = stored.profiles.first(where: { $0.id == id }), p.profile.savePassword else { return HelperReply(flag: false) }
            return HelperReply(flag: keychain.get(TunnelController.passwordAccount(p.profile)) != nil)
        case .connect(let id, let password):
            guard stored.profiles.contains(where: { $0.id == id }) else { return HelperReply(error: "No such profile.") }
            await stopController()
            setDesired(HelperDesiredState(profile: id, wantConnected: true))
            connect(id, password: password)
            return HelperReply()
        case .disconnect:
            setDesired(HelperDesiredState(profile: desired.profile, wantConnected: false))
            if controller != nil {
                update { $0.state = .disconnecting }
                await stopController()
            }
            codeWaiter?.resume(throwing: GPError.cancelled)
            codeWaiter = nil
            update { s in s = HelperStatus(profileID: s.profileID, lastIncident: s.lastIncident) }
            return HelperReply()
        case .answerSecondFactor(let code):
            codeWaiter?.resume(returning: code)
            codeWaiter = nil
            return HelperReply()
        case .status:
            await refresh()
            return HelperReply(status: status)
        case .diagnosticsSettings:
            return HelperReply(diagnostics: stored.diagnostics)
        case .setDiagnosticsSettings(let d):
            stored.diagnostics = d
            return saveProfiles()
        case .saveDiagnosticsNow:
            controller?.saveDiagnosticsNow()
            try? await Task.sleep(for: .milliseconds(500))
            await refresh()
            return HelperReply()
        }
    }

    // MARK: The tunnel

    private func connect(_ id: UUID, password: String?) {
        guard let p = stored.profiles.first(where: { $0.id == id }) else { return }
        generation += 1
        let gen = generation
        status = HelperStatus(profileID: id, state: .authenticating)
        broadcast()
        Task { await run(p, password: password, generation: gen) }
    }

    /// Runs one profile until it's stopped, needs a login, or is replaced.
    /// A start that fails for a reason that may pass (no network yet, the
    /// gateway unreachable) is retried with backoff.
    private func run(_ p: StoredProfile, password: String?, generation gen: Int) async {
        var attempt = 0
        var password = password
        while gen == generation {
            let c = makeController(p, password: password, generation: gen)
            controller = c
            do {
                try await c.start()
            } catch {
                await c.stop()
                guard gen == generation else { return }
                controller = nil
                if Self.needsUser(error) {
                    update { $0.state = .needsLogin(reason: Self.describe(error)) }
                    return
                }
                attempt += 1
                // The password was just typed: keep it for the retry only if
                // the profile doesn't save it (else the keychain has it).
                if p.profile.savePassword { password = nil }
                let delay = min(60.0, 5.0 * pow(2.0, Double(attempt - 1)))
                log.notice("start failed (\(Self.describe(error), privacy: .public)); retrying in \(Int(delay)) s")
                update { $0.state = .reconnecting(attempt: attempt, reason: Self.describe(error)) }
                try? await Task.sleep(for: .seconds(delay))
                continue
            }
            let end = await c.waitUntilFinished()
            guard gen == generation else { return }
            await c.stop()
            controller = nil
            await refresh()
            switch end {
            case .needsLogin(let why):
                update { $0.state = .needsLogin(reason: why) }
            default:
                update { s in s = HelperStatus(profileID: s.profileID, lastIncident: s.lastIncident) }
            }
            return
        }
    }

    private func makeController(_ p: StoredProfile, password: String?, generation gen: Int) -> TunnelController {
        let profile = p.profile
        let serverHost = Self.host(profile.server)
        let config = TunnelController.Configuration(profile: profile, password: password, diagnostics: stored.diagnostics,
                                                    keychain: keychain)
        return TunnelController(
            config,
            hipReport: { [hip] ctx in try await hip.report(for: ctx) },
            askSecondFactor: { [weak self] prompt in
                guard let self else { throw GPError.cancelled }
                return try await self.waitForCode(prompt)
            },
            makeHost: { hooks, gateway, watcher in
                try UtunHost(dnsMode: .split, gatewayHosts: [serverHost, Self.host(gateway)],
                             router: { [watcher] in watcher.ipv4Router }, hooks: hooks)
            },
            onEvent: { [weak self] e in
                Task { await self?.event(e, generation: gen) }
            })
    }

    private func stopController() async {
        generation += 1
        let c = controller
        controller = nil
        await c?.stop()
    }

    private func event(_ e: TunnelController.Event, generation gen: Int) async {
        if case .log(let m) = e {
            log.info("\(m, privacy: .public)")
            return
        }
        guard gen == generation else { return }
        switch e {
        case .authenticating: status.state = .authenticating
        case .waitingForPush: status.state = .waitingForPush
        case .needsSecondFactor(let prompt): status.state = .needsSecondFactor(prompt: prompt)
        case .state(let s):
            log.notice("state \(String(describing: s), privacy: .public)")
            switch s {
            case .idle: return
            case .connecting(let phase): status.state = .connecting(phase: "\(phase)")
            case .connected: status.state = .connected
            case .reconnecting(let n, let why): status.state = .reconnecting(attempt: n, reason: why)
            case .waitingForNetwork: status.state = .waitingForNetwork
            case .reauthenticating: status.state = .authenticating
            case .needsLogin(let why): status.state = .needsLogin(reason: why)
            // `run` sets the final state once the session has ended.
            case .stopped: return
            }
        case .log: return
        }
        await refresh()
        broadcast()
    }

    private func waitForCode(_ prompt: String) async throws -> String {
        codeWaiter?.resume(throwing: GPError.cancelled)
        // Nobody may be there to answer (the app isn't running): give up
        // after five minutes, so the session can say a login is needed.
        let timeout = Task { [weak self] in
            try await Task.sleep(for: .seconds(300))
            await self?.expireCode()
        }
        defer { timeout.cancel() }
        return try await withCheckedThrowingContinuation { codeWaiter = $0 }
    }

    private func expireCode() {
        codeWaiter?.resume(throwing: GPError.badCredentials("no verification code was entered"))
        codeWaiter = nil
    }

    private func powerEvent(_ e: PowerWatcher.Event) async {
        switch e {
        case .willSleep: await controller?.sleep()
        case .didWake: await controller?.wake()
        }
    }

    // MARK: Status

    private func refresh() async {
        guard let c = controller else { return }
        let snap = await c.snapshot()
        status.gateway = snap.gateway
        status.ipv4 = snap.settings?.ipv4Address
        status.connectedSince = snap.connectedSince
        status.cookieExpiry = snap.cookieExpiry
        if let s = snap.settings {
            status.routes = s.isFullTunnel ? [] : s.includedIPv4.map { "\($0.address)/\($0.prefixLength)" }
            status.dnsDomains = s.matchDomains ?? s.searchDomains
        }
        status.hipRequested = snap.hipRequested
        status.hipLastSent = snap.hipLastSent
        status.lastIncident = snap.lastIncident ?? status.lastIncident
    }

    private func update(_ change: (inout HelperStatus) -> Void) {
        change(&status)
        broadcast()
    }

    private func broadcast() {
        let data = HelperCoding.encode(status)
        for c in clients { c.send(data) }
    }

    // MARK: Files

    private func saveProfiles() -> HelperReply {
        do {
            try Self.write(stored, AlbiHelper.profilesFile)
            return HelperReply(profiles: stored.profiles)
        } catch {
            return HelperReply(error: "Couldn't save profiles: \(error.localizedDescription)")
        }
    }

    private func setDesired(_ d: HelperDesiredState) {
        desired = d
        do { try Self.write(d, AlbiHelper.stateFile) } catch { log.error("writing the desired state: \(error.localizedDescription, privacy: .public)") }
    }

    static func read<T: Decodable>(_ t: T.Type, _ url: URL) -> T? {
        guard let d = try? Data(contentsOf: url) else { return nil }
        do {
            return try HelperCoding.decode(t, d)
        } catch {
            log.error("unreadable \(url.path, privacy: .public): \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }

    /// Root-owned, readable by everyone (no secrets: those are in the keychain).
    static func write<T: Encodable>(_ v: T, _ url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o755])
        try HelperCoding.encode(v).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
    }

    // MARK: Helpers

    /// Errors only the user can fix: a login is needed.
    static func needsUser(_ e: Error) -> Bool {
        if e is StoredCredentials.NeedsUser || e is ControllerError { return true }
        if let g = e as? GPError {
            switch g {
            case .badCredentials, .cookieRejected, .certificateRequired, .cancelled: return true
            default: return false
            }
        }
        return false
    }

    static func describe(_ e: Error) -> String {
        if e is StoredCredentials.NeedsUser { return "The gateway needs you to log in." }
        if let g = e as? GPError {
            switch g {
            case .badCredentials(let m): return m.isEmpty ? "The gateway rejected the login." : m
            case .cookieRejected: return "The gateway ended the session."
            case .cancelled: return "Login cancelled."
            default: return "\(g)"
            }
        }
        return (e as? LocalizedError)?.errorDescription ?? "\(e)"
    }

    /// "host:port" → "host".
    static func host(_ server: String) -> String {
        if server.hasPrefix("[") { return String(server.dropFirst().prefix { $0 != "]" }) }
        let parts = server.split(separator: ":")
        return parts.count == 2 ? String(parts[0]) : server
    }
}

/// `albi-helper status`: prints the running helper's status as JSON.
enum HelperStatusCommand {
    static func run() {
        let c = NSXPCConnection(machServiceName: AlbiHelper.label, options: .privileged)
        c.remoteObjectInterface = AlbiHelper.interface()
        c.resume()
        let done = DispatchSemaphore(value: 0)
        let proxy = c.remoteObjectProxyWithErrorHandler { e in
            print("albi-helper isn't answering: \(e.localizedDescription)")
            exit(1)
        } as? AlbiHelperXPC
        for req in [HelperRequest.hello, .status] {
            proxy?.call(HelperCoding.encode(req)) { data in
                print(String(decoding: data, as: UTF8.self))
                done.signal()
            }
            if done.wait(timeout: .now() + 5) == .timedOut {
                print("albi-helper didn't answer in 5 s")
                exit(1)
            }
        }
        exit(0)
    }
}
#endif
