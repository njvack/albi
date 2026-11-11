import Diagnostics
import Foundation
import GPCore
import GPMac
import NetworkExtension
import os

private let log = Logger(subsystem: "com.github.njvack.albi", category: "tunnel")

/// The packet tunnel. Logs in (or reuses a saved cookie), runs the session,
/// and lets macOS own routes and DNS: they go away when this process does.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var runner: SessionRunner?
    private var host: PacketFlowHost?
    private var watcher: PathWatcher?
    private let hip = HIPBridge()
    /// hipreport inside this extension's bundle (Contents/MacOS), out of
    /// the user's reach. Used when the profile sets `bundledHIP`.
    private let bundledHIP = BundledHIP()
    private let probeLock = NSLock()
    private var lastProbe: ProviderMessage.HIPProbe?
    private var profile: Profile?
    private var gateway: String?
    private var connectedOnce = false
    private var lastState: SessionState = .idle
    private let stateLock = NSLock()
    private var diagnostics: Diagnostics?

    /// Secrets live in the System keychain: this process runs as root.
    private let keychain = KeychainStore(service: "com.github.njvack.albi.tunnel")

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let profile = Profile(providerConfiguration: proto.providerConfiguration) else {
            completionHandler(TunnelError("the VPN configuration has no Albi profile"))
            return
        }
        self.profile = profile
        let diagSettings = DiagnosticsSettings(providerConfiguration: proto.providerConfiguration) ?? DiagnosticsSettings()
        let account = "\(profile.username)@\(profile.server)"
        if let pw = options?["password"] as? String {
            keychain.set("password:" + account, profile.savePassword ? Data(pw.utf8) : nil)
        }
        let password = (options?["password"] as? String) ??
            keychain.get("password:" + account).map { String(decoding: $0, as: UTF8.self) }

        Task {
            do {
                try await self.start(profile: profile, account: account, password: password, diagnostics: diagSettings)
                completionHandler(nil)
            } catch {
                log.error("start failed: \(String(describing: error), privacy: .public)")
                completionHandler(TunnelError("\(error)"))
            }
        }
    }

    private func start(profile: Profile, account: String, password: String?, diagnostics settings: DiagnosticsSettings) async throws {
        let clock = ContinuousSessionClock()
        var client = ClientInfo(computer: ProcessInfo.processInfo.hostName)

        // Diagnostics mode: record the session and write a redacted incident
        // file when an outage isn't recovered. The connector is wrapped
        // before login so the setup exchanges are recorded too.
        var diag: Diagnostics?
        if settings.enabled {
            let d = Diagnostics(settings: settings, directory: DiagnosticsSettings.systemDirectory, clock: clock,
                                secrets: KnownSecrets(password: password, servers: [profile.server], computer: client.computer)) { _, line in
                log.notice("diagnostics: \(line, privacy: .public)")
            }
            d.start()
            diag = d
            self.diagnostics = d
        }
        let base = NWGatewayConnector(trust: profile.trust)
        let connector: any GatewayConnector = diag.map { RecordingConnector(base, recorder: $0.recorder, clock: clock) } ?? base

        // A saved cookie lets a restarted extension come back without a new
        // login (and without a push). If the gateway rejects it, the session
        // logs in again.
        var cookie: AuthCookie?
        var gateway: String?
        var hipInterval: Double?
        if let d = keychain.get("cookie:" + account), let saved = try? JSONDecoder().decode(SavedCookie.self, from: d) {
            cookie = saved.cookie
            gateway = saved.gateway
            hipInterval = saved.hipInterval
            if let v = saved.appVersion { client.appVersion = v }
        }
        if cookie == nil {
            guard let password else { throw TunnelError("no password: connect from the app") }
            let creds = StoredCredentials(username: profile.username, password: password, secondFactor: profile.secondFactor)
            let r = try await Login(transport: connector, credentials: creds, client: client, username: profile.username)
                .run(profile.target)
            cookie = r.cookie
            gateway = r.gateway
            if let v = r.portal?.version { client.appVersion = v }
            diag?.recorder.setInfo("portal-version", r.portal?.version)
            hipInterval = r.portal?.hipReportInterval.map(Double.init)
            saveCookie(r.cookie, gateway: r.gateway, appVersion: client.appVersion, hipInterval: hipInterval, account: account)
        }
        guard let cookie, let gateway else { throw TunnelError("login gave no cookie") }
        self.gateway = gateway
        diag?.updateSecrets {
            $0.cookies.append(cookie)
            $0.servers.append(gateway)
        }

        var policy = SessionPolicy()
        policy.canReauthenticate = password != nil && profile.secondFactor != nil

        let clientInfo = client
        let interval = hipInterval
        let hooks = PacketFlowHost.Hooks(
            hipReport: { [hip, bundledHIP] ctx in
                if profile.bundledHIP == true { return try await bundledHIP.report(for: ctx) }
                return try await hip.report(for: ctx, timeout: 20)
            },
            reauthenticate: { [keychain] in
                guard let pw = keychain.get("password:" + account).map({ String(decoding: $0, as: UTF8.self) }) ?? password
                else { throw StoredCredentials.NeedsUser() }
                let creds = StoredCredentials(username: profile.username, password: pw, secondFactor: profile.secondFactor)
                let r = try await Login(transport: connector, credentials: creds, client: clientInfo, username: profile.username)
                    .run(profile.target)
                // The session keeps talking to the gateway it started with.
                return r.cookie
            },
            saveCookie: { [weak self] c in
                guard let self else { return }
                if let c {
                    self.saveCookie(c, gateway: gateway, appVersion: clientInfo.appVersion, hipInterval: interval, account: account)
                } else {
                    self.keychain.set("cookie:" + account, nil)
                }
            },
            stateChanged: { [weak self] s in self?.stateChanged(s) },
            log: { m in log.info("\(m, privacy: .public)") }
        )
        let host = PacketFlowHost(provider: self, hooks: hooks)
        let runner = SessionRunner(server: gateway, client: client,
                                   session: Session(cookie: cookie, policy: policy, hipInterval: hipInterval),
                                   io: connector, host: host, clock: clock, recorder: diag?.recorder)
        self.host = host
        self.runner = runner

        let watcher = PathWatcher { usable in Task { await runner.post(.pathChanged(usable: usable)) } }
        watcher.start()
        self.watcher = watcher

        await runner.start()
        host.pumpPackets(to: runner)

        // Report success to macOS once the tunnel is up the first time.
        while true {
            switch await runner.state {
            case .connected: return
            case .needsLogin(let why), .stopped(let why): throw TunnelError(why)
            default: try await Task.sleep(for: .milliseconds(100))
            }
        }
    }

    private func saveCookie(_ c: AuthCookie, gateway: String, appVersion: String, hipInterval: Double?, account: String) {
        let saved = SavedCookie(cookie: c, gateway: gateway, appVersion: appVersion, hipInterval: hipInterval)
        if let d = try? JSONEncoder().encode(saved) { keychain.set("cookie:" + account, d) }
    }

    private func stateChanged(_ s: SessionState) {
        stateLock.withLock { lastState = s }
        switch s {
        case .connected:
            connectedOnce = true
            reasserting = false
        case .connecting, .reconnecting, .waitingForNetwork, .reauthenticating:
            if connectedOnce { reasserting = true }
        case .needsLogin(let why):
            if connectedOnce { cancelTunnelWithError(TunnelError("login needed: \(why)")) }
        case .stopped, .idle:
            break
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        // Only a user's Disconnect logs out; anything else (sleep, a new
        // configuration, a crash restart) keeps the cookie for next time.
        let logout = reason == .userInitiated
        log.info("stopping (reason \(reason.rawValue), logout \(logout))")
        watcher?.stop()
        Task {
            await runner?.stop(logout: logout)
            diagnostics?.stop()
            completionHandler()
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        Task {
            await runner?.post(.sleep)
            completionHandler()
        }
    }

    override func wake() {
        Task { await runner?.post(.wake) }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let req = try? JSONDecoder().decode(ProviderMessage.Request.self, from: messageData) else {
            completionHandler?(nil)
            return
        }
        Task {
            if let report = req.hipReport {
                await hip.answer(report: report)
            } else if req.hipUnavailable == true {
                await hip.answer(report: nil)
            }
            if req.diagnosticsDump == true { diagnostics?.saveNow() }
            if req.probeBundledHIP == true {
                let p = await bundledHIP.probe()
                log.notice("bundled hipreport probe: \(p.summary, privacy: .public) stderr: \(p.stderrHead ?? "", privacy: .public)")
                probeLock.withLock { lastProbe = p }
            }
            let state = stateLock.withLock { lastState }
            let config = await runner?.config
            var status = ProviderMessage.Status(state: "\(state)", gateway: gateway, ipv4: config?.ipv4,
                                                hipRequest: await hip.request, lastHIPReport: await hip.lastReport,
                                                lastIncident: diagnostics?.lastIncident?.path,
                                                diagnosticsEnabled: diagnostics != nil)
            status.hipProbe = probeLock.withLock { lastProbe }
            completionHandler?(try? JSONEncoder().encode(status))
        }
    }
}

struct SavedCookie: Codable {
    var cookie: AuthCookie
    var gateway: String
    var appVersion: String?
    var hipInterval: Double?
}

struct TunnelError: LocalizedError {
    var message: String
    init(_ m: String) { message = m }
    var errorDescription: String? { message }
}
