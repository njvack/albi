#if canImport(SwiftUI)
    import AlbiConstants
    import Diagnostics
    import Foundation
    import GPCore
    import GPMac
    import os

    private let log = Logger(subsystem: AlbiIDs.logSubsystem, category: "session")

    /// The helper build's VPN session, in the app, as the user: profiles,
    /// credentials, login, the tunnel and its packets. Only what needs root
    /// goes to albi-helper: opening the utun, and its addresses, routes and
    /// DNS.
    ///
    /// Passwords and cookies live in the user's login keychain. An item made
    /// there gets an access list that trusts only the app that made it, so
    /// other apps have to ask the user first. A password the user types and
    /// doesn't save stays in this process's memory for the session, for
    /// re-auth, and goes nowhere else: never on a command line, in the
    /// environment, a file or a log.
    actor AgentCore {
        private var stored = HelperProfiles()
        private var controller: TunnelController?
        /// Bumped for each connect, so a stale task's results are ignored.
        private var generation = 0
        private var status = HelperStatus()
        private var codeWaiter: CheckedContinuation<String, Error>?
        private var power: PowerWatcher?
        /// The helper restarted under a running session, which lost its utun.
        private var helperWasLost = false
        private let keychain: KeychainStore
        private let hip: BundledHIP
        private let profilesFile: URL
        private let diagnosticsDirectory: URL
        let helper: HelperConnection
        private let onStatus: @Sendable (HelperStatus) -> Void

        /// ~/Library/Application Support/Albi.
        static var supportDirectory: URL {
            FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("Albi", isDirectory: true)
        }

        init(
            helper: HelperConnection,
            profilesFile: URL = AgentCore.supportDirectory.appendingPathComponent("profiles.json"),
            legacyProfiles: URL = URL(fileURLWithPath: AlbiPaths.profiles),
            diagnosticsDirectory: URL = AgentCore.supportDirectory.appendingPathComponent("Diagnostics"),
            keychain: KeychainStore = KeychainStore(service: AlbiIDs.helperKeychainService),
            hip: BundledHIP = BundledHIP(executable: Bundle.main.url(forAuxiliaryExecutable: "albi-hipreport")),
            onStatus: @escaping @Sendable (HelperStatus) -> Void
        ) {
            self.helper = helper
            self.profilesFile = profilesFile
            self.diagnosticsDirectory = diagnosticsDirectory
            self.keychain = keychain
            self.hip = hip
            self.onStatus = onStatus
            if let mine = Self.read(HelperProfiles.self, profilesFile) {
                stored = mine
            } else if let old = Self.read(HelperProfiles.self, legacyProfiles) {
                // Profiles the root helper kept before the session moved
                // here. Its passwords and cookies were in the System keychain,
                // out of the user's reach: the login window asks again.
                stored = old
                try? Self.write(old, profilesFile)
                log.notice("imported \(old.profiles.count) profile(s) from \(legacyProfiles.path, privacy: .public)")
            }
        }

        // MARK: Profiles

        func profiles() -> [StoredProfile] { stored.profiles }

        func save(_ p: StoredProfile) throws {
            guard Profile.isValidServer(p.profile.server) else {
                throw AgentError("\"\(p.profile.server)\" isn't a server name or address.")
            }
            if let i = stored.profiles.firstIndex(where: { $0.id == p.id }) {
                let old = stored.profiles[i].profile
                // The saved password goes with the server, the account and
                // how the server is trusted: change any of them and it must
                // be typed again, so it's never sent somewhere new.
                if old.username != p.profile.username || old.server != p.profile.server
                    || old.pins != p.profile.pins || old.mode != p.profile.mode || !p.profile.savePassword
                {
                    keychain.set(TunnelController.passwordAccount(old), nil)
                }
                stored.profiles[i] = p
            } else {
                stored.profiles.append(p)
            }
            try saveProfiles()
        }

        func delete(_ id: UUID) throws {
            if let p = stored.profiles.first(where: { $0.id == id }) {
                keychain.set(TunnelController.passwordAccount(p.profile), nil)
                CookieStore(store: keychain, username: p.profile.username, server: p.profile.server).remove()
            }
            stored.profiles.removeAll { $0.id == id }
            try saveProfiles()
        }

        /// Whether a connect can go ahead without asking for the password: a
        /// saved password, or a saved cookie the gateway may still take. If
        /// it doesn't, the session says a login is needed.
        func canConnectWithoutPassword(_ id: UUID) -> Bool {
            guard let p = stored.profiles.first(where: { $0.id == id })?.profile else { return false }
            if p.savePassword, keychain.get(TunnelController.passwordAccount(p)) != nil { return true }
            return CookieStore(store: keychain, username: p.username, server: p.server)
                .load(mode: p.mode, clearedAt: p.cookiesClearedAt) != nil
        }

        func diagnostics() -> DiagnosticsSettings { stored.diagnostics }

        func setDiagnostics(_ d: DiagnosticsSettings) throws {
            stored.diagnostics = d
            try saveProfiles()
        }

        // MARK: Requests

        func connect(_ id: UUID, password: String?) async throws {
            guard stored.profiles.contains(where: { $0.id == id }) else { throw AgentError("No such profile.") }
            await stopController()
            startPowerWatcher()
            connect(id, password: password)
        }

        func disconnect() async {
            if controller != nil {
                update { $0.state = .disconnecting }
                await stopController()
            }
            codeWaiter?.resume(throwing: GPError.cancelled)
            codeWaiter = nil
            update { s in s = HelperStatus(profileID: s.profileID, lastIncident: s.lastIncident) }
        }

        func answerSecondFactor(_ code: String) {
            codeWaiter?.resume(returning: code)
            codeWaiter = nil
        }

        func currentStatus() async -> HelperStatus {
            await refresh()
            return status
        }

        func saveDiagnosticsNow() async {
            controller?.saveDiagnosticsNow()
            try? await Task.sleep(for: .milliseconds(500))
            await refresh()
        }

        /// The helper restarted or went away. It took the utun's routes and
        /// DNS with it, so a running session starts over on a new utun, with
        /// its saved cookie.
        func helperLost() async {
            guard let c = controller else { return }
            log.notice("the helper went away; restarting the tunnel")
            helperWasLost = true
            await c.stop()
        }

        // MARK: The tunnel

        private func connect(_ id: UUID, password: String?) {
            guard let p = stored.profiles.first(where: { $0.id == id }) else { return }
            generation += 1
            let gen = generation
            helperWasLost = false
            status = HelperStatus(profileID: id, state: .authenticating)
            broadcast()
            Task { await run(p, password: password, generation: gen) }
        }

        /// Runs one profile until it's stopped, needs a login, or is replaced.
        /// A start that fails for a reason that may pass (no network yet, the
        /// gateway or the helper unreachable) is retried with backoff.
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
                if helperWasLost {
                    helperWasLost = false
                    if p.profile.savePassword { password = nil }
                    update { $0.state = .reconnecting(attempt: 1, reason: "The Albi helper restarted.") }
                    try? await Task.sleep(for: .seconds(1))
                    continue
                }
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
            let config = TunnelController.Configuration(
                profile: profile, password: password, diagnostics: stored.diagnostics,
                diagnosticsDirectory: diagnosticsDirectory, keychain: keychain)
            return TunnelController(
                config,
                hipReport: { [hip] ctx in try await hip.report(for: ctx) },
                askSecondFactor: { [weak self] prompt in
                    guard let self else { throw GPError.cancelled }
                    return try await self.waitForCode(prompt)
                },
                makeHost: { [helper] hooks, gateway, watcher in
                    let device = try await helper.openTunnel()
                    return UtunHost(
                        device: device, network: HelperTunnelNetwork(helper), dnsMode: .split,
                        gatewayHosts: [serverHost, Self.host(gateway)],
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
            if case .state(let s) = e { log.notice("state \(String(describing: s), privacy: .public)") }
            guard status.apply(e) else { return }
            await refresh()
            broadcast()
        }

        private func waitForCode(_ prompt: String) async throws -> String {
            codeWaiter?.resume(throwing: GPError.cancelled)
            // Nobody may be there to answer: give up after five minutes, so
            // the session can say a login is needed.
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

        private func startPowerWatcher() {
            guard power == nil else { return }
            let p = PowerWatcher { [weak self] e in
                Task { await self?.powerEvent(e) }
            }
            if !p.start() { log.error("could not watch for sleep and wake") }
            power = p
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
            status.apply(await c.snapshot())
        }

        private func update(_ change: (inout HelperStatus) -> Void) {
            change(&status)
            broadcast()
        }

        private func broadcast() { onStatus(status) }

        // MARK: Files

        private func saveProfiles() throws {
            do { try Self.write(stored, profilesFile) } catch {
                throw AgentError("Couldn't save profiles: \(error.localizedDescription)")
            }
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

        /// Readable by the user only. No secrets: those are in the keychain.
        static func write<T: Encodable>(_ v: T, _ url: URL) throws {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            try HelperCoding.encode(v).write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
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

    struct AgentError: LocalizedError {
        var message: String
        init(_ m: String) { message = m }
        var errorDescription: String? { message }
    }
#endif
