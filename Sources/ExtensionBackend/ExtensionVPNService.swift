#if canImport(SwiftUI)
    import AlbiApp
    import Diagnostics
    import Foundation
    import GPMac
    import NetworkExtension
    import SystemExtensions

    /// `VPNService` over the packet tunnel system extension. Each profile is one
    /// VPN configuration (NETunnelProviderManager) whose providerConfiguration
    /// holds the `Profile`, the diagnostics settings and the profile's ID. While
    /// a tunnel runs, the service polls the extension with provider messages for
    /// its status, and answers its HIP requests and second-factor prompts.
    @MainActor
    public final class ExtensionVPNService: NSObject, VPNService {
        /// The extension's bundle ID, from the app's Info.plist.
        let tunnelBundleID: String
        /// Remembers which profiles the extension holds a password for: the app
        /// can't read the extension's keychain.
        private let defaults: UserDefaults

        private var managers: [NETunnelProviderManager] = []
        private let status = StatusBroadcaster()
        private var poll: Task<Void, Never>?
        private var observer: (any NSObjectProtocol)?
        private var hipInFlight = false
        /// Set by `disconnect()`, so a stop the user asked for isn't reported
        /// as the tunnel giving up.
        private var stopRequested = false
        /// The last state the extension reported, for telling why it stopped.
        private var lastReported: HelperStatus.State?

        private var extensionState: SetupStatus.Extension = .notActivated
        private var extensionChecked = false

        static let idKey = "albi.id"
        static let savedPasswordsKey = "savedPasswords"
        static let diagnosticsKey = "diagnostics"

        public init(tunnelBundleID: String? = nil, defaults: UserDefaults = .standard) {
            self.tunnelBundleID =
                tunnelBundleID
                ?? Bundle.main.object(forInfoDictionaryKey: "AlbiTunnelBundleIdentifier") as? String ?? ""
            self.defaults = defaults
            super.init()
        }

        // MARK: Profiles

        private func loadManagers() async throws {
            let all = try await NETunnelProviderManager.loadAllFromPreferences()
            managers = all.filter { Self.proto($0)?.providerBundleIdentifier == tunnelBundleID }
            // Configurations saved by the Step 1 test build have no ID yet.
            for m in managers where Self.profileID(m) == nil && Self.profile(m) != nil {
                var config = Self.proto(m)?.providerConfiguration ?? [:]
                config[Self.idKey] = UUID().uuidString
                Self.proto(m)?.providerConfiguration = config
                try? await m.saveToPreferences()
            }
            observe()
        }

        public func loadProfiles() async throws -> [VPNProfile] {
            try await loadManagers()
            return managers.compactMap(Self.vpnProfile)
        }

        public func save(_ profile: VPNProfile) async throws {
            if managers.isEmpty { try await loadManagers() }
            // Reuse the placeholder `allowVPNConfiguration` saved, if any.
            let m = manager(for: profile.id) ?? managers.first { Self.profile($0) == nil } ?? NETunnelProviderManager()
            let proto = Self.proto(m) ?? NETunnelProviderProtocol()
            proto.providerBundleIdentifier = tunnelBundleID
            proto.serverAddress = profile.settings.server
            proto.username = profile.settings.username
            var config = profile.settings.providerConfiguration
            config[Self.idKey] = profile.id.uuidString
            storedDiagnostics.store(in: &config)
            proto.providerConfiguration = config
            m.protocolConfiguration = proto
            m.localizedDescription = profile.name
            m.isEnabled = true
            try await m.saveToPreferences()
            try await m.loadFromPreferences()
            if !managers.contains(where: { $0 === m }) { managers.append(m) }
            if !profile.settings.savePassword { forgetPassword(profile.id) }
        }

        public func delete(_ id: VPNProfile.ID) async throws {
            guard let m = manager(for: id) else { return }
            if m.connection.status != .disconnected, m.connection.status != .invalid { m.connection.stopVPNTunnel() }
            try await m.removeFromPreferences()
            managers.removeAll { $0 === m }
            forgetPassword(id)
        }

        public func hasSavedPassword(for id: VPNProfile.ID) async -> Bool {
            savedPasswords.contains(id.uuidString)
        }

        // MARK: Tunnel

        public func connect(_ id: VPNProfile.ID, password: String?) async throws {
            guard let m = manager(for: id), let profile = Self.profile(m) else { throw Failure("No such profile.") }
            // One tunnel at a time.
            for other in managers where other !== m && Self.isActive(other.connection.status) {
                other.connection.stopVPNTunnel()
            }
            if !m.isEnabled {
                m.isEnabled = true
                try await m.saveToPreferences()
            }
            var options: [String: NSObject] = [:]
            if let password { options["password"] = password as NSString }
            stopRequested = false
            lastReported = .authenticating
            status.send(TunnelStatus(profileID: id, state: .authenticating))
            do {
                try m.connection.startVPNTunnel(options: options)
            } catch {
                status.send(TunnelStatus(profileID: id, state: .failed(reason: error.localizedDescription)))
                throw error
            }
            if password != nil, profile.savePassword { rememberPassword(id) }
            startPolling()
        }

        public func disconnect() async {
            guard let m = activeManager else { return }
            stopRequested = true
            status.update { $0.state = .disconnecting }
            m.connection.stopVPNTunnel()
        }

        public func answerSecondFactor(_ code: String) async {
            await send(ProviderMessage.Request(secondFactorCode: code))
        }

        public func currentStatus() async -> TunnelStatus {
            if managers.isEmpty { try? await loadManagers() }
            statusChanged()
            if activeManager != nil { await send(ProviderMessage.Request(poll: true)) }
            return status.current
        }

        public func statusUpdates() -> AsyncStream<TunnelStatus> {
            Task { _ = await currentStatus() }
            return status.stream()
        }

        private var activeManager: NETunnelProviderManager? {
            managers.first { Self.isActive($0.connection.status) }
        }

        private func observe() {
            guard observer == nil else { return }
            observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main)
            {
                [weak self] _ in
                Task { @MainActor in self?.statusChanged() }
            }
        }

        /// Follows NEVPNStatus: polls while a tunnel runs, and says why it
        /// stopped when it does.
        private func statusChanged() {
            if let m = activeManager {
                if status.current.profileID == nil { status.update { $0.profileID = Self.profileID(m) } }
                if m.connection.status == .disconnecting { status.update { $0.state = .disconnecting } }
                startPolling()
                return
            }
            poll?.cancel()
            poll = nil
            guard status.current.state != .disconnected else { return }
            let id = status.current.profileID
            let last = lastReported
            lastReported = nil
            if stopRequested || status.current.state == .disconnecting {
                stopRequested = false
                status.send(TunnelStatus(profileID: id, lastIncident: status.current.lastIncident))
                return
            }
            // The extension stopped by itself: it gave up and needs the user,
            // which is what the login window is for.
            Task { [weak self] in
                guard let self else { return }
                let reason = await self.stopReason(id, last: last)
                if case .needsLogin = reason, let id { self.forgetPassword(id) }
                self.status.send(
                    TunnelStatus(profileID: id, state: reason, lastIncident: self.status.current.lastIncident))
            }
        }

        private func stopReason(_ id: VPNProfile.ID?, last: HelperStatus.State?) async -> TunnelState {
            if case .needsLogin(let why) = last { return .needsLogin(reason: why) }
            var why = "The tunnel stopped."
            if let m = id.flatMap(manager(for:)) {
                let err: (any Error)? = await withCheckedContinuation { c in
                    m.connection.fetchLastDisconnectError { c.resume(returning: $0) }
                }
                if let err { why = err.localizedDescription }
            }
            return .needsLogin(reason: why)
        }

        private func startPolling() {
            guard poll == nil else { return }
            poll = Task { [weak self] in
                while !Task.isCancelled {
                    await self?.send(ProviderMessage.Request(poll: true))
                    try? await Task.sleep(for: .seconds(1))
                }
            }
        }

        /// Sends one message to the running extension and takes in its status.
        private func send(_ req: ProviderMessage.Request) async {
            guard let m = activeManager, let session = m.connection as? NETunnelProviderSession,
                let data = try? JSONEncoder().encode(req)
            else { return }
            let reply: Data? = await withCheckedContinuation { cont in
                do {
                    try session.sendProviderMessage(data) { cont.resume(returning: $0) }
                } catch {
                    cont.resume(returning: nil)
                }
            }
            guard let reply, let s = try? JSONDecoder().decode(ProviderMessage.Status.self, from: reply) else { return }
            received(s, from: m)
        }

        private func received(_ s: ProviderMessage.Status, from m: NETunnelProviderManager) {
            guard Self.isActive(m.connection.status), var report = s.tunnel else { return }
            report.profileID = Self.profileID(m)
            if m.connection.status == .disconnecting { report.state = .disconnecting }
            lastReported = report.state
            status.send(TunnelStatus(report))
            if let hip = s.hipRequest, !hipInFlight {
                hipInFlight = true
                Task { [weak self] in
                    guard let self else { return }
                    let answer = await Self.makeHIPReport(hip)
                    await self.send(answer)
                    self.hipInFlight = false
                }
            }
        }

        // MARK: HIP

        /// albi-hipreport in this app's Contents/MacOS. It runs as the user, so
        /// checks only root can make report n/a.
        nonisolated static var bundledHIPReport: URL {
            Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/albi-hipreport")
        }

        /// Runs albi-hipreport as openconnect runs a --csd-wrapper.
        nonisolated static func makeHIPReport(_ r: ProviderMessage.HIPRequest) async -> ProviderMessage.Request {
            let tool = bundledHIPReport
            let result: String? = await Task.detached {
                let p = Process()
                p.executableURL = tool
                p.arguments = r.wrapperArguments
                var env = ProcessInfo.processInfo.environment
                env["APP_VERSION"] = r.appVersion
                p.environment = env
                let out = Pipe()
                p.standardOutput = out
                do { try p.run() } catch { return nil }
                let data = out.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                return p.terminationStatus == 0 ? String(decoding: data, as: UTF8.self) : nil
            }.value
            if let result { return ProviderMessage.Request(hipReport: result) }
            return ProviderMessage.Request(hipUnavailable: true)
        }

        // MARK: Diagnostics

        /// Kept in the app's defaults too, so it survives having no profiles.
        private var storedDiagnostics: DiagnosticsSettings {
            get {
                if let d = defaults.data(forKey: Self.diagnosticsKey),
                    let s = try? JSONDecoder().decode(DiagnosticsSettings.self, from: d)
                {
                    return s
                }
                for m in managers {
                    if let s = DiagnosticsSettings(providerConfiguration: Self.proto(m)?.providerConfiguration) {
                        return s
                    }
                }
                return DiagnosticsSettings()
            }
            set { defaults.set(try? JSONEncoder().encode(newValue), forKey: Self.diagnosticsKey) }
        }

        public func diagnosticsSettings() async -> DiagnosticsSettings {
            if managers.isEmpty { try? await loadManagers() }
            return storedDiagnostics
        }

        /// Saved in every profile's VPN configuration; the extension reads it
        /// when it starts.
        public func setDiagnosticsSettings(_ settings: DiagnosticsSettings) async throws {
            storedDiagnostics = settings
            for m in managers {
                guard let proto = Self.proto(m), var config = proto.providerConfiguration else { continue }
                settings.store(in: &config)
                proto.providerConfiguration = config
                try await m.saveToPreferences()
            }
        }

        public func saveDiagnosticsNow() async {
            await send(ProviderMessage.Request(diagnosticsDump: true))
        }

        // MARK: Setup

        public func setupStatus() async -> SetupStatus {
            if !extensionChecked {
                extensionChecked = true
                extensionState = await extensionProperties()
            }
            if managers.isEmpty { try? await loadManagers() }
            return SetupStatus(
                backend: .systemExtension, systemExtension: extensionState,
                vpnConfigurationAllowed: !managers.isEmpty,
                helper: .unavailable("Not available in this build yet."))
        }

        public func activateSystemExtension() async {
            extensionState = await submit(.activationRequest(forExtensionWithIdentifier: tunnelBundleID, queue: .main))
        }

        /// macOS asks to allow VPN configurations the first time one is saved.
        /// With no profile yet, save a disabled placeholder that the first
        /// profile then takes over.
        public func allowVPNConfiguration() async {
            if managers.isEmpty { try? await loadManagers() }
            guard managers.isEmpty else { return }
            let m = NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = tunnelBundleID
            proto.serverAddress = "Albi"
            m.protocolConfiguration = proto
            m.localizedDescription = "Albi"
            m.isEnabled = false
            do {
                try await m.saveToPreferences()
                try await m.loadFromPreferences()
                managers.append(m)
            } catch {
                NSLog("Albi: saving the VPN configuration: %@", String(describing: error))
            }
        }

        public func registerHelper() async {}

        private var pending: [ObjectIdentifier: CheckedContinuation<SetupStatus.Extension, Never>] = [:]
        /// Properties requests may also report a result, which says nothing
        /// about the extension's state.
        private var propertyRequests: Set<ObjectIdentifier> = []

        private func extensionProperties() async -> SetupStatus.Extension {
            let req = OSSystemExtensionRequest.propertiesRequest(
                forExtensionWithIdentifier: tunnelBundleID, queue: .main)
            propertyRequests.insert(ObjectIdentifier(req))
            return await submit(req)
        }

        private func submit(_ req: OSSystemExtensionRequest) async -> SetupStatus.Extension {
            await withCheckedContinuation { c in
                pending[ObjectIdentifier(req)] = c
                req.delegate = self
                OSSystemExtensionManager.shared.submitRequest(req)
            }
        }

        fileprivate func finish(
            _ req: OSSystemExtensionRequest, _ result: SetupStatus.Extension, isResult: Bool = false
        ) {
            let key = ObjectIdentifier(req)
            var result = result
            if propertyRequests.contains(key) {
                if isResult { return }
                // A properties request fails when there's nothing installed yet.
                if case .failed = result { result = .notActivated }
            }
            extensionState = result
            pending.removeValue(forKey: key)?.resume(returning: result)
        }

        /// Reports awaiting approval without finishing the request: macOS
        /// finishes it once the user allows the extension.
        fileprivate func awaitingApproval(_ req: OSSystemExtensionRequest) {
            extensionState = .awaitingApproval
            pending.removeValue(forKey: ObjectIdentifier(req))?.resume(returning: .awaitingApproval)
        }

        // MARK: Passwords

        private var savedPasswords: Set<String> {
            get { Set(defaults.stringArray(forKey: Self.savedPasswordsKey) ?? []) }
            set { defaults.set(Array(newValue), forKey: Self.savedPasswordsKey) }
        }

        private func rememberPassword(_ id: VPNProfile.ID) { savedPasswords.insert(id.uuidString) }
        private func forgetPassword(_ id: VPNProfile.ID) { savedPasswords.remove(id.uuidString) }

        // MARK: Mapping

        struct Failure: LocalizedError {
            var message: String
            init(_ m: String) { message = m }
            var errorDescription: String? { message }
        }

        private func manager(for id: VPNProfile.ID) -> NETunnelProviderManager? {
            managers.first { Self.profileID($0) == id }
        }

        static func proto(_ m: NETunnelProviderManager) -> NETunnelProviderProtocol? {
            m.protocolConfiguration as? NETunnelProviderProtocol
        }

        static func profile(_ m: NETunnelProviderManager) -> Profile? {
            Profile(providerConfiguration: proto(m)?.providerConfiguration)
        }

        static func profileID(_ m: NETunnelProviderManager) -> UUID? {
            (proto(m)?.providerConfiguration?[idKey] as? String).flatMap(UUID.init(uuidString:))
        }

        static func vpnProfile(_ m: NETunnelProviderManager) -> VPNProfile? {
            guard let id = profileID(m), let p = profile(m) else { return nil }
            return VPNProfile(id: id, name: m.localizedDescription ?? p.server, settings: p)
        }

        static func isActive(_ s: NEVPNStatus) -> Bool {
            switch s {
            case .connecting, .connected, .reasserting, .disconnecting: true
            default: false
            }
        }
    }

    extension ExtensionVPNService: OSSystemExtensionRequestDelegate {
        nonisolated public func request(
            _ request: OSSystemExtensionRequest,
            actionForReplacingExtension existing: OSSystemExtensionProperties,
            withExtension ext: OSSystemExtensionProperties
        ) -> OSSystemExtensionRequest.ReplacementAction {
            .replace
        }

        nonisolated public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
            nonisolated(unsafe) let request = request
            Task { @MainActor in self.awaitingApproval(request) }
        }

        nonisolated public func request(
            _ request: OSSystemExtensionRequest,
            didFinishWithResult result: OSSystemExtensionRequest.Result
        ) {
            nonisolated(unsafe) let request = request
            Task { @MainActor in self.finish(request, .active, isResult: true) }
        }

        nonisolated public func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
            nonisolated(unsafe) let request = request
            let msg = error.localizedDescription
            Task { @MainActor in self.finish(request, .failed(msg)) }
        }

        nonisolated public func request(
            _ request: OSSystemExtensionRequest,
            foundProperties properties: [OSSystemExtensionProperties]
        ) {
            let state: SetupStatus.Extension =
                if properties.contains(where: { $0.isEnabled && !$0.isUninstalling }) {
                    .active
                } else if properties.contains(where: { $0.isAwaitingUserApproval }) { .awaitingApproval } else {
                    .notActivated
                }
            nonisolated(unsafe) let request = request
            Task { @MainActor in self.finish(request, state) }
        }
    }
#endif
