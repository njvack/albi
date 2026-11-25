#if canImport(SwiftUI)
    import AlbiApp
    import Diagnostics
    import Foundation
    import GPMac
    import ServiceManagement

    /// The helper build's `VPNService`. The session runs here, in the app,
    /// as the user (`AgentCore`); albi-helper, the root LaunchDaemon the app
    /// registers with SMAppService from its own bundle, only opens the utun
    /// and sets its addresses, routes and DNS. Launch at login starts the
    /// app, and "At launch" reconnects with the saved cookie, or the saved
    /// password once the gateway stops taking the cookie.
    @MainActor
    public final class HelperVPNService: VPNService {
        private let status: StatusBroadcaster
        private let helper: HelperConnection
        private let core: AgentCore

        public init() {
            let lost = LostRelay()
            let helper = HelperConnection(requirement: Self.helperRequirement) { lost.fire() }
            let status = StatusBroadcaster()
            let core = AgentCore(helper: helper) { s in
                Task { @MainActor in status.send(TunnelStatus(s)) }
            }
            lost.core = core
            self.status = status
            self.helper = helper
            self.core = core
        }

        /// The helper inside this app: Contents/MacOS/albi-helper.
        static var bundledHelper: URL {
            Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/albi-helper")
        }

        /// The helper's launchd job: Contents/Library/LaunchDaemons/<plistName>.
        static var bundledPlist: URL {
            Bundle.main.bundleURL.appendingPathComponent("Contents/Library/LaunchDaemons/\(AlbiHelper.plistName)")
        }

        /// What the helper must be signed as, for a team-signed app.
        static let helperRequirement = AlbiHelper.helperRequirement(app: Bundle.main.bundleURL, helper: bundledHelper)

        static var daemon: SMAppService { SMAppService.daemon(plistName: AlbiHelper.plistName) }

        /// One request to the helper, for the setup check and tests.
        func call(_ req: HelperRequest, timeout: Double = 15) async throws -> HelperReply {
            try await helper.call(req, timeout: timeout)
        }

        // MARK: Profiles

        public func loadProfiles() async throws -> [VPNProfile] {
            await core.profiles().map(Self.vpnProfile)
        }

        public func save(_ profile: VPNProfile) async throws {
            try await core.save(StoredProfile(id: profile.id, name: profile.name, profile: profile.settings))
        }

        public func delete(_ id: VPNProfile.ID) async throws {
            try await core.delete(id)
        }

        /// True with a saved cookie too: the session tries that first, and
        /// asks for a login if the gateway turns it down.
        public func hasSavedPassword(for id: VPNProfile.ID) async -> Bool {
            await core.canConnectWithoutPassword(id)
        }

        // MARK: Tunnel

        public func connect(_ id: VPNProfile.ID, password: String?) async throws {
            try await core.connect(id, password: password)
        }

        public func disconnect() async {
            await core.disconnect()
        }

        public func answerSecondFactor(_ code: String) async {
            await core.answerSecondFactor(code)
        }

        public func currentStatus() async -> TunnelStatus {
            status.send(TunnelStatus(await core.currentStatus()))
            return status.current
        }

        public func statusUpdates() -> AsyncStream<TunnelStatus> {
            status.stream()
        }

        // MARK: Diagnostics

        public func diagnosticsSettings() async -> DiagnosticsSettings {
            await core.diagnostics()
        }

        public func setDiagnosticsSettings(_ settings: DiagnosticsSettings) async throws {
            try await core.setDiagnostics(settings)
        }

        public func saveDiagnosticsNow() async {
            await core.saveDiagnosticsNow()
        }

        // MARK: Setup

        public func setupStatus() async -> SetupStatus {
            SetupStatus(backend: .helper, helper: await helperState())
        }

        func helperState() async -> SetupStatus.Helper {
            guard FileManager.default.fileExists(atPath: Self.bundledHelper.path) else {
                return .unavailable("This copy of Albi has no helper in Contents/MacOS. Build the HelperApp scheme.")
            }
            switch Self.daemon.status {
            case .notRegistered: return .notRegistered
            case .requiresApproval: return .awaitingApproval
            case .notFound:
                // macOS also says notFound for a daemon that was never
                // registered, so only a missing plist means we can't offer it.
                guard FileManager.default.fileExists(atPath: Self.bundledPlist.path) else {
                    return .unavailable("This copy of Albi has no helper plist in Contents/Library/LaunchDaemons.")
                }
                return .notRegistered
            case .enabled: break
            @unknown default: return .notRegistered
            }
            do {
                let hello = try await call(.hello, timeout: 5)
                if hello.version != AlbiHelper.protocolVersion {
                    return .needsReinstall("The running helper speaks another version.")
                }
                if let mine = HelperBuild.id(ofExecutableAt: Self.bundledHelper.path), hello.build != mine {
                    return .needsReinstall("The running helper is from another build of Albi.")
                }
                return .registered
            } catch {
                return .needsReinstall("The helper is registered but doesn't answer.")
            }
        }

        /// Registers the helper, first unregistering one that's stale. macOS
        /// asks the user to allow it in System Settings the first time (and may
        /// again after an unregister).
        public func registerHelper() async {
            let svc = Self.daemon
            if case .needsReinstall = await helperState() {
                try? await svc.unregister()
                helper.invalidate()
                try? await Task.sleep(for: .seconds(1))
            }
            do {
                try svc.register()
            } catch {
                // Usually "Operation not permitted" until the user allows it.
                NSLog("Albi: registering the helper: %@", String(describing: error))
            }
            if svc.status == .requiresApproval { SMAppService.openSystemSettingsLoginItems() }
        }

        public func activateSystemExtension() async {}
        public func allowVPNConfiguration() async {}

        // MARK: Mapping

        static func vpnProfile(_ p: StoredProfile) -> VPNProfile {
            VPNProfile(id: p.id, name: p.name, settings: p.profile)
        }

        static func tunnelStatus(_ s: HelperStatus) -> TunnelStatus { TunnelStatus(s) }
    }

    /// Hands the helper connection's "lost" to the session, which is made
    /// after the connection.
    final class LostRelay: @unchecked Sendable {
        private let lock = NSLock()
        private weak var _core: AgentCore?
        var core: AgentCore? {
            get { lock.withLock { _core } }
            set { lock.withLock { _core = newValue } }
        }

        func fire() {
            guard let core else { return }
            Task { await core.helperLost() }
        }
    }
#endif
