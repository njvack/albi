#if canImport(SwiftUI)
    import AlbiApp
    import AlbiConstants
    import ServiceManagement

    /// Launch at login as a LaunchAgent in the app's bundle
    /// (Contents/Library/LaunchAgents), which also has launchd start the app
    /// again if it crashes. A normal quit exits 0, and launchd leaves it be.
    @MainActor
    public final class AgentLoginItem: LoginItem {
        let service: SMAppService

        public init(plistName: String = AlbiIDs.helperLoginAgentPlist) {
            service = SMAppService.agent(plistName: plistName)
        }

        public var isEnabled: Bool { service.status == .enabled }

        public func setEnabled(_ on: Bool) throws {
            if on {
                try service.register()
            } else {
                try service.unregister()
            }
        }
    }
#endif
