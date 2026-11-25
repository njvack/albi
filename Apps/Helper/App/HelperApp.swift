import AlbiApp
import HelperBackend
import SwiftUI

/// Albi with the helper backend: the shared menu-bar app (AlbiScenes) over
/// HelperVPNService. It runs the tunnel itself, as the user, and asks
/// albi-helper, the root LaunchDaemon in its bundle, only for the utun,
/// routes and DNS; it disconnects when it quits. Launch at login is a
/// LaunchAgent, so launchd also restarts the app after a crash, and "At
/// launch" reconnects with the saved cookie. Launched with `-demo YES` (or ALBI_DEMO=1) it
/// runs against the mock tunnel instead, with a Demo submenu to drop the
/// connection or fail a HIP check.
@main
struct HelperApp: App {
    @State private var model: AppModel
    @NSApplicationDelegateAdaptor private var quit: QuitDisconnects
    private let demo: MockVPNService?

    init() {
        let wantsDemo =
            UserDefaults.standard.bool(forKey: "demo") || ProcessInfo.processInfo.environment["ALBI_DEMO"] == "1"
        let demo = wantsDemo ? MockVPNService.demo() : nil
        self.demo = demo
        let service: any VPNService = demo ?? HelperVPNService()
        _model = State(initialValue: AppModel(service: service, notifier: UserNotifier(), loginItem: AgentLoginItem()))
    }

    var body: some Scene {
        let _ = quit.model = model
        AlbiScenes(model: model, demo: demo)
    }
}
