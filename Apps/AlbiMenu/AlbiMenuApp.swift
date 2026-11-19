import AlbiApp
import SwiftUI

/// The menu-bar app. It runs the tunnel through albi-helper, the root
/// LaunchDaemon in its bundle, and disconnects when it quits. Launched with `-demo YES` (or ALBI_DEMO=1) it
/// runs against the mock tunnel instead, with a Demo submenu to drop the
/// connection or fail a HIP check.
@main
struct AlbiMenuApp: App {
    @State private var model: AppModel
    @NSApplicationDelegateAdaptor private var quit: QuitDisconnects
    private let demo: MockVPNService?

    init() {
        let wantsDemo = UserDefaults.standard.bool(forKey: "demo") || ProcessInfo.processInfo.environment["ALBI_DEMO"] == "1"
        let demo = wantsDemo ? MockVPNService.demo() : nil
        self.demo = demo
        let service: any VPNService = demo ?? HelperVPNService()
        _model = State(initialValue: AppModel(service: service, notifier: UserNotifier(), loginItem: MainAppLoginItem()))
    }

    var body: some Scene {
        let _ = quit.model = model
        AlbiScenes(model: model, demo: demo)
    }
}
