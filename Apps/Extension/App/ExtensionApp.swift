import AlbiApp
import ExtensionBackend
import SwiftUI

/// Albi with the extension backend: the shared menu-bar app (AlbiScenes)
/// over ExtensionVPNService. The tunnel runs in the packet tunnel system
/// extension in Contents/Library/SystemExtensions; the app answers its HIP
/// requests with the albi-hipreport in Contents/MacOS, and disconnects when
/// it quits. Launched with `-demo YES` (or ALBI_DEMO=1) it runs against the
/// mock tunnel instead.
@main
struct ExtensionApp: App {
    @State private var model: AppModel
    @NSApplicationDelegateAdaptor private var quit: QuitDisconnects
    private let demo: MockVPNService?

    init() {
        let wantsDemo =
            UserDefaults.standard.bool(forKey: "demo") || ProcessInfo.processInfo.environment["ALBI_DEMO"] == "1"
        let demo = wantsDemo ? MockVPNService.demo() : nil
        self.demo = demo
        let service: any VPNService = demo ?? ExtensionVPNService()
        _model = State(
            initialValue: AppModel(service: service, notifier: UserNotifier(), loginItem: MainAppLoginItem()))
    }

    var body: some Scene {
        let _ = quit.model = model
        AlbiScenes(model: model, demo: demo)
    }
}
