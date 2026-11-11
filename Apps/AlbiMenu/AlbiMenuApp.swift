import AlbiApp
import SwiftUI

/// The menu-bar app. For now it runs against the mock tunnel, with a Demo
/// submenu to drop the connection or fail a HIP check.
@main
struct AlbiMenuApp: App {
    @State private var model: AppModel
    private let demo: MockVPNService

    init() {
        let demo = MockVPNService.demo()
        self.demo = demo
        _model = State(initialValue: AppModel(service: demo, notifier: UserNotifier(), loginItem: MainAppLoginItem()))
    }

    var body: some Scene {
        AlbiScenes(model: model, demo: demo)
    }
}
