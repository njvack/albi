#if canImport(SwiftUI)
import AppKit
import SwiftUI

/// Window identifiers for `openWindow`.
public enum AlbiWindow {
    public static let login = "login"
    public static let hip = "hip"
    public static let setup = "setup"
}

/// The whole app: the menu-bar extra, its windows and Settings. The app
/// target's `App` only builds the model and returns this.
public struct AlbiScenes: Scene {
    let model: AppModel
    let demo: MockVPNService?

    /// `demo` adds a Demo submenu that drives the mock tunnel.
    public init(model: AppModel, demo: MockVPNService? = nil) {
        self.model = model
        self.demo = demo
    }

    public var body: some Scene {
        MenuBarExtra {
            MenuContent(model: model, demo: demo)
        } label: {
            MenuBarLabel(model: model)
        }
        .menuBarExtraStyle(.menu)

        Window("Log In", id: AlbiWindow.login) {
            LoginView(model: model)
        }
        .windowResizability(.contentSize)
        .defaultPosition(.center)

        Window("HIP Compliance", id: AlbiWindow.hip) {
            HIPView(model: model)
        }
        .defaultSize(width: 760, height: 380)

        Window("Set Up Albi", id: AlbiWindow.setup) {
            SetupView(model: model)
        }
        .windowResizability(.contentSize)
        .defaultPosition(.center)

        Settings {
            SettingsView(model: model)
        }
    }
}

/// The status item. It lives as long as the app, so it also starts the model
/// and opens setup on a launch where something still needs approval.
struct MenuBarLabel: View {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(systemName: model.status.state.symbolName)
            .accessibilityLabel(model.status.state.accessibilityLabel)
            .task {
                await model.start()
                if !model.setup.isReady {
                    present(AlbiWindow.setup, openWindow)
                } else if await model.connectAtLaunch() == .needsLogin {
                    present(AlbiWindow.login, openWindow)
                }
            }
    }
}

/// Opens one of the app's windows and brings it forward; a menu-bar app is
/// not active when its menu is used.
@MainActor
func present(_ id: String, _ openWindow: OpenWindowAction) {
    openWindow(id: id)
    NSApp.activate()
}
#endif
