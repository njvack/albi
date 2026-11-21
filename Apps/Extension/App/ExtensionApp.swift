import SwiftUI

// Albi with the extension backend. For now this is still the Step 1 test
// build: one window to set up the profile, approve the extension, connect
// and watch the session. Next it moves onto the shared menu-bar app
// (AlbiScenes) over an ExtensionVPNService, like HelperApp.
@main
struct ExtensionApp: App {
    @StateObject private var vpn = VPNController()

    var body: some Scene {
        WindowGroup("Albi") {
            ContentView()
                .environmentObject(vpn)
                .frame(minWidth: 460, minHeight: 520)
                .task { await vpn.load() }
        }
    }
}
