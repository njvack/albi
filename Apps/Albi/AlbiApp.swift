import SwiftUI

// Step 1 test build: one window to set up the profile, approve the
// extension, connect and watch the session. The menu-bar app is Phase 3.
@main
struct AlbiApp: App {
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
