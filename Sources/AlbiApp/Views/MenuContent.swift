#if canImport(SwiftUI)
import AppKit
import SwiftUI

/// The menu-bar menu. A real NSMenu (`.menuBarExtraStyle(.menu)`), so it reads
/// and behaves like the system's own VPN menu.
struct MenuContent: View {
    @Bindable var model: AppModel
    let demo: MockVPNService?
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        let s = model.status
        let name = model.connectedProfile?.name ?? model.selectedProfile?.name

        Text(s.state.title(profile: name))
        if let detail = s.state.detail { Text(detail) }
        if s.state.isConnected {
            if let ip = s.ipv4, let gw = s.gateway { Text("\(ip) via \(gw)") }
            if let since = s.connectedSince {
                Text("Connected since \(since.formatted(date: .omitted, time: .shortened))")
            }
            if let expiry = s.expiryText() { Text(expiry) }
            if let hip = s.hip, !hip.isCompliant {
                Text("HIP: \(hip.failing.count) check\(hip.failing.count == 1 ? "" : "s") failing")
            }
            if !s.routes.isEmpty || !s.dnsDomains.isEmpty {
                Menu("Network Details") {
                    Section("Routes") {
                        ForEach(s.routes, id: \.self) { Text($0) }
                    }
                    Section("DNS Domains") {
                        ForEach(s.dnsDomains, id: \.self) { Text($0) }
                    }
                }
            }
        }
        if let error = model.lastError { Text(error) }

        Divider()

        if s.state.isActive {
            if case .needsSecondFactor = s.state {
                Button("Enter Verification Code…") { present(AlbiWindow.login, openWindow) }
            }
            Button("Disconnect") { Task { await model.disconnect() } }
        } else {
            Button(model.selectedProfile.map { "Connect to \($0.name)" } ?? "Connect") {
                Task {
                    if await model.connect() == .needsLogin { present(AlbiWindow.login, openWindow) }
                }
            }
            .disabled(model.selectedProfile == nil || !model.setup.isReady)
        }

        if model.profiles.count > 1 {
            Divider()
            Picker("Profile", selection: $model.selectedProfileID) {
                ForEach(model.profiles) { p in
                    Text(p.name).tag(Optional(p.id))
                }
            }
            .pickerStyle(.inline)
            .labelsHidden()
            .disabled(s.state.isActive)
        }

        Divider()

        Button("HIP Compliance…") { present(AlbiWindow.hip, openWindow) }
        if model.diagnostics.enabled {
            Menu("Diagnostics") {
                Button("Save Diagnostics Now") { Task { await model.saveDiagnosticsNow() } }
                    .disabled(!model.canSaveDiagnosticsNow)
                Button("Show Diagnostics in Finder") { showInFinder(model.diagnosticsLocation) }
            }
        }
        if !model.setup.isReady {
            Button("Set Up Albi…") { present(AlbiWindow.setup, openWindow) }
        }
        Button("Settings…") {
            openSettings()
            NSApp.activate()
        }
        .keyboardShortcut(",")

        if let demo {
            Menu("Demo") {
                Button("Drop Connection") { demo.simulateDrop() }
                Button("Fail a HIP Check") { demo.simulateHIPFailure() }
                Button("Record an Incident") { demo.simulateIncident() }
            }
        }

        Divider()

        Button("Quit Albi") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }
}
#endif
