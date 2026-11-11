import GPMac
import SwiftUI

struct ContentView: View {
    @EnvironmentObject var vpn: VPNController
    @State private var password = ""

    var body: some View {
        Form {
            Section("Setup") {
                LabeledContent("System extension") {
                    HStack {
                        Text(vpn.extensionStatus)
                        Button("Activate") { vpn.activateExtension() }
                    }
                }
            }
            Section("Profile") {
                TextField("Portal or gateway", text: $vpn.profile.server)
                TextField("Username", text: $vpn.profile.username)
                    .textContentType(.username)
                Picker("Server is", selection: $vpn.profile.mode) {
                    Text("Portal, else gateway").tag(Profile.Mode.auto)
                    Text("Portal").tag(Profile.Mode.portal)
                    Text("Gateway").tag(Profile.Mode.gateway)
                }
                TextField("Second factor answer (blank to ask)", text: Binding(
                    get: { vpn.profile.secondFactor ?? "" },
                    set: { vpn.profile.secondFactor = $0.isEmpty ? nil : $0 }))
                TextField("Certificate pin (pin-sha256:…, blank for system trust)", text: Binding(
                    get: { vpn.profile.pins.joined(separator: " ") },
                    set: { vpn.profile.pins = $0.split(separator: " ").map(String.init) }))
                Toggle("Save password for unattended reconnect", isOn: $vpn.profile.savePassword)
                TextField("HIP report command (csd-wrapper)", text: $vpn.hipCommand)
                Toggle("Make HIP reports inside the extension (bundled hipreport)", isOn: Binding(
                    get: { vpn.profile.bundledHIP ?? false },
                    set: { vpn.profile.bundledHIP = $0 ? true : nil }))
                Button("Save VPN configuration") { Task { await vpn.save() } }
            }
            Section("Connection") {
                SecureField("Password", text: $password)
                    .textContentType(.password)
                HStack {
                    Button("Connect") { Task { await vpn.connect(password: password.isEmpty ? nil : password) } }
                    Button("Disconnect") { vpn.disconnect() }
                }
                LabeledContent("VPN status", value: vpn.vpnStatus)
                LabeledContent("Session", value: vpn.sessionState)
                if let ip = vpn.ipv4 { LabeledContent("Address", value: ip) }
                if let gw = vpn.gateway { LabeledContent("Gateway", value: gw) }
                if let t = vpn.lastHIPReport { LabeledContent("Last HIP report", value: t.formatted()) }
                LabeledContent("Bundled hipreport") {
                    HStack {
                        Text(vpn.hipProbe?.summary ?? "not tried")
                        Button("Test") { Task { await vpn.probeBundledHIP() } }
                    }
                }
                if let err = vpn.hipProbe?.stderrHead, !err.isEmpty {
                    Text(err).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
            Section("Diagnostics") {
                Toggle("Diagnostics mode", isOn: $vpn.diagnostics.enabled)
                Stepper("Keep the last \(vpn.diagnostics.windowMinutes) minutes",
                        value: $vpn.diagnostics.windowMinutes, in: 2...30)
                Text("When a dropped connection isn't back within a minute, the extension writes a redacted incident file. Save the VPN configuration and reconnect to apply.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button("Save diagnostics now") { Task { await vpn.saveDiagnosticsNow() } }
                        .disabled(!vpn.diagnostics.enabled)
                    Button("Show in Finder") { vpn.showDiagnostics() }
                }
                if let p = vpn.lastIncident { LabeledContent("Last incident file", value: p).textSelection(.enabled) }
            }
            if !vpn.message.isEmpty {
                Section { Text(vpn.message).foregroundStyle(.secondary).textSelection(.enabled) }
            }
        }
        .formStyle(.grouped)
        .padding()
    }
}
