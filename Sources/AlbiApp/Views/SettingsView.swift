#if canImport(SwiftUI)
import AppKit
import Diagnostics
import GPMac
import SwiftUI

/// Settings (⌘,): General and Profiles tabs.
struct SettingsView: View {
    let model: AppModel

    var body: some View {
        TabView {
            GeneralSettings(model: model)
                .tabItem { Label("General", systemImage: "gearshape") }
            ProfilesSettings(model: model)
                .tabItem { Label("Profiles", systemImage: "network") }
        }
        .frame(width: 620)
    }
}

private struct GeneralSettings: View {
    @Bindable var model: AppModel

    var body: some View {
        Form {
            Picker("At launch", selection: $model.launchBehavior) {
                ForEach(LaunchBehavior.allCases, id: \.self) { Text($0.title).tag($0) }
            }
            Text("Restore last state connects if you were connected when Albi last quit or the Mac restarted, and stays disconnected if you chose Disconnect. With a saved login, a restart after updates comes back connected without asking.")
                .font(.callout)
                .foregroundStyle(.secondary)
            Toggle("Launch at login", isOn: Binding(get: { model.launchAtLogin }, set: { model.setLaunchAtLogin($0) }))
                .disabled(!model.canLaunchAtLogin)
            Toggle("Show notifications", isOn: $model.notificationsEnabled)
            Text("Albi notifies you to approve a push, when the VPN disconnects unexpectedly, when a HIP check stops meeting the policy, and when diagnostics saves a file.")
                .font(.callout)
                .foregroundStyle(.secondary)

            Section {
                Toggle("Diagnostics mode", isOn: diagnosticsEnabled)
                Stepper("Keep the last \(model.diagnostics.windowMinutes) minutes", value: diagnosticsWindow, in: 2...30)
                    .disabled(!model.diagnostics.enabled)
                HStack {
                    Button("Save Diagnostics Now") { Task { await model.saveDiagnosticsNow() } }
                        .disabled(!model.canSaveDiagnosticsNow)
                    Button("Show in Finder") { showInFinder(model.diagnosticsLocation) }
                }
            } header: {
                Text("Diagnostics")
            } footer: {
                Text("When a dropped connection isn't back within a minute, Albi writes a redacted incident file you can attach to an issue. Changes take effect the next time you connect.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(height: 480)
    }

    private var diagnosticsEnabled: Binding<Bool> {
        Binding(get: { model.diagnostics.enabled }, set: { on in
            var d = model.diagnostics
            d.enabled = on
            Task { await model.setDiagnostics(d) }
        })
    }

    private var diagnosticsWindow: Binding<Int> {
        Binding(get: { model.diagnostics.windowMinutes }, set: { minutes in
            var d = model.diagnostics
            d.windowMinutes = minutes
            Task { await model.setDiagnostics(d) }
        })
    }
}

/// Selects the file in Finder, or opens the folder if there is no file yet.
@MainActor
func showInFinder(_ url: URL) {
    if url.hasDirectoryPath || !FileManager.default.fileExists(atPath: url.path) {
        let dir = url.hasDirectoryPath ? url : url.deletingLastPathComponent()
        NSWorkspace.shared.open(dir)
    } else {
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }
}

private struct ProfilesSettings: View {
    let model: AppModel
    @State private var selection: VPNProfile.ID?

    var body: some View {
        HStack(spacing: 0) {
            VStack(spacing: 0) {
                List(selection: $selection) {
                    ForEach(model.profiles) { p in
                        Text(p.name.isEmpty ? "Untitled" : p.name).tag(p.id)
                    }
                }
                .listStyle(.bordered)
                HStack(spacing: 0) {
                    Button {
                        Task { selection = await model.addProfile().id }
                    } label: {
                        Image(systemName: "plus").frame(width: 24, height: 20)
                    }
                    .accessibilityLabel("Add Profile")
                    Divider().frame(height: 16)
                    Button {
                        guard let id = selection else { return }
                        Task { await model.deleteProfile(id); selection = model.profiles.first?.id }
                    } label: {
                        Image(systemName: "minus").frame(width: 24, height: 20)
                    }
                    .accessibilityLabel("Remove Profile")
                    .disabled(selection == nil)
                    Spacer()
                }
                .buttonStyle(.borderless)
                .padding(4)
            }
            .frame(width: 180)
            .padding([.leading, .vertical], 20)

            if let p = model.profiles.first(where: { $0.id == selection }) {
                ProfileEditor(model: model, profile: p, connected: model.status.profileID == p.id && model.status.state.isActive)
                    .id(p.id)
            } else {
                ContentUnavailableView("No Profile Selected", systemImage: "network",
                                       description: Text("Add a profile with the + button."))
                    .frame(maxWidth: .infinity)
            }
        }
        .frame(height: 440)
        .onAppear { if selection == nil { selection = model.selectedProfileID ?? model.profiles.first?.id } }
    }
}

/// Edits one profile. Changes save shortly after you stop typing, as Mac
/// settings do; there is no Apply button.
private struct ProfileEditor: View {
    let model: AppModel
    let connected: Bool
    @State private var draft: VPNProfile
    @State private var fixedAnswer: String

    init(model: AppModel, profile: VPNProfile, connected: Bool) {
        self.model = model
        self.connected = connected
        _draft = State(initialValue: profile)
        if case .fixed(let a) = profile.secondFactor {
            _fixedAnswer = State(initialValue: a)
        } else {
            _fixedAnswer = State(initialValue: "1")
        }
    }

    var body: some View {
        Form {
            Section {
                TextField("Name", text: $draft.name)
            }
            Section("Server") {
                TextField("Portal or gateway", text: $draft.settings.server, prompt: Text("vpn.example.edu"))
                Picker("Connect to", selection: $draft.settings.mode) {
                    Text("Portal, or gateway if there's no portal").tag(Profile.Mode.auto)
                    Text("Portal").tag(Profile.Mode.portal)
                    Text("Gateway").tag(Profile.Mode.gateway)
                }
            }
            Section {
                TextField("Username", text: $draft.settings.username)
                Picker("Second factor", selection: asksEachTime) {
                    Text("Ask me each time").tag(true)
                    Text("Always answer with").tag(false)
                }
                if !asksEachTime.wrappedValue {
                    TextField("Answer", text: $fixedAnswer, prompt: Text("1"))
                        .onChange(of: fixedAnswer) { _, a in draft.secondFactor = .fixed(a) }
                }
                Toggle("Save password for unattended reconnect", isOn: $draft.settings.savePassword)
            } header: {
                Text("Login")
            } footer: {
                Text(draft.canReconnectUnattended
                     ? "Albi can log in again by itself when the gateway's login expires. An answer of 1 sends a push to your phone."
                     : "Albi will ask you to log in again when the gateway's login expires.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Section {
                TextField("Certificate pins", text: pins, prompt: Text("Use the system's trusted certificates"))
            } header: {
                Text("Security")
            } footer: {
                Text("openconnect-style pin-sha256: values, separated by spaces.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            if connected {
                Text("Changes take effect the next time you connect.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .task(id: draft) {
            try? await Task.sleep(for: .milliseconds(600))
            guard !Task.isCancelled, draft != model.profiles.first(where: { $0.id == draft.id }) else { return }
            await model.save(draft)
        }
    }

    private var asksEachTime: Binding<Bool> {
        Binding(
            get: { draft.secondFactor == .askEachTime },
            set: { draft.secondFactor = $0 ? .askEachTime : .fixed(fixedAnswer) })
    }

    private var pins: Binding<String> {
        Binding(
            get: { draft.settings.pins.joined(separator: " ") },
            set: { draft.settings.pins = $0.split(separator: " ").map(String.init) })
    }
}
#endif
