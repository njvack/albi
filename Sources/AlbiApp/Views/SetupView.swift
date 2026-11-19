#if canImport(SwiftUI)
import AppKit
import SwiftUI

/// The setup checklist. Opens at launch while anything still needs approval;
/// each row links to the approval macOS needs.
struct SetupView: View {
    let model: AppModel
    @Environment(\.dismissWindow) private var dismissWindow

    var body: some View {
        let setup = model.setup
        VStack(alignment: .leading, spacing: 16) {
            Text(setup.backend == .helper ? "Albi needs your OK before it can connect." : "Albi needs your OK for a few things before it can connect.")
                .fixedSize(horizontal: false, vertical: true)
            Form {
                switch setup.backend {
                case .helper: helperRow(setup.helper)
                case .systemExtension: extensionRows(setup)
                }
            }
            .formStyle(.grouped)
            .scrollDisabled(true)
            HStack {
                Spacer()
                Button("Done") { dismissWindow(id: AlbiWindow.setup) }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!setup.isReady)
            }
        }
        .padding(20)
        .frame(width: 500)
        .task {
            // Approvals happen in System Settings, so look again every few
            // seconds while something is still missing.
            await model.refreshSetup()
            while !Task.isCancelled && !model.setup.isReady {
                try? await Task.sleep(for: .seconds(2))
                await model.refreshSetup()
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { await model.refreshSetup() }
        }
    }

    /// The helper backend's one item: the albi-helper LaunchDaemon, which
    /// also makes the HIP checks that need root.
    @ViewBuilder private func helperRow(_ h: SetupStatus.Helper) -> some View {
        SetupRow(done: h == .registered, title: "Approve the Albi helper", detail: helperDetail(h)) {
            switch h {
            case .notRegistered: Button("Approve…") { Task { await model.registerHelper() } }
            case .awaitingApproval: Button("Open System Settings…") { openLoginItemsSettings() }
            case .needsReinstall: Button("Reinstall") { Task { await model.registerHelper() } }
            case .registered, .unavailable: EmptyView()
            }
        }
    }

    private func helperDetail(_ h: SetupStatus.Helper) -> String {
        switch h {
        case .notRegistered: "Albi's tunnel runs in a small helper that macOS starts as root. It also lets HIP checks read settings only root can see. You allow it once."
        case .awaitingApproval: "Turn on Albi in System Settings › General › Login Items & Extensions, under Allow in the Background."
        case .registered: "Installed and running."
        case .needsReinstall(let why): "\(why) Reinstall it; macOS may ask you to allow it again."
        case .unavailable(let why): why
        }
    }

    @ViewBuilder private func extensionRows(_ setup: SetupStatus) -> some View {
        SetupRow(
            done: setup.systemExtension == .active,
            title: "Tunnel extension",
            detail: extensionDetail(setup.systemExtension)
        ) {
            switch setup.systemExtension {
            case .notActivated, .failed:
                Button("Install") { Task { await model.activateSystemExtension() } }
            case .awaitingApproval:
                Button("Open System Settings…") { openLoginItemsSettings() }
            case .active:
                EmptyView()
            }
        }
        SetupRow(
            done: setup.vpnConfigurationAllowed,
            title: "VPN configuration",
            detail: "macOS asks once before Albi can add VPN configurations."
        ) {
            Button("Allow…") { Task { await model.allowVPNConfiguration() } }
                .disabled(setup.systemExtension != .active)
        }
        SetupRow(
            done: setup.helper == .registered,
            title: "HIP helper (optional)",
            detail: "Lets HIP checks read settings only root can see, such as the packet filter. Without it, those checks report n/a."
        ) {
            switch setup.helper {
            case .notRegistered, .needsReinstall: Button("Register") { Task { await model.registerHelper() } }
            case .awaitingApproval: Button("Open System Settings…") { openLoginItemsSettings() }
            case .registered, .unavailable: EmptyView()
            }
        }
    }

    private func extensionDetail(_ e: SetupStatus.Extension) -> String {
        switch e {
        case .notActivated: "Albi's tunnel runs as a system extension, which you allow once."
        case .awaitingApproval: "Turn on Albi in System Settings › General › Login Items & Extensions › Network Extensions."
        case .active: "Installed and allowed."
        case .failed(let why): "Installing failed: \(why)"
        }
    }

    private func openLoginItemsSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") {
            NSWorkspace.shared.open(url)
        }
    }
}

private struct SetupRow<Action: View>: View {
    let done: Bool
    let title: String
    let detail: String
    @ViewBuilder let action: () -> Action

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: done ? "checkmark.circle.fill" : "circle.dashed")
                .foregroundStyle(done ? AnyShapeStyle(.green) : AnyShapeStyle(.secondary))
                .accessibilityLabel(done ? "Done" : "Not done")
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            if !done { action() }
        }
    }
}
#endif
