#if canImport(SwiftUI)
import SwiftUI

/// The login window: username and password with AutoFill content types, then
/// progress, push approval or a code step while the tunnel connects.
struct LoginView: View {
    @Bindable var model: AppModel
    @Environment(\.dismissWindow) private var dismissWindow
    @FocusState private var focus: Field?

    enum Field { case username, password, code }

    var body: some View {
        Group {
            if let req = model.login, let profile = model.profiles.first(where: { $0.id == req.profileID }) {
                content(req, profile)
            } else {
                Text("Choose Connect from the Albi menu to log in.")
                    .foregroundStyle(.secondary)
                    .padding(40)
            }
        }
        .frame(width: 400)
        .onChange(of: model.login == nil) { _, closed in
            if closed { dismissWindow(id: AlbiWindow.login) }
        }
    }

    @ViewBuilder
    private func content(_ req: LoginRequest, _ profile: VPNProfile) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: "lock.shield")
                    .font(.system(size: 36))
                    .foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Log in to \(profile.name)").font(.headline)
                    Text(profile.settings.server).foregroundStyle(.secondary)
                }
            }

            if case .needsSecondFactor(let prompt) = model.status.state, req.submitted {
                codeStep(prompt)
            } else if req.submitted {
                progress
            } else {
                passwordStep(req)
            }
        }
        .padding(20)
    }

    private func passwordStep(_ req: LoginRequest) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Form {
                TextField("Username:", text: username)
                    .textContentType(.username)
                    .focused($focus, equals: .username)
                SecureField("Password:", text: password)
                    .textContentType(.password)
                    .focused($focus, equals: .password)
                Toggle("Save password for unattended reconnect", isOn: savePassword)
            }
            if let error = req.error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.callout)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { Task { await model.cancelLogin() } }
                    .keyboardShortcut(.cancelAction)
                Button("Log In") { Task { await model.submitLogin() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(req.username.isEmpty || req.password.isEmpty)
            }
        }
        .onAppear { focus = req.username.isEmpty ? .username : .password }
    }

    private func codeStep(_ prompt: String) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(prompt)
            Form {
                TextField("Code:", text: code)
                    .textContentType(.oneTimeCode)
                    .focused($focus, equals: .code)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { Task { await model.cancelLogin() } }
                    .keyboardShortcut(.cancelAction)
                Button("Continue") { Task { await model.submitCode() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(model.login?.code.isEmpty ?? true)
            }
        }
        .onAppear { focus = .code }
    }

    private var progress: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text(model.status.state.title(profile: nil))
            }
            if case .waitingForPush = model.status.state {
                Text("Approve the sign-in on your phone. Albi finishes connecting once you do.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { Task { await model.cancelLogin() } }
                    .keyboardShortcut(.cancelAction)
            }
        }
    }

    private var username: Binding<String> {
        Binding(get: { model.login?.username ?? "" }, set: { model.login?.username = $0 })
    }
    private var password: Binding<String> {
        Binding(get: { model.login?.password ?? "" }, set: { model.login?.password = $0 })
    }
    private var code: Binding<String> {
        Binding(get: { model.login?.code ?? "" }, set: { model.login?.code = $0 })
    }
    private var savePassword: Binding<Bool> {
        Binding(get: { model.login?.savePassword ?? false }, set: { model.login?.savePassword = $0 })
    }
}
#endif
