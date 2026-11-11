#if canImport(SwiftUI)
import Foundation
import GPMac
import Observation

/// Posts user notifications. The live one uses UNUserNotificationCenter.
@MainActor
public protocol Notifier: AnyObject {
    func post(id: String, title: String, body: String)
}

/// Launch at login. The live one uses SMAppService.mainApp.
@MainActor
public protocol LoginItem: AnyObject {
    var isEnabled: Bool { get }
    func setEnabled(_ on: Bool) throws
}

/// The login window's state: the password step, then (for profiles that ask
/// each time) the code step, while the tunnel connects.
public struct LoginRequest: Equatable, Sendable {
    public var profileID: VPNProfile.ID
    public var username: String
    public var password = ""
    public var savePassword: Bool
    public var code = ""
    public var error: String?
    /// The user pressed Log In and the tunnel is working on it.
    public var submitted = false
}

/// The app's state and actions, for the menu, the windows and Settings.
@MainActor
@Observable
public final class AppModel {
    public private(set) var profiles: [VPNProfile] = []
    /// The profile Connect uses. Remembered across launches.
    public var selectedProfileID: VPNProfile.ID? {
        didSet { defaults.set(selectedProfileID?.uuidString, forKey: Self.selectedKey) }
    }
    public private(set) var status: TunnelStatus = .disconnected
    public private(set) var setup = SetupStatus()
    public var login: LoginRequest?
    public var notificationsEnabled: Bool {
        didSet { defaults.set(notificationsEnabled, forKey: Self.notificationsKey) }
    }
    /// The last error from an action, shown in the menu.
    public private(set) var lastError: String?

    @ObservationIgnored private let service: any VPNService
    @ObservationIgnored private let notifier: (any Notifier)?
    @ObservationIgnored private let loginItem: (any LoginItem)?
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private var watch: Task<Void, Never>?
    @ObservationIgnored private var userDisconnected = false

    static let selectedKey = "selectedProfile"
    static let notificationsKey = "notificationsEnabled"

    public init(service: any VPNService, notifier: (any Notifier)? = nil, loginItem: (any LoginItem)? = nil,
                defaults: UserDefaults = .standard) {
        self.service = service
        self.notifier = notifier
        self.loginItem = loginItem
        self.defaults = defaults
        notificationsEnabled = defaults.object(forKey: Self.notificationsKey) as? Bool ?? true
        selectedProfileID = defaults.string(forKey: Self.selectedKey).flatMap(UUID.init(uuidString:))
        launchAtLogin = loginItem?.isEnabled ?? false
    }

    /// Loads profiles and setup and starts following the tunnel. Call once at launch.
    public func start() async {
        await reload()
        setup = await service.setupStatus()
        guard watch == nil else { return }
        let updates = service.statusUpdates()
        watch = Task { [weak self] in
            for await s in updates {
                guard let self else { return }
                self.apply(s)
            }
        }
    }

    public func reload() async {
        do {
            profiles = try await service.loadProfiles()
        } catch {
            lastError = "Couldn't load VPN configurations: \(error.localizedDescription)"
        }
        if selectedProfile == nil { selectedProfileID = profiles.first?.id }
    }

    public var selectedProfile: VPNProfile? { profiles.first { $0.id == selectedProfileID } }
    public var connectedProfile: VPNProfile? { profiles.first { $0.id == status.profileID } }

    // MARK: Connecting

    public enum ConnectOutcome: Equatable { case started, needsLogin, nothingSelected }

    /// Connects the selected profile, or asks for the password first. The
    /// caller opens the login window on `.needsLogin`.
    @discardableResult
    public func connect() async -> ConnectOutcome {
        guard let p = selectedProfile else { return .nothingSelected }
        if await service.hasSavedPassword(for: p.id) {
            await start(p.id, password: nil)
            return .started
        }
        login = LoginRequest(profileID: p.id, username: p.settings.username, savePassword: p.settings.savePassword)
        return .needsLogin
    }

    /// The login window's Log In button.
    public func submitLogin() async {
        guard var req = login, var p = profiles.first(where: { $0.id == req.profileID }) else { return }
        if p.settings.username != req.username || p.settings.savePassword != req.savePassword {
            p.settings.username = req.username
            p.settings.savePassword = req.savePassword
            await save(p)
        }
        req.error = nil
        req.submitted = true
        login = req
        await start(p.id, password: req.password)
    }

    /// The login window's Continue button on the code step.
    public func submitCode() async {
        guard let code = login?.code, !code.isEmpty else { return }
        login?.code = ""
        await service.answerSecondFactor(code)
    }

    public func cancelLogin() async {
        let wasWorking = login?.submitted == true
        login = nil
        if wasWorking { await disconnect() }
    }

    public func disconnect() async {
        userDisconnected = true
        await service.disconnect()
    }

    private func start(_ id: VPNProfile.ID, password: String?) async {
        userDisconnected = false
        lastError = nil
        do {
            try await service.connect(id, password: password)
        } catch {
            lastError = error.localizedDescription
            if login != nil { login?.error = error.localizedDescription; login?.submitted = false }
        }
    }

    /// Takes a status from the tunnel: updates the login window and posts
    /// notifications on the transitions that matter.
    func apply(_ new: TunnelStatus) {
        let old = status
        status = new
        let name = profiles.first { $0.id == new.profileID }?.name ?? "VPN"

        switch new.state {
        case .waitingForPush where old.state != .waitingForPush:
            notify("push", "Approve the sign-in", "Albi sent a push to your phone for \(name).")
        case .needsSecondFactor where login == nil:
            // An unattended re-auth needs a code: bring back the login window's code step.
            if let p = connectedProfile ?? selectedProfile {
                login = LoginRequest(profileID: p.id, username: p.settings.username, savePassword: p.settings.savePassword,
                                     submitted: true)
            }
            notify("code", "Verification code needed", "\(name) needs a code to stay connected.")
        case .connected:
            login = nil
        case .needsLogin(let reason):
            if login != nil {
                login?.submitted = false
                login?.password = ""
                login?.error = reason
            } else if old.state.isActive {
                notify("disconnected", "\(name) disconnected", reason)
            }
        case .failed(let reason):
            login?.submitted = false
            login?.error = reason
            if old.state.isActive { notify("disconnected", "\(name) disconnected", reason) }
        case .disconnected where old.state.isActive && !userDisconnected:
            notify("disconnected", "\(name) disconnected", "The VPN connection ended unexpectedly.")
        default:
            break
        }

        if let hip = new.hip, !hip.isCompliant, old.hip?.isCompliant ?? true {
            let names = hip.failing.map(\.name).joined(separator: ", ")
            notify("hip", "HIP check failing", "\(names) no longer meets the expected policy.")
        }
    }

    private func notify(_ id: String, _ title: String, _ body: String) {
        guard notificationsEnabled else { return }
        notifier?.post(id: id, title: title, body: body)
    }

    // MARK: Profiles

    public func save(_ profile: VPNProfile) async {
        do {
            try await service.save(profile)
            if let i = profiles.firstIndex(where: { $0.id == profile.id }) {
                profiles[i] = profile
            } else {
                profiles.append(profile)
            }
        } catch {
            lastError = "Couldn't save \(profile.name): \(error.localizedDescription)"
        }
    }

    /// A new, empty profile, saved and selected.
    @discardableResult
    public func addProfile() async -> VPNProfile {
        var p = VPNProfile(name: "New VPN", settings: Profile(server: "", username: NSUserName()))
        p.secondFactor = .fixed("1")
        await save(p)
        if selectedProfileID == nil { selectedProfileID = p.id }
        return p
    }

    public func deleteProfile(_ id: VPNProfile.ID) async {
        if status.profileID == id, status.state.isActive { await disconnect() }
        do {
            try await service.delete(id)
            profiles.removeAll { $0.id == id }
            if selectedProfileID == id { selectedProfileID = profiles.first?.id }
        } catch {
            lastError = error.localizedDescription
        }
    }

    // MARK: Setup

    public func refreshSetup() async { setup = await service.setupStatus() }
    public func activateSystemExtension() async { await service.activateSystemExtension(); await refreshSetup() }
    public func allowVPNConfiguration() async { await service.allowVPNConfiguration(); await refreshSetup() }
    public func registerHIPHelper() async { await service.registerHIPHelper(); await refreshSetup() }

    // MARK: Launch at login

    public private(set) var launchAtLogin = false
    public var canLaunchAtLogin: Bool { loginItem != nil }

    public func setLaunchAtLogin(_ on: Bool) {
        do { try loginItem?.setEnabled(on) } catch { lastError = "Couldn't change Launch at Login: \(error.localizedDescription)" }
        launchAtLogin = loginItem?.isEnabled ?? false
    }
}
#endif
