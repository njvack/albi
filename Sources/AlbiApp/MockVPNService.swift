#if canImport(SwiftUI)
import Foundation
import GPMac

/// A pretend tunnel for previews, the demo build and tests. It walks through
/// the same states the extension does, `step` apart.
///
/// The password "wrong" is rejected. A profile set to ask each time accepts
/// any code except "000000".
@MainActor
public final class MockVPNService: VPNService {
    public var profiles: [VPNProfile]
    public var savedPasswords: Set<VPNProfile.ID> = []
    public var setup: SetupStatus
    public var step: Duration
    /// Checks the mock reports once connected.
    public var hipChecks: [HIPCheck] = MockVPNService.sampleChecks
    public internal(set) var connectCalls: [(id: VPNProfile.ID, password: String?)] = []

    private let status = StatusBroadcaster()
    private var run: Task<Void, Never>?
    private var secondFactor: CheckedContinuation<String, Never>?

    public init(profiles: [VPNProfile] = [], setup: SetupStatus = SetupStatus(), step: Duration = .milliseconds(600)) {
        self.profiles = profiles
        self.setup = setup
        self.step = step
    }

    /// Two profiles and a finished setup, for the demo build and previews.
    public static func demo() -> MockVPNService {
        var work = VPNProfile(name: "Work", settings: Profile(server: "vpn.example.edu", username: "nate"))
        work.secondFactor = .fixed("1")
        var lab = VPNProfile(name: "Lab", settings: Profile(server: "gp.lab.example.edu", username: "nvack"))
        lab.secondFactor = .askEachTime
        lab.settings.savePassword = false
        let m = MockVPNService(profiles: [work, lab],
                               setup: SetupStatus(systemExtension: .active, vpnConfigurationAllowed: true, hipHelper: .notRegistered))
        m.savedPasswords = [work.id]
        return m
    }

    public func currentStatus() async -> TunnelStatus { status.current }

    // MARK: Profiles

    public func loadProfiles() async throws -> [VPNProfile] { profiles }

    public func save(_ profile: VPNProfile) async throws {
        if let i = profiles.firstIndex(where: { $0.id == profile.id }) {
            profiles[i] = profile
        } else {
            profiles.append(profile)
        }
        if !profile.settings.savePassword { savedPasswords.remove(profile.id) }
    }

    public func delete(_ id: VPNProfile.ID) async throws {
        profiles.removeAll { $0.id == id }
        savedPasswords.remove(id)
    }

    public func hasSavedPassword(for id: VPNProfile.ID) async -> Bool { savedPasswords.contains(id) }

    // MARK: Tunnel

    public func connect(_ id: VPNProfile.ID, password: String?) async throws {
        guard let profile = profiles.first(where: { $0.id == id }) else { return }
        connectCalls.append((id, password))
        if password != nil, profile.settings.savePassword { savedPasswords.insert(id) }
        run?.cancel()
        run = Task { [weak self] in await self?.walk(profile, password: password) }
    }

    public func disconnect() async {
        run?.cancel()
        run = nil
        secondFactor?.resume(returning: "")
        secondFactor = nil
        status.update { $0.state = .disconnecting }
        try? await Task.sleep(for: step / 2)
        status.send(.disconnected)
    }

    public func answerSecondFactor(_ code: String) async {
        secondFactor?.resume(returning: code)
        secondFactor = nil
    }

    /// Drops the tunnel and reconnects, for trying the reconnecting state.
    public func simulateDrop(attempts: Int = 2) {
        guard status.current.state.isConnected else { return }
        run?.cancel()
        run = Task { [weak self] in
            guard let self else { return }
            for n in 1...max(attempts, 1) {
                self.status.update { $0.state = .reconnecting(attempt: n, reason: "The gateway stopped answering keepalives.") }
                guard await self.pause() else { return }
            }
            self.status.update { $0.state = .connected(.https) }
        }
    }

    /// Makes one HIP check fail, for trying the compliance notification.
    public func simulateHIPFailure() {
        status.update { s in
            guard var hip = s.hip, !hip.checks.isEmpty else { return }
            hip.checks[0].actual = "Off"
            hip.checks[0].passed = false
            s.hip = hip
        }
    }

    public func statusUpdates() -> AsyncStream<TunnelStatus> { status.stream() }

    private func walk(_ profile: VPNProfile, password: String?) async {
        var s = TunnelStatus(profileID: profile.id, state: .authenticating)
        status.send(s)
        guard await pause() else { return }
        if password == "wrong" {
            status.send(TunnelStatus(profileID: profile.id, state: .needsLogin(reason: "The gateway rejected the username or password.")))
            return
        }
        switch profile.secondFactor {
        case .fixed:
            s.state = .waitingForPush
            status.send(s)
            guard await pause(times: 3) else { return }
        case .askEachTime:
            s.state = .needsSecondFactor(prompt: "Enter the code from your authenticator app.")
            status.send(s)
            let code = await withCheckedContinuation { secondFactor = $0 }
            guard !Task.isCancelled else { return }
            if code == "000000" {
                status.send(TunnelStatus(profileID: profile.id, state: .needsLogin(reason: "The gateway rejected the code.")))
                return
            }
        }
        for phase in [TunnelState.Phase.config, .hip, .tunnel] {
            s.state = .connecting(phase)
            if phase == .hip { s.hip = HIPStatus(requested: true) }
            status.send(s)
            guard await pause() else { return }
        }
        let now = Date()
        s.state = .connected(.https)
        s.gateway = profile.settings.server
        s.ipv4 = "10.99.0.2"
        s.connectedSince = now
        s.cookieExpiry = now.addingTimeInterval(8 * 3600)
        s.routes = ["10.0.0.0/8", "172.16.0.0/12", "128.104.0.0/16"]
        s.dnsDomains = ["example.edu", "lab.example.edu"]
        s.hip = HIPStatus(requested: true, lastSent: now, checks: hipChecks)
        status.send(s)
    }

    private func pause(times: Int = 1) async -> Bool {
        try? await Task.sleep(for: step * times)
        return !Task.isCancelled
    }

    public static let sampleChecks: [HIPCheck] = [
        HIPCheck(id: "disk-encryption", category: "Disk encryption", name: "FileVault (Macintosh HD)",
                 expected: "Encrypted", actual: "Encrypted", method: "fdesetup status", passed: true),
        HIPCheck(id: "firewall", category: "Firewall", name: "macOS Application Firewall",
                 expected: "On", actual: "On", method: "socketfilterfw --getglobalstate", passed: true),
        HIPCheck(id: "os-version", category: "Operating system", name: "macOS",
                 expected: "27.0 or later", actual: "27.1", method: "sw_vers -productVersion", passed: true),
        HIPCheck(id: "anti-malware", category: "Anti-malware", name: "XProtect",
                 expected: "Definitions within 30 days", actual: "Updated 3 days ago", method: "bundle version of XProtect.bundle", passed: true),
        HIPCheck(id: "pf", category: "Firewall", name: "Packet filter",
                 expected: "No expectation", actual: "n/a (helper not registered)", method: "root helper: pf.enabled", passed: nil),
    ]

    // MARK: Setup

    public func setupStatus() async -> SetupStatus { setup }

    public func activateSystemExtension() async {
        setup.systemExtension = .awaitingApproval
        try? await Task.sleep(for: step * 2)
        setup.systemExtension = .active
    }

    public func allowVPNConfiguration() async { setup.vpnConfigurationAllowed = true }

    public func registerHIPHelper() async { setup.hipHelper = .registered }
}
#endif
