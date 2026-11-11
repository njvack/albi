#if canImport(SwiftUI)
import Foundation
import GPMac
import Testing
@testable import AlbiApp

@MainActor
final class RecordingNotifier: Notifier {
    var posted: [String] = []
    func post(id: String, title: String, body: String) { posted.append(id) }
}

@MainActor
final class FakeLoginItem: LoginItem {
    var isEnabled = false
    func setEnabled(_ on: Bool) throws { isEnabled = on }
}

@MainActor
private func freshDefaults() -> UserDefaults {
    let name = "AlbiAppTests-\(UUID().uuidString)"
    let d = UserDefaults(suiteName: name)!
    d.removePersistentDomain(forName: name)
    return d
}

@MainActor
private func makeModel(_ service: MockVPNService, notifier: RecordingNotifier = RecordingNotifier()) async -> AppModel {
    let m = AppModel(service: service, notifier: notifier, loginItem: FakeLoginItem(), defaults: freshDefaults())
    await m.start()
    return m
}

/// Waits (up to two seconds) for the model's tunnel state to satisfy `ok`.
@MainActor
private func waitFor(_ model: AppModel, _ ok: (TunnelState) -> Bool) async throws {
    for _ in 0..<200 {
        if ok(model.status.state) { return }
        try await Task.sleep(for: .milliseconds(10))
    }
    Issue.record("timed out in state \(model.status.state)")
}

@MainActor
@Suite struct ProfileTests {
    @Test func secondFactorMapsOntoProfile() {
        var p = VPNProfile(name: "Work", settings: Profile(server: "vpn.example.edu", username: "nate"))
        p.secondFactor = .askEachTime
        #expect(p.settings.secondFactor == nil)
        #expect(!p.canReconnectUnattended)
        p.secondFactor = .fixed("1")
        #expect(p.settings.secondFactor == "1")
        p.settings.savePassword = true
        #expect(p.canReconnectUnattended)
        p.settings.savePassword = false
        #expect(!p.canReconnectUnattended)
    }

    @Test func addingAndDeletingProfiles() async {
        let service = MockVPNService(step: .zero)
        let model = await makeModel(service)
        let p = await model.addProfile()
        #expect(model.profiles.map(\.id) == [p.id])
        #expect(model.selectedProfileID == p.id)
        #expect(service.profiles.map(\.id) == [p.id])
        await model.deleteProfile(p.id)
        #expect(model.profiles.isEmpty)
        #expect(model.selectedProfileID == nil)
    }

    @Test func selectionIsRemembered() async {
        let service = MockVPNService.demo()
        let defaults = freshDefaults()
        let a = AppModel(service: service, defaults: defaults)
        await a.start()
        a.selectedProfileID = service.profiles[1].id
        let b = AppModel(service: service, defaults: defaults)
        await b.start()
        #expect(b.selectedProfileID == service.profiles[1].id)
    }
}

@MainActor
@Suite struct ConnectTests {
    @Test func savedPasswordConnectsWithoutLogin() async throws {
        let service = MockVPNService.demo()
        service.step = .zero
        let notifier = RecordingNotifier()
        let model = await makeModel(service, notifier: notifier)
        model.selectedProfileID = service.profiles[0].id

        #expect(await model.connect() == .started)
        #expect(model.login == nil)
        #expect(service.connectCalls.last?.password == nil)
        try await waitFor(model) { $0.isConnected }
        #expect(model.status.gateway == "vpn.example.edu")
        #expect(model.status.hip?.isCompliant == true)
        #expect(notifier.posted == ["push"])
    }

    @Test func noSavedPasswordAsksFirst() async throws {
        let service = MockVPNService.demo()
        service.step = .zero
        let model = await makeModel(service)
        let lab = service.profiles[1]
        model.selectedProfileID = lab.id

        #expect(await model.connect() == .needsLogin)
        #expect(model.login?.username == "nvack")
        #expect(service.connectCalls.isEmpty)

        model.login?.password = "secret"
        model.login?.savePassword = true
        await model.submitLogin()
        #expect(service.connectCalls.last?.password == "secret")
        #expect(service.profiles[1].settings.savePassword)
        #expect(model.login?.submitted == true)

        try await waitFor(model) { if case .needsSecondFactor = $0 { true } else { false } }
        model.login?.code = "123456"
        await model.submitCode()
        try await waitFor(model) { $0.isConnected }
        #expect(model.login == nil)
    }

    @Test func rejectedPasswordReturnsToTheLoginWindow() async throws {
        let service = MockVPNService.demo()
        service.step = .zero
        let notifier = RecordingNotifier()
        let model = await makeModel(service, notifier: notifier)
        model.selectedProfileID = service.profiles[1].id
        await model.connect()
        model.login?.password = "wrong"
        await model.submitLogin()
        try await waitFor(model) { if case .needsLogin = $0 { true } else { false } }
        #expect(model.login?.submitted == false)
        #expect(model.login?.password == "")
        #expect(model.login?.error != nil)
        #expect(!notifier.posted.contains("disconnected"))
    }

    @Test func cancelDuringLoginDisconnects() async throws {
        let service = MockVPNService.demo()
        service.step = .seconds(10)
        let model = await makeModel(service)
        model.selectedProfileID = service.profiles[1].id
        await model.connect()
        model.login?.password = "secret"
        await model.submitLogin()
        try await waitFor(model) { $0 == .authenticating }
        service.step = .zero
        await model.cancelLogin()
        #expect(model.login == nil)
        try await waitFor(model) { $0 == .disconnected }
    }

    @Test func connectNeedsASelection() async {
        let model = await makeModel(MockVPNService(step: .zero))
        #expect(await model.connect() == .nothingSelected)
    }
}

@MainActor
@Suite struct NotificationTests {
    private func connected(_ service: MockVPNService) -> TunnelStatus {
        TunnelStatus(profileID: service.profiles[0].id, state: .connected(.https), gateway: "gw",
                     hip: HIPStatus(requested: true, checks: MockVPNService.sampleChecks))
    }

    @Test func unexpectedDisconnectNotifies() async {
        let service = MockVPNService.demo()
        let notifier = RecordingNotifier()
        let model = await makeModel(service, notifier: notifier)
        model.apply(connected(service))
        model.apply(.disconnected)
        #expect(notifier.posted == ["disconnected"])
    }

    @Test func userDisconnectDoesNotNotify() async throws {
        let service = MockVPNService.demo()
        service.step = .zero
        let notifier = RecordingNotifier()
        let model = await makeModel(service, notifier: notifier)
        model.selectedProfileID = service.profiles[0].id
        await model.connect()
        try await waitFor(model) { $0.isConnected }
        await model.disconnect()
        try await waitFor(model) { $0 == .disconnected }
        #expect(notifier.posted == ["push"])
    }

    @Test func hipGoingOutOfComplianceNotifiesOnce() async {
        let service = MockVPNService.demo()
        let notifier = RecordingNotifier()
        let model = await makeModel(service, notifier: notifier)
        var s = connected(service)
        model.apply(s)
        s.hip?.checks[0].passed = false
        model.apply(s)
        model.apply(s)
        #expect(notifier.posted == ["hip"])
    }

    @Test func turningNotificationsOffSilencesThem() async {
        let service = MockVPNService.demo()
        let notifier = RecordingNotifier()
        let model = await makeModel(service, notifier: notifier)
        model.notificationsEnabled = false
        model.apply(connected(service))
        model.apply(.disconnected)
        #expect(notifier.posted.isEmpty)
    }

    @Test func codeNeededDuringUnattendedReauthOpensTheCodeStep() async {
        let service = MockVPNService.demo()
        let notifier = RecordingNotifier()
        let model = await makeModel(service, notifier: notifier)
        model.apply(connected(service))
        var s = connected(service)
        s.state = .needsSecondFactor(prompt: "Code?")
        model.apply(s)
        #expect(model.login?.submitted == true)
        #expect(notifier.posted == ["code"])
    }
}

@MainActor
@Suite struct SetupAndPresentationTests {
    @Test func setupNeedsExtensionAndConfiguration() async {
        let service = MockVPNService(step: .zero)
        let model = await makeModel(service)
        #expect(!model.setup.isReady)
        await model.activateSystemExtension()
        #expect(model.setup.systemExtension == .active)
        #expect(!model.setup.isReady)
        await model.allowVPNConfiguration()
        #expect(model.setup.isReady)
        #expect(model.setup.hipHelper == .notRegistered)
    }

    @Test func launchAtLogin() async {
        let model = await makeModel(MockVPNService(step: .zero))
        #expect(!model.launchAtLogin)
        model.setLaunchAtLogin(true)
        #expect(model.launchAtLogin)
    }

    @Test func everyStateHasItsOwnIconOrTitle() {
        let states: [TunnelState] = [
            .disconnected, .authenticating, .waitingForPush, .needsSecondFactor(prompt: ""),
            .connecting(.config), .connecting(.hip), .connecting(.tunnel), .connected(.esp), .connected(.https),
            .reconnecting(attempt: 3, reason: "x"), .waitingForNetwork, .disconnecting,
            .needsLogin(reason: "x"), .failed(reason: "x"),
        ]
        let titles = Set(states.map { $0.title(profile: "Work") })
        #expect(titles.count == states.count)
        #expect(TunnelState.reconnecting(attempt: 3, reason: "x").title(profile: nil) == "Reconnecting (Attempt 3)…")
        #expect(TunnelState.connected(.esp).symbolName != TunnelState.connected(.https).symbolName)
        #expect(TunnelState.disconnected.symbolName != TunnelState.connected(.https).symbolName)
    }

    @Test func expiryText() {
        let now = Date(timeIntervalSince1970: 1_000_000)
        var s = TunnelStatus(state: .connected(.https))
        #expect(s.expiryText(now: now) == nil)
        s.cookieExpiry = now.addingTimeInterval(-1)
        #expect(s.expiryText(now: now) == "Login expired")
        s.cookieExpiry = now.addingTimeInterval(7 * 3600 + 59 * 60)
        #expect(s.expiryText(now: now)?.hasPrefix("Login expires in 7") == true)
    }
}
#endif

#if canImport(SwiftUI)
@MainActor
@Suite struct LaunchBehaviorTests {
    /// A second launch of the app against the same service and defaults.
    private func relaunch(_ service: MockVPNService, _ defaults: UserDefaults) async -> AppModel {
        let m = AppModel(service: service, defaults: defaults)
        await m.start()
        return m
    }

    private func connectedThenQuit(_ service: MockVPNService, _ defaults: UserDefaults) async throws {
        let first = await relaunch(service, defaults)
        first.selectedProfileID = service.profiles[0].id
        await first.connect()
        try await waitFor(first) { $0.isConnected }
    }

    @Test func restoreIsTheDefault() {
        #expect(AppModel(service: MockVPNService(), defaults: freshDefaults()).launchBehavior == .restore)
    }

    @Test func restoreReconnectsAfterARestart() async throws {
        let service = MockVPNService.demo()
        service.step = .zero
        let defaults = freshDefaults()
        try await connectedThenQuit(service, defaults)
        // The Mac restarts: the tunnel is gone, but the user never chose Disconnect.
        await service.disconnect()
        service.connectCalls.removeAll()
        let second = await relaunch(service, defaults)
        #expect(await second.connectAtLaunch() == .started)
        #expect(service.connectCalls.map(\.id) == [service.profiles[0].id])
    }

    @Test func restoreStaysDisconnectedAfterDisconnect() async throws {
        let service = MockVPNService.demo()
        service.step = .zero
        let defaults = freshDefaults()
        try await connectedThenQuit(service, defaults)
        let first = await relaunch(service, defaults)
        await first.disconnect()
        service.connectCalls.removeAll()
        let second = await relaunch(service, defaults)
        #expect(await second.connectAtLaunch() == nil)
        #expect(service.connectCalls.isEmpty)
    }

    @Test func restoreLeavesARunningTunnelAlone() async throws {
        let service = MockVPNService.demo()
        service.step = .zero
        let defaults = freshDefaults()
        try await connectedThenQuit(service, defaults)
        service.connectCalls.removeAll()
        // Quitting the app left the tunnel up.
        let second = await relaunch(service, defaults)
        #expect(await second.connectAtLaunch() == nil)
        #expect(service.connectCalls.isEmpty)
    }

    @Test func connectAlwaysConnectsTheSelectedProfile() async {
        let service = MockVPNService.demo()
        service.step = .zero
        let defaults = freshDefaults()
        let m = await relaunch(service, defaults)
        m.launchBehavior = .connect
        m.selectedProfileID = service.profiles[1].id
        // Lab has no saved password, so launch asks for it.
        #expect(await m.connectAtLaunch() == .needsLogin)
        m.selectedProfileID = service.profiles[0].id
        #expect(await m.connectAtLaunch() == .started)
    }

    @Test func dontConnectNeverConnects() async throws {
        let service = MockVPNService.demo()
        service.step = .zero
        let defaults = freshDefaults()
        try await connectedThenQuit(service, defaults)
        await service.disconnect()
        let m = await relaunch(service, defaults)
        m.launchBehavior = .dontConnect
        service.connectCalls.removeAll()
        #expect(await m.connectAtLaunch() == nil)
        #expect(service.connectCalls.isEmpty)
    }

    @Test func nothingHappensBeforeSetupIsDone() async {
        let service = MockVPNService.demo()
        service.setup = SetupStatus()
        let m = await relaunch(service, freshDefaults())
        m.launchBehavior = .connect
        #expect(await m.connectAtLaunch() == nil)
    }

    @Test func cancellingTheLoginCountsAsDisconnect() async {
        let service = MockVPNService.demo()
        let defaults = freshDefaults()
        let m = await relaunch(service, defaults)
        m.selectedProfileID = service.profiles[1].id
        #expect(await m.connect() == .needsLogin)
        await m.cancelLogin()
        #expect(m.wantedProfileID == nil)
    }
}
#endif

#if canImport(SwiftUI)
import Diagnostics

@MainActor
@Suite struct DiagnosticsTests {
    @Test func settingsReachTheServiceAndAreClamped() async {
        let service = MockVPNService.demo()
        let model = await makeModel(service)
        #expect(!model.diagnostics.enabled)
        await model.setDiagnostics(DiagnosticsSettings(enabled: true, windowMinutes: 45))
        #expect(service.diagnostics.enabled)
        #expect(service.diagnostics.windowMinutes == 30)
        #expect(model.diagnostics == service.diagnostics)
    }

    @Test func saveNowNeedsDiagnosticsModeAndATunnel() async throws {
        let service = MockVPNService.demo()
        service.step = .zero
        let model = await makeModel(service)
        #expect(!model.canSaveDiagnosticsNow)
        await model.setDiagnostics(DiagnosticsSettings(enabled: true))
        #expect(!model.canSaveDiagnosticsNow)
        model.selectedProfileID = service.profiles[0].id
        await model.connect()
        try await waitFor(model) { $0.isConnected }
        #expect(model.canSaveDiagnosticsNow)
        await model.saveDiagnosticsNow()
        for _ in 0..<100 where model.status.lastIncident == nil { try await Task.sleep(for: .milliseconds(10)) }
        let path = try #require(model.status.lastIncident)
        #expect(path.hasPrefix(DiagnosticsSettings.systemDirectory.path))
        #expect(model.diagnosticsLocation.path == path)
    }

    @Test func newIncidentNotifiesButOneFromBeforeLaunchDoesNot() async {
        let service = MockVPNService.demo()
        let notifier = RecordingNotifier()
        let model = AppModel(service: service, notifier: notifier, defaults: freshDefaults())
        let id = service.profiles[0].id
        // The first status arrives with an incident from an earlier run.
        model.apply(TunnelStatus(profileID: id, state: .connected(.https), lastIncident: "/old.json"))
        #expect(notifier.posted.isEmpty)
        model.apply(TunnelStatus(profileID: id, state: .connected(.https), lastIncident: "/new.json"))
        model.apply(TunnelStatus(profileID: id, state: .connected(.https), lastIncident: "/new.json"))
        #expect(notifier.posted == ["incident"])
    }

    @Test func locationIsTheFolderWithoutAnIncident() async {
        let model = await makeModel(MockVPNService(step: .zero))
        #expect(model.diagnosticsLocation == DiagnosticsSettings.systemDirectory)
    }
}
#endif
