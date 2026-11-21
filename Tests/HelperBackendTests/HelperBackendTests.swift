#if canImport(SwiftUI)
import AlbiApp
import Foundation
import GPMac
import Testing
@testable import HelperBackend

@MainActor
@Suite struct HelperMappingTests {
    @Test func helperStatusMapsOntoTunnelStatus() {
        let id = UUID()
        var h = HelperStatus(profileID: id, state: .connecting(phase: "hip"))
        #expect(HelperVPNService.tunnelStatus(h).state == .connecting(.hip))
        h.state = .connected
        h.routes = ["10.0.0.0/8"]
        h.hipRequested = true
        let t = HelperVPNService.tunnelStatus(h)
        #expect(t.state == .connected(.https))
        #expect(t.profileID == id)
        #expect(t.routes == ["10.0.0.0/8"])
        #expect(t.hip?.requested == true)
        h.state = .needsLogin(reason: "x")
        h.hipRequested = false
        #expect(HelperVPNService.tunnelStatus(h).state == .needsLogin(reason: "x"))
        #expect(HelperVPNService.tunnelStatus(h).hip == nil)
    }
}

@Suite struct HelperConnectionTests {
    /// With no helper registered, launchd has no such service and XPC
    /// invalidates the connection from its own queue. That used to trap on
    /// the main-actor check and kill the app at launch.
    @MainActor @Test func noHelperFailsTheCallInsteadOfCrashing() async {
        let service = HelperVPNService()
        await #expect(throws: (any Error).self) { try await service.call(.hello, timeout: 2) }
        // Let the invalidation handler and the retry it schedules run too.
        try? await Task.sleep(for: .seconds(2))
        #expect(await service.currentStatus().state == .disconnected)
    }
}
#endif
