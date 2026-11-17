import Testing
#if os(macOS)
import Darwin
import Foundation
@testable import GPMac

@Suite struct RoutingSocketTests {
    @Test func netmasks() {
        #expect(Array(RoutingSocket.netmask(1, v6: false)[4..<8]) == [0x80, 0, 0, 0])
        #expect(Array(RoutingSocket.netmask(20, v6: false)[4..<8]) == [255, 255, 0xF0, 0])
        #expect(RoutingSocket.netmask(0, v6: false).count == MemoryLayout<sockaddr_in>.size)
        let m6 = RoutingSocket.netmask(65, v6: true)
        #expect(m6.count == MemoryLayout<sockaddr_in6>.size)
        #expect(Array(m6[8..<18]) == [255, 255, 255, 255, 255, 255, 255, 255, 0x80, 0])
    }

    @Test func gatewayRouteMessage() throws {
        let r = RouteSpec(destination: "203.0.113.0", prefixLength: 24, gateway: "192.168.1.1")
        let m = try RoutingSocket.message(RoutingSocket.rtmAdd, r)
        let hdr = MemoryLayout<rt_msghdr>.size
        // Header, then dst, gateway, netmask: 16 bytes each.
        #expect(m.count == hdr + 48)
        let h = m.withUnsafeBytes { $0.loadUnaligned(as: rt_msghdr.self) }
        #expect(Int(h.rtm_msglen) == m.count)
        #expect(h.rtm_version == 5)
        #expect(h.rtm_type == 1)
        #expect(h.rtm_addrs == 0x7)
        #expect(h.rtm_flags & 0x2 != 0) // RTF_GATEWAY
        #expect(Array(m[(hdr + 4)..<(hdr + 8)]) == [203, 0, 113, 0])
        #expect(Array(m[(hdr + 20)..<(hdr + 24)]) == [192, 168, 1, 1])
        #expect(Array(m[(hdr + 36)..<(hdr + 40)]) == [255, 255, 255, 0])
    }

    @Test func hostRouteHasNoNetmask() throws {
        let r = RouteSpec(destination: "198.51.100.7", prefixLength: 32, gateway: "192.168.1.1")
        let m = try RoutingSocket.message(RoutingSocket.rtmDelete, r)
        let h = m.withUnsafeBytes { $0.loadUnaligned(as: rt_msghdr.self) }
        #expect(h.rtm_addrs == 0x3)
        #expect(h.rtm_flags & 0x4 != 0) // RTF_HOST
        #expect(m.count == MemoryLayout<rt_msghdr>.size + 32)
    }

    @Test func interfaceRouteUsesLinkAddress() throws {
        let r = RouteSpec(destination: "10.99.0.0", prefixLength: 24, interface: "lo0")
        let m = try RoutingSocket.message(RoutingSocket.rtmAdd, r)
        let h = m.withUnsafeBytes { $0.loadUnaligned(as: rt_msghdr.self) }
        #expect(h.rtm_flags & 0x2 == 0)
        let gw = m[(MemoryLayout<rt_msghdr>.size + 16)...]
        #expect(gw[gw.startIndex + 1] == UInt8(AF_LINK))
        #expect(throws: SystemError.self) {
            try RoutingSocket.message(RoutingSocket.rtmAdd, RouteSpec(destination: "10.0.0.0", prefixLength: 8, interface: "nope0"))
        }
    }

    @Test func sweepWithoutJournalIsNoop() {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("albi-no-journal-\(UUID()).json")
        #expect(NetConfig.sweep(journal: url) { _ in }.isEmpty)
    }

    @Test func unreadableJournalIsRemoved() throws {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("albi-bad-journal-\(UUID()).json")
        try Data("not json".utf8).write(to: url)
        #expect(NetConfig.sweep(journal: url) { _ in }.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: url.path))
    }
}
#endif
