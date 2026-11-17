#if os(macOS)
import Darwin
import Foundation
import GPCore

/// The `TunnelHost` for a root process: packets over a utun, routes and DNS
/// through `NetConfig`. It takes the place `PacketFlowHost` has in the
/// extension.
///
/// Settings arrive before the tunnel is open (getconfig comes first), but
/// routes and DNS go in only once the session is connected. A gateway socket
/// pinned to the physical interface can briefly fail right after a new
/// network service appears, so the tunnel's own connection is made first.
/// Routes stay through reconnects, so a full tunnel doesn't leak while it's
/// down, and come out when the session stops or needs a login.
public final class UtunHost: TunnelHost, @unchecked Sendable {
    public struct Hooks: Sendable {
        public var hipReport: @Sendable (HIPContext) async throws -> String?
        public var reauthenticate: @Sendable () async throws -> AuthCookie
        public var saveCookie: @Sendable (AuthCookie?) -> Void
        public var stateChanged: @Sendable (SessionState) -> Void
        public var log: @Sendable (String) -> Void

        public init(hipReport: @escaping @Sendable (HIPContext) async throws -> String?,
                    reauthenticate: @escaping @Sendable () async throws -> AuthCookie,
                    saveCookie: @escaping @Sendable (AuthCookie?) -> Void,
                    stateChanged: @escaping @Sendable (SessionState) -> Void,
                    log: @escaping @Sendable (String) -> Void) {
            self.hipReport = hipReport
            self.reauthenticate = reauthenticate
            self.saveCookie = saveCookie
            self.stateChanged = stateChanged
            self.log = log
        }
    }

    public let device: UtunDevice
    public let dnsMode: NetConfig.DNSMode
    private let net: NetConfig
    private let hooks: Hooks
    private let router: @Sendable () -> String?
    private let gatewayHosts: [String]
    private let queue = DispatchQueue(label: "albi.utun-host")
    private let readQueue = DispatchQueue(label: "albi.utun-read")
    // Touched only on `queue`.
    private var settings: TunnelSettings?
    private var applied: TunnelSettings?
    private var shutDown = false

    /// Opens a utun. `router` gives the physical network's IPv4 router, for
    /// excluded routes and the host routes to the gateway. `gatewayHosts`
    /// are resolved for those host routes, along with getconfig's gw-address.
    public init(dnsMode: NetConfig.DNSMode = .split, journal: URL = NetConfig.defaultJournal,
                gatewayHosts: [String] = [],
                router: @escaping @Sendable () -> String?, hooks: Hooks) throws {
        device = try UtunDevice()
        self.dnsMode = dnsMode
        self.gatewayHosts = gatewayHosts
        self.router = router
        self.hooks = hooks
        net = NetConfig(journal: journal, log: hooks.log)
    }

    public func apply(_ s: TunnelSettings) async throws {
        try queue.sync {
            guard !shutDown else { return }
            if let a = s.ipv4Address { try device.setIPv4(a, previous: settings?.ipv4Address) }
            if let a = s.ipv6Address, a != settings?.ipv6Address {
                try device.addIPv6(a, prefixLength: s.ipv6PrefixLength ?? 128)
            }
            try device.setMTU(s.mtu)
            settings = s
        }
        hooks.log("tun \(device.name) ipv4=\(s.ipv4Address ?? "-") ipv6=\(s.ipv6Address ?? "-") mtu=\(s.mtu)")
    }

    public func deliver(_ packets: [[UInt8]]) { device.write(packets) }

    public func stateChanged(_ state: SessionState) {
        switch state {
        case .connected:
            queue.async { self.install() }
        case .stopped, .needsLogin:
            queue.async { self.removeNetwork() }
        default:
            break
        }
        hooks.stateChanged(state)
    }

    public func hipReport(_ c: HIPContext) async throws -> String? { try await hooks.hipReport(c) }
    public func reauthenticate() async throws -> AuthCookie { try await hooks.reauthenticate() }
    public func saveCookie(_ c: AuthCookie?) { hooks.saveCookie(c) }
    public func log(_ m: String) { hooks.log(m) }

    /// Sends what the system routes into the utun through `runner`, in order.
    public func pumpPackets(to runner: SessionRunner) {
        let (stream, cont) = AsyncStream<[[UInt8]]>.makeStream()
        device.startReading(on: readQueue) { cont.yield($0) }
        Task {
            for await batch in stream { await runner.send(packets: batch) }
        }
    }

    /// The physical network changed: excluded routes follow the new router.
    public func pathChanged() {
        queue.async {
            guard self.applied != nil, !self.shutDown else { return }
            do { try self.net.updateRouter(self.router()) } catch { self.hooks.log("updating excluded routes: \(error)") }
        }
    }

    /// Removes routes and DNS and closes the utun. Call before exiting.
    public func shutdown() {
        queue.sync {
            guard !shutDown else { return }
            shutDown = true
            removeNetwork()
            device.close()
        }
    }

    private func install() {
        guard !shutDown, let s = settings, s != applied else { return }
        // Resolved now, while DNS and routes are still the physical network's.
        let gateways = Self.ipv4Addresses(of: [s.remoteAddress] + gatewayHosts)
        do {
            try net.apply(s, interface: device.name, router: router(), gateways: gateways, dnsMode: dnsMode)
            applied = s
            hooks.log("network applied: \(net.summary)")
        } catch {
            hooks.log("applying network settings failed: \(error)")
        }
    }

    /// The IPv4 addresses `hosts` resolve to, leaving out loopback (never
    /// captured by tunnel routes).
    static func ipv4Addresses(of hosts: [String]) -> [String] {
        var out: [String] = []
        for h in hosts where !h.isEmpty {
            var hints = addrinfo()
            hints.ai_family = AF_INET
            hints.ai_socktype = SOCK_STREAM
            var res: UnsafeMutablePointer<addrinfo>?
            guard getaddrinfo(h, nil, &hints, &res) == 0, let first = res else { continue }
            defer { freeaddrinfo(res) }
            var p: UnsafeMutablePointer<addrinfo>? = first
            while let ai = p {
                p = ai.pointee.ai_next
                guard let sa = ai.pointee.ai_addr else { continue }
                var sin = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                guard inet_ntop(AF_INET, &sin.sin_addr, &buf, socklen_t(buf.count)) != nil else { continue }
                let a = String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
                if !a.hasPrefix("127."), !out.contains(a) { out.append(a) }
            }
        }
        return out
    }

    private func removeNetwork() {
        let had = applied != nil
        net.teardown()
        applied = nil
        if had { hooks.log("network removed") }
    }
}
#endif
