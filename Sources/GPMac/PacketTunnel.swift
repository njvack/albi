#if canImport(NetworkExtension)
import Foundation
import GPCore
import NetworkExtension

extension TunnelSettings {
    /// The one settings object macOS applies, and removes when the tunnel stops.
    public func networkSettings() -> NEPacketTunnelNetworkSettings {
        let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        if let a = ipv4Address {
            let v4 = NEIPv4Settings(addresses: [a], subnetMasks: [ipv4Mask ?? "255.255.255.255"])
            v4.includedRoutes = includedIPv4.map(Self.route)
            v4.excludedRoutes = excludedIPv4.map(Self.route)
            s.ipv4Settings = v4
        }
        if let a = ipv6Address {
            let v6 = NEIPv6Settings(addresses: [a], networkPrefixLengths: [NSNumber(value: ipv6PrefixLength ?? 128)])
            v6.includedRoutes = includedIPv6.map(Self.route)
            v6.excludedRoutes = excludedIPv6.map(Self.route)
            s.ipv6Settings = v6
        }
        if !dnsServers.isEmpty {
            let d = NEDNSSettings(servers: dnsServers)
            d.searchDomains = searchDomains.isEmpty ? nil : searchDomains
            d.matchDomains = matchDomains
            s.dnsSettings = d
        }
        s.mtu = NSNumber(value: mtu)
        return s
    }

    static func route(_ r: IPv4Route) -> NEIPv4Route {
        r == .default ? NEIPv4Route.default() : NEIPv4Route(destinationAddress: r.address, subnetMask: r.mask)
    }

    static func route(_ r: IPv6Route) -> NEIPv6Route {
        r == .default ? NEIPv6Route.default() :
            NEIPv6Route(destinationAddress: r.address, networkPrefixLength: NSNumber(value: r.prefixLength))
    }
}

/// The `TunnelHost` for a packet tunnel provider: settings go to
/// `setTunnelNetworkSettings`, packets to and from `packetFlow`.
public final class PacketFlowHost: TunnelHost, @unchecked Sendable {
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

    private weak var provider: NEPacketTunnelProvider?
    private let hooks: Hooks

    public init(provider: NEPacketTunnelProvider, hooks: Hooks) {
        self.provider = provider
        self.hooks = hooks
    }

    public func apply(_ settings: TunnelSettings) async throws {
        guard let provider else { return }
        try await provider.setTunnelNetworkSettings(settings.networkSettings())
    }

    public func deliver(_ packets: [[UInt8]]) {
        guard let flow = provider?.packetFlow else { return }
        let protos = packets.map { p in NSNumber(value: (p.first ?? 0) >> 4 == 6 ? AF_INET6 : AF_INET) }
        flow.writePackets(packets.map { Data($0) }, withProtocols: protos)
    }

    public func stateChanged(_ state: SessionState) { hooks.stateChanged(state) }
    public func hipReport(_ c: HIPContext) async throws -> String? { try await hooks.hipReport(c) }
    public func reauthenticate() async throws -> AuthCookie { try await hooks.reauthenticate() }
    public func saveCookie(_ c: AuthCookie?) { hooks.saveCookie(c) }
    public func log(_ m: String) { hooks.log(m) }

    /// Reads packets from the OS and sends them through `runner`, in order,
    /// until the provider goes away.
    public func pumpPackets(to runner: SessionRunner) {
        guard let packetFlow = provider?.packetFlow else { return }
        nonisolated(unsafe) let flow = packetFlow
        let (stream, cont) = AsyncStream<[[UInt8]]>.makeStream()
        @Sendable func readNext() {
            flow.readPackets { packets, _ in
                cont.yield(packets.map { [UInt8]($0) })
                readNext()
            }
        }
        readNext()
        Task {
            for await batch in stream { await runner.send(packets: batch) }
        }
    }
}
#endif
