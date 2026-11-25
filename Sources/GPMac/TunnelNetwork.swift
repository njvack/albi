#if os(macOS)
    import Foundation
    import GPCore

    /// The changes to the system's network that a tunnel needs and only root
    /// may make: the utun's addresses and MTU, routes, and DNS. `UtunHost`
    /// asks for them here and does everything else (packets, timing, name
    /// lookups) itself, so the session can run in an unprivileged process
    /// that hands these to the root helper (`HelperTunnelNetwork`), or in a
    /// root process that makes them itself (`LocalTunnelNetwork`, for
    /// `albi-cli --tun` and inside the helper).
    ///
    /// Called from one queue at a time.
    public protocol TunnelNetwork: AnyObject, Sendable {
        /// Sets the utun's addresses and MTU to `settings`'.
        func configure(_ settings: TunnelSettings) throws
        /// Makes routes and DNS match `settings`. `router` is the physical
        /// network's IPv4 router; `gateways` are IPv4 addresses that get host
        /// routes via it, so the tunnel's own connection stays outside.
        /// Returns a summary for the log.
        func install(
            _ settings: TunnelSettings, router: String?, gateways: [String], dnsMode: NetConfig.DNSMode
        ) throws -> String
        /// Re-points the gateway and excluded routes at a new router.
        func updateRouter(_ router: String?) throws
        /// Takes out the routes and DNS. The utun stays.
        func remove()
        /// Takes out everything and lets go of the utun. Once only.
        func close()
    }

    /// `TunnelNetwork` for a root process: the utun by name and `NetConfig`.
    public final class LocalTunnelNetwork: TunnelNetwork, @unchecked Sendable {
        public let interface: UtunInterface
        private let net: NetConfig
        /// What `configure` last set, so an address that changes replaces the
        /// old one and an unchanged IPv6 address isn't added twice.
        private var configured: TunnelSettings?

        public init(
            interface: UtunInterface, journal: URL = NetConfig.defaultJournal, log: @escaping @Sendable (String) -> Void
        ) {
            self.interface = interface
            net = NetConfig(journal: journal, log: log)
        }

        public func configure(_ s: TunnelSettings) throws {
            if let a = s.ipv4Address { try interface.setIPv4(a, previous: configured?.ipv4Address) }
            if let a = s.ipv6Address, a != configured?.ipv6Address {
                try interface.addIPv6(a, prefixLength: s.ipv6PrefixLength ?? 128)
            }
            try interface.setMTU(s.mtu)
            configured = s
        }

        public func install(
            _ s: TunnelSettings, router: String?, gateways: [String], dnsMode: NetConfig.DNSMode
        ) throws -> String {
            try net.apply(s, interface: interface.name, router: router, gateways: gateways, dnsMode: dnsMode)
            return net.summary
        }

        public func updateRouter(_ router: String?) throws { try net.updateRouter(router) }

        public func remove() { net.teardown() }

        public func close() { net.teardown() }
    }
#endif
