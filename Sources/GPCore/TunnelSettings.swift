/// The network settings a tunnel needs, as plain values. The macOS layer turns
/// this into one `NEPacketTunnelNetworkSettings`; keeping it here lets the
/// mapping from getconfig be tested on Linux.
public struct TunnelSettings: Equatable, Sendable {
    public struct IPv4Route: Equatable, Hashable, Sendable {
        public var address: String
        public var mask: String
        public var prefixLength: Int
        public static let `default` = IPv4Route(address: "0.0.0.0", mask: "0.0.0.0", prefixLength: 0)
    }

    public struct IPv6Route: Equatable, Hashable, Sendable {
        public var address: String
        public var prefixLength: Int
        public static let `default` = IPv6Route(address: "::", prefixLength: 0)
    }

    /// The gateway host, for NETunnelNetworkSettings.tunnelRemoteAddress.
    public var remoteAddress: String
    public var ipv4Address: String?
    public var ipv4Mask: String?
    public var ipv6Address: String?
    public var ipv6PrefixLength: Int?
    public var includedIPv4: [IPv4Route]
    public var excludedIPv4: [IPv4Route]
    public var includedIPv6: [IPv6Route]
    public var excludedIPv6: [IPv6Route]
    public var dnsServers: [String]
    public var searchDomains: [String]
    /// nil: the tunnel's DNS servers answer every query. Otherwise only
    /// queries for these domains go to them.
    public var matchDomains: [String]?
    public var mtu: Int
    /// Route entries from the gateway that could not be parsed.
    public var ignoredRoutes: [String]

    /// Whether all IPv4 traffic goes through the tunnel.
    public var isFullTunnel: Bool { includedIPv4.contains(.default) }

    /// MTU when getconfig gives none (gateways often send 0). The tunnel runs
    /// over TCP, so this mostly bounds packet size, not fragmentation.
    public static let defaultMTU = 1400

    /// Maps a getconfig answer to tunnel settings.
    ///
    /// - No IPv4 access routes, or one of 0.0.0.0/0: full tunnel, default route.
    /// - Split tunnel: only the access routes; DNS search domains become match
    ///   domains so other names resolve outside the tunnel. A split tunnel with
    ///   no search domains sends all DNS to the tunnel's servers.
    public init(config c: GatewayConfig, remoteAddress: String, mtu fallbackMTU: Int = TunnelSettings.defaultMTU) {
        self.remoteAddress = remoteAddress
        ipv4Address = c.ipv4
        ipv4Mask = c.ipv4 == nil ? nil : (c.netmask.flatMap { IPv4.parse($0) == nil ? nil : $0 } ?? "255.255.255.255")
        ipv6Address = c.ipv6.map { a in a.split(separator: "/").first.map(String.init) ?? a }
        ipv6PrefixLength = c.ipv6.map { a in
            let parts = a.split(separator: "/")
            return parts.count == 2 ? Int(parts[1]) ?? 128 : 128
        }
        var ignored: [String] = []
        var inc4: [IPv4Route] = [], exc4: [IPv4Route] = []
        var inc6: [IPv6Route] = [], exc6: [IPv6Route] = []
        for (list, isExclude) in [(c.accessRoutes, false), (c.excludeRoutes, true)] {
            for r in list {
                if r.contains(":") {
                    guard let route = TunnelSettings.parseIPv6Route(r) else { ignored.append(r); continue }
                    if isExclude { exc6.append(route) } else { inc6.append(route) }
                } else {
                    guard let route = TunnelSettings.parseIPv4Route(r) else { ignored.append(r); continue }
                    if isExclude { exc4.append(route) } else { inc4.append(route) }
                }
            }
        }
        let full = inc4.isEmpty || inc4.contains(.default)
        if full { inc4 = [.default] }
        if c.ipv6 != nil && (inc6.isEmpty || inc6.contains(.default)) && full {
            inc6 = [.default]
        }
        if c.ipv6 == nil {
            inc6 = []
            exc6 = []
        }
        includedIPv4 = TunnelSettings.unique(inc4)
        excludedIPv4 = TunnelSettings.unique(exc4)
        includedIPv6 = TunnelSettings.unique(inc6)
        excludedIPv6 = TunnelSettings.unique(exc6)
        ignoredRoutes = ignored
        dnsServers = c.dns
        searchDomains = c.dnsSuffixes
        matchDomains = full || c.dnsSuffixes.isEmpty ? nil : c.dnsSuffixes
        mtu = c.mtu ?? fallbackMTU
    }

    static func unique<T: Hashable>(_ xs: [T]) -> [T] {
        var seen = Set<T>()
        return xs.filter { seen.insert($0).inserted }
    }

    /// Parses `a.b.c.d`, `a.b.c.d/len` or `a.b.c.d/m.m.m.m`; clears host bits.
    static func parseIPv4Route(_ s: String) -> IPv4Route? {
        let parts = s.trimmingXMLWhitespace().split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2, let addr = IPv4.parse(String(parts[0])) else { return nil }
        var len = 32
        if parts.count == 2 {
            if let n = Int(parts[1]), (0...32).contains(n) {
                len = n
            } else if let m = IPv4.parse(String(parts[1])), let n = IPv4.prefixLength(mask: m) {
                len = n
            } else {
                return nil
            }
        }
        let mask: UInt32 = len == 0 ? 0 : ~UInt32(0) << (32 - len)
        return IPv4Route(address: IPv4.format(addr & mask), mask: IPv4.format(mask), prefixLength: len)
    }

    /// Parses `addr` or `addr/len`. The address is passed through as given.
    static func parseIPv6Route(_ s: String) -> IPv6Route? {
        let parts = s.trimmingXMLWhitespace().split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2, !parts[0].isEmpty,
              parts[0].allSatisfy({ $0.isHexDigit || $0 == ":" || $0 == "." }) else { return nil }
        var len = 128
        if parts.count == 2 {
            guard let n = Int(parts[1]), (0...128).contains(n) else { return nil }
            len = n
        }
        return IPv6Route(address: String(parts[0]), prefixLength: len)
    }
}

enum IPv4 {
    static func parse(_ s: String) -> UInt32? {
        let p = s.split(separator: ".", omittingEmptySubsequences: false)
        guard p.count == 4 else { return nil }
        var v: UInt32 = 0
        for o in p {
            guard !o.isEmpty, o.count <= 3, o.allSatisfy(\.isASCII), let n = UInt32(o), n <= 255 else { return nil }
            v = v << 8 | n
        }
        return v
    }

    static func format(_ v: UInt32) -> String {
        "\(v >> 24).\(v >> 16 & 0xff).\(v >> 8 & 0xff).\(v & 0xff)"
    }

    static func prefixLength(mask: UInt32) -> Int? {
        let n = mask.nonzeroBitCount
        let expect: UInt32 = n == 0 ? 0 : ~UInt32(0) << (32 - n)
        return mask == expect ? n : nil
    }
}
