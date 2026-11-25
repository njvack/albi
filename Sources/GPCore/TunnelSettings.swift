/// The network settings a tunnel needs, as plain values. The macOS layer turns
/// this into one `NEPacketTunnelNetworkSettings`; keeping it here lets the
/// mapping from getconfig be tested on Linux.
public struct TunnelSettings: Equatable, Sendable {
    public struct IPv4Route: Equatable, Hashable, Sendable {
        public var address: String
        public var mask: String
        public var prefixLength: Int
        public static let `default` = IPv4Route(address: "0.0.0.0", mask: "0.0.0.0", prefixLength: 0)

        public init(address: String, mask: String, prefixLength: Int) {
            self.address = address
            self.mask = mask
            self.prefixLength = prefixLength
        }
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
    /// What the gateway sent that was malformed or unsafe to apply, and was
    /// left out: route entries as given, other values as `name value`.
    public var ignored: [String]

    /// Whether all IPv4 traffic goes through the tunnel.
    public var isFullTunnel: Bool { includedIPv4.contains(.default) }

    /// MTU when getconfig gives none (gateways often send 0): openconnect's
    /// figure for the HTTPS tunnel, 1406 minus TCP, IP and TLS record
    /// headers. With 1400, a PAN-OS 11.1 gateway that sends 0 stopped
    /// answering on the tunnel, keepalives included, once real traffic flowed.
    public static let defaultMTU = 1361

    /// Maps a getconfig answer to tunnel settings.
    ///
    /// - No IPv4 access routes, or one of 0.0.0.0/0: full tunnel, default route.
    /// - Split tunnel: only the access routes; DNS search domains become match
    ///   domains so other names resolve outside the tunnel. A split tunnel with
    ///   no search domains sends all DNS to the tunnel's servers.
    ///
    /// Everything here comes from the gateway and is applied by a root
    /// process, so each value is checked first; see `Limits`. What fails is
    /// left out and listed in `ignored`.
    public init(config c: GatewayConfig, remoteAddress: String, mtu fallbackMTU: Int = TunnelSettings.defaultMTU) {
        self.remoteAddress = remoteAddress
        var ignored: [String] = []

        ipv4Address = c.ipv4.flatMap { a in
            guard let v = IPv4.parse(a), IPv4.isUsableHost(v) else {
                ignored.append("ip-address \(a)")
                return nil
            }
            return IPv4.format(v)
        }
        ipv4Mask =
            ipv4Address == nil ? nil : (c.netmask.flatMap { IPv4.parse($0) == nil ? nil : $0 } ?? "255.255.255.255")
        var v6: (address: String, prefix: Int)?
        if let a = c.ipv6 {
            let parts = a.split(separator: "/", omittingEmptySubsequences: false)
            let prefix = parts.count == 2 ? Int(parts[1]) : (parts.count == 1 ? 128 : nil)
            if parts.count <= 2, let bytes = IPv6.parse(String(parts[0])), IPv6.isUsableHost(bytes),
                let prefix, (1...128).contains(prefix)
            {
                v6 = (String(parts[0]), prefix)
            } else {
                ignored.append("ip-address-v6 \(a)")
            }
        }
        ipv6Address = v6?.address
        ipv6PrefixLength = v6?.prefix

        var inc4: [IPv4Route] = [], exc4: [IPv4Route] = []
        var inc6: [IPv6Route] = [], exc6: [IPv6Route] = []
        var count = 0
        for (list, isExclude) in [(c.accessRoutes, false), (c.excludeRoutes, true)] {
            for r in list {
                count += 1
                guard count <= Limits.routes else {
                    ignored.append(r)
                    continue
                }
                if r.contains(":") {
                    guard let route = TunnelSettings.parseIPv6Route(r), route.isAllowed(excluded: isExclude) else {
                        ignored.append(r)
                        continue
                    }
                    if isExclude { exc6.append(route) } else { inc6.append(route) }
                } else {
                    guard let route = TunnelSettings.parseIPv4Route(r), route.isAllowed(excluded: isExclude) else {
                        ignored.append(r)
                        continue
                    }
                    if isExclude { exc4.append(route) } else { inc4.append(route) }
                }
            }
        }
        let full = inc4.isEmpty || inc4.contains(.default)
        if full { inc4 = [.default] }
        if ipv6Address != nil && (inc6.isEmpty || inc6.contains(.default)) && full {
            inc6 = [.default]
        }
        if ipv6Address == nil {
            inc6 = []
            exc6 = []
        }
        includedIPv4 = TunnelSettings.unique(inc4)
        excludedIPv4 = TunnelSettings.unique(exc4)
        includedIPv6 = TunnelSettings.unique(inc6)
        excludedIPv6 = TunnelSettings.unique(exc6)

        var servers: [String] = []
        for d in c.dns {
            if servers.count < Limits.dnsServers, let a = TunnelSettings.dnsServer(d) {
                if !servers.contains(a) { servers.append(a) }
            } else {
                ignored.append("dns \(d)")
            }
        }
        dnsServers = servers
        var domains: [String] = []
        for d in c.dnsSuffixes {
            if domains.count < Limits.dnsDomains, let n = TunnelSettings.domainName(d) {
                if !domains.contains(n) { domains.append(n) }
            } else {
                ignored.append("dns-suffix \(d)")
            }
        }
        searchDomains = domains
        matchDomains = full || domains.isEmpty ? nil : domains

        if let m = c.mtu, !Limits.mtu.contains(m) {
            ignored.append("mtu \(m)")
            mtu = fallbackMTU
        } else {
            mtu = c.mtu ?? fallbackMTU
        }
        self.ignored = ignored
    }

    /// Bounds on what a gateway may push.
    public enum Limits {
        /// IPv4's minimum datagram size up to jumbo frames.
        public static let mtu = 576...9000
        /// Access and exclude routes together, IPv4 and IPv6.
        public static let routes = 4096
        public static let dnsServers = 8
        public static let dnsDomains = 64
    }

    /// An IPv4 or IPv6 literal that can serve DNS: not unspecified, loopback
    /// (that would hand the tunnel's DNS to a local process) or multicast.
    static func dnsServer(_ s: String) -> String? {
        let t = s.trimmingXMLWhitespace()
        if let v = IPv4.parse(t) { return IPv4.isUsableHost(v) ? IPv4.format(v) : nil }
        if let b = IPv6.parse(t) { return IPv6.isUsableHost(b) ? t : nil }
        return nil
    }

    /// A DNS name as a search or match domain: LDH labels (plus `_`) of 1 to
    /// 63 bytes, 253 in all, lowercased, without a trailing dot. nil for
    /// anything else, including the empty name, which as a match domain
    /// would send every query to the tunnel.
    static func domainName(_ s: String) -> String? {
        var t = s.trimmingXMLWhitespace().lowercased()
        if t.hasSuffix(".") { t.removeLast() }
        guard !t.isEmpty, t.utf8.count <= 253 else { return nil }
        for label in t.split(separator: ".", omittingEmptySubsequences: false) {
            guard (1...63).contains(label.utf8.count),
                label.utf8.allSatisfy({ b in
                    (b >= 0x61 && b <= 0x7a) || (b >= 0x30 && b <= 0x39) || b == 0x2d || b == 0x5f
                })
            else { return nil }
        }
        return t
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

    /// Parses `addr` or `addr/len`; clears host bits.
    static func parseIPv6Route(_ s: String) -> IPv6Route? {
        let parts = s.trimmingXMLWhitespace().split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2, var bytes = IPv6.parse(String(parts[0])) else { return nil }
        var len = 128
        if parts.count == 2 {
            guard let n = Int(parts[1]), (0...128).contains(n) else { return nil }
            len = n
        }
        for i in 0..<16 {
            let bits = max(0, min(8, len - i * 8))
            bytes[i] &= bits == 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - bits))
        }
        return IPv6Route(address: IPv6.format(bytes), prefixLength: len)
    }
}

extension TunnelSettings.IPv4Route {
    /// Whether a gateway may push this route. Never loopback, multicast,
    /// link-local, 0.0.0.0/8 or the limited broadcast address; and never an
    /// exclude of everything, which only a misconfigured or hostile gateway
    /// would send.
    func isAllowed(excluded: Bool) -> Bool {
        if self == .default { return !excluded }
        guard let a = IPv4.parse(address) else { return false }
        if prefixLength == 0 { return false }
        let reserved: [(UInt32, Int)] = [
            (0x0000_0000, 8), (0x7F00_0000, 8), (0xA9FE_0000, 16), (0xE000_0000, 3),
        ]
        return !reserved.contains { net, len in IPv4.overlaps(a, prefixLength, net, len) }
    }
}

extension TunnelSettings.IPv6Route {
    /// As for IPv4: never unspecified, loopback, link-local or multicast, and
    /// never an exclude of everything.
    func isAllowed(excluded: Bool) -> Bool {
        if self == .default { return !excluded }
        guard let a = IPv6.parse(address), prefixLength > 0 else { return false }
        if prefixLength == 128 && !IPv6.isUsableHost(a) { return false }
        // fe80::/10 and ff00::/8 (which covers ff00..ffff, so /8 from 0xff).
        let linkLocal = a[0] == 0xFE && a[1] & 0xC0 == 0x80
        let multicast = a[0] == 0xFF
        let coversSpecial = prefixLength < 8
        return !linkLocal && !multicast && !coversSpecial
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

    static func mask(_ len: Int) -> UInt32 { len <= 0 ? 0 : ~UInt32(0) << (32 - min(32, len)) }

    /// Whether two prefixes share any address.
    static func overlaps(_ a: UInt32, _ alen: Int, _ b: UInt32, _ blen: Int) -> Bool {
        let m = mask(min(alen, blen))
        return a & m == b & m
    }

    /// An address a host can have: not in 0.0.0.0/8, loopback, link-local,
    /// multicast or reserved (224.0.0.0/3, which takes in 255.255.255.255).
    static func isUsableHost(_ a: UInt32) -> Bool {
        let top = a >> 24
        return top != 0 && top != 127 && top < 224 && a >> 16 != 0xA9FE
    }
}

/// IPv6 text forms, without Foundation or inet_pton so it tests on Linux.
enum IPv6 {
    /// RFC 4291 text: eight groups, `::` once, an IPv4 dotted quad last.
    static func parse(_ s: String) -> [UInt8]? {
        guard !s.isEmpty, s.utf8.count <= 45 else { return nil }
        var head: [UInt16] = [], tail: [UInt16] = []
        var sawGap = false
        let pieces = s.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        var i = 0
        // A leading or trailing "::" shows up as two empty pieces.
        if pieces.first == "" {
            guard pieces.count > 2, pieces[1] == "" else { return nil }
            i = 1
        }
        if pieces.count >= 2, pieces.last == "", pieces[pieces.count - 2] != "" { return nil }
        while i < pieces.count {
            let p = pieces[i]
            let isLast = i == pieces.count - 1
            if p.isEmpty {
                if sawGap {
                    // Only the second empty piece of a trailing "::" may follow.
                    guard isLast, i > 0, pieces[i - 1].isEmpty else { return nil }
                } else {
                    sawGap = true
                }
            } else if isLast, p.contains(".") {
                guard let v = IPv4.parse(p) else { return nil }
                let groups = [UInt16(v >> 16), UInt16(v & 0xFFFF)]
                if sawGap { tail += groups } else { head += groups }
            } else {
                guard p.utf8.count <= 4, let g = UInt16(p, radix: 16), p.allSatisfy(\.isHexDigit) else { return nil }
                if sawGap { tail.append(g) } else { head.append(g) }
            }
            i += 1
        }
        let n = head.count + tail.count
        guard sawGap ? n <= 7 : n == 8 else { return nil }
        let groups = head + [UInt16](repeating: 0, count: 8 - n) + tail
        return groups.flatMap { [UInt8($0 >> 8), UInt8($0 & 0xFF)] }
    }

    /// Lowercase groups with the longest run of zero groups (two or more) as `::`.
    static func format(_ b: [UInt8]) -> String {
        let g = stride(from: 0, to: 16, by: 2).map { UInt16(b[$0]) << 8 | UInt16(b[$0 + 1]) }
        var best = (start: -1, len: 0), cur = (start: -1, len: 0)
        for (i, v) in g.enumerated() {
            if v == 0 {
                cur = cur.start < 0 ? (i, 1) : (cur.start, cur.len + 1)
                if cur.len > best.len { best = cur }
            } else {
                cur = (-1, 0)
            }
        }
        let hex = g.map { String($0, radix: 16) }
        guard best.len >= 2 else { return hex.joined(separator: ":") }
        let left = hex[..<best.start].joined(separator: ":")
        let right = hex[(best.start + best.len)...].joined(separator: ":")
        return left + "::" + right
    }

    /// Not unspecified, loopback, link-local (fe80::/10) or multicast (ff00::/8).
    static func isUsableHost(_ b: [UInt8]) -> Bool {
        if b.allSatisfy({ $0 == 0 }) { return false }
        if b[0..<15].allSatisfy({ $0 == 0 }) && b[15] == 1 { return false }
        if b[0] == 0xFF { return false }
        if b[0] == 0xFE && b[1] & 0xC0 == 0x80 { return false }
        return true
    }
}
