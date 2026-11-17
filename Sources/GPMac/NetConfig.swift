#if os(macOS)
import Darwin
import Foundation
import GPCore
import SystemConfiguration

/// One route, as the routing socket takes it and as the journal stores it.
public struct RouteSpec: Codable, Hashable, Sendable, CustomStringConvertible {
    public var destination: String
    public var prefixLength: Int
    /// A router's address; nil for a route straight onto `interface`.
    public var gateway: String?
    public var interface: String?

    public init(destination: String, prefixLength: Int, gateway: String? = nil, interface: String? = nil) {
        self.destination = destination
        self.prefixLength = prefixLength
        self.gateway = gateway
        self.interface = interface
    }

    public var isIPv6: Bool { destination.contains(":") }

    public var description: String {
        "\(destination)/\(prefixLength) via \(gateway ?? interface ?? "?")"
    }
}

/// The routing table and DNS, changed the way the root helper's cleanup rules
/// need:
///
/// - Routes into the tunnel go on the utun, so the kernel purges them when
///   the utun goes away, however the process ends.
/// - DNS is published as temporary dynamic-store keys, which configd drops
///   when this process's store session ends.
/// - Excluded routes go via the physical router and would outlive the
///   process, so each is written to a journal before it's added. `sweep`
///   removes whatever a journal still lists, at the next startup.
///
/// The default route and the user's own DNS settings are never touched. Not
/// thread-safe: call from one queue.
public final class NetConfig: @unchecked Sendable {
    public enum DNSMode: String, Sendable {
        /// Only the gateway's domains go to its DNS servers (supplemental
        /// match domains). Coexists with other VPNs' DNS, such as Tailscale's.
        case split
        /// The tunnel's DNS servers become the default resolver
        /// (OverridePrimary). Another VPN's DNS may still win.
        case full
    }

    public static let defaultJournal = URL(fileURLWithPath: "/Library/Application Support/Albi/helper-journal.json")

    struct Journal: Codable {
        var routes: [RouteSpec]
    }

    public let journal: URL
    private let log: @Sendable (String) -> Void
    private var store: SCDynamicStore?
    public let serviceID = "albi-\(UUID().uuidString)"
    private var tunnelRoutes: Set<RouteSpec> = []
    private var excluded: Set<RouteSpec> = []
    private var excludedWanted: [RouteSpec] = []
    private var dnsKeys: [String] = []

    public init(journal: URL = NetConfig.defaultJournal, log: @escaping @Sendable (String) -> Void) {
        self.journal = journal
        self.log = log
    }

    // MARK: Apply

    /// Makes routes and DNS match `settings` for the tunnel on `interface`.
    /// Call again with new settings; only the difference changes.
    public func apply(_ settings: TunnelSettings, interface: String, router: String?, dnsMode: DNSMode) throws {
        // Into the tunnel. A default route becomes two halves so the real
        // default route stays as it is.
        var want = Set<RouteSpec>()
        for r in settings.includedIPv4 {
            if r == .default {
                want.insert(RouteSpec(destination: "0.0.0.0", prefixLength: 1, interface: interface))
                want.insert(RouteSpec(destination: "128.0.0.0", prefixLength: 1, interface: interface))
            } else {
                want.insert(RouteSpec(destination: r.address, prefixLength: r.prefixLength, interface: interface))
            }
        }
        for r in settings.includedIPv6 {
            if r == .default {
                want.insert(RouteSpec(destination: "::", prefixLength: 1, interface: interface))
                want.insert(RouteSpec(destination: "8000::", prefixLength: 1, interface: interface))
            } else {
                want.insert(RouteSpec(destination: r.address, prefixLength: r.prefixLength, interface: interface))
            }
        }
        for r in tunnelRoutes.subtracting(want) {
            try? RoutingSocket.delete(r)
        }
        for r in want.subtracting(tunnelRoutes) {
            try RoutingSocket.add(r)
        }
        tunnelRoutes = want

        excludedWanted = settings.excludedIPv4.map { RouteSpec(destination: $0.address, prefixLength: $0.prefixLength) }
        if !settings.excludedIPv6.isEmpty {
            log("IPv6 excluded routes not supported yet; ignored: \(settings.excludedIPv6.map { "\($0.address)/\($0.prefixLength)" })")
        }
        try routeExcluded(via: router)
        try publishDNS(settings, interface: interface, mode: dnsMode)
    }

    /// Re-points excluded routes at a new router after a network change.
    public func updateRouter(_ router: String?) throws {
        try routeExcluded(via: router)
    }

    public var summary: String {
        let inc = tunnelRoutes.map { "\($0.destination)/\($0.prefixLength)" }.sorted().joined(separator: ",")
        let exc = excluded.map(\.description).sorted().joined(separator: ",")
        return "routes=\(inc) excluded=\(exc.isEmpty ? "-" : exc) dns-service=\(dnsKeys.isEmpty ? "-" : serviceID)"
    }

    private func routeExcluded(via router: String?) throws {
        let want = Set(router.map { r in excludedWanted.map { RouteSpec(destination: $0.destination, prefixLength: $0.prefixLength, gateway: r) } } ?? [])
        if router == nil && !excludedWanted.isEmpty { log("no IPv4 router; excluded routes left out for now") }
        let remove = excluded.subtracting(want)
        let add = want.subtracting(excluded)
        guard !remove.isEmpty || !add.isEmpty else { return }
        // Journal first: a route we might have added must be in the journal
        // before the kernel has it.
        try writeJournal(excluded.union(add))
        for r in remove {
            do { try RoutingSocket.delete(r) } catch { log("removing excluded route \(r): \(error)") }
        }
        excluded.subtract(remove)
        for r in add {
            do {
                try RoutingSocket.add(r)
                excluded.insert(r)
            } catch {
                log("adding excluded route \(r): \(error)")
            }
        }
        try writeJournal(excluded)
    }

    // MARK: DNS

    private func publishDNS(_ s: TunnelSettings, interface: String, mode: DNSMode) throws {
        removeDNS()
        guard !s.dnsServers.isEmpty else { return }
        guard let v4 = s.ipv4Address else {
            log("no IPv4 address; tunnel DNS not published")
            return
        }
        if store == nil {
            store = SCDynamicStoreCreate(nil, "albi" as CFString, nil, nil)
        }
        guard let store else { throw SystemError("SCDynamicStoreCreate", EIO) }

        let domains = s.matchDomains ?? s.searchDomains
        let override = mode == .full || domains.isEmpty
        if mode == .split && domains.isEmpty { log("gateway sent no DNS domains; using its DNS for everything") }
        var ipv4: [String: Any] = [
            "Addresses": [v4],
            "SubnetMasks": ["255.255.255.255"],
            "DestAddresses": [v4],
            "InterfaceName": interface,
        ]
        var dns: [String: Any] = ["ServerAddresses": s.dnsServers]
        if override {
            // No Router: with one, configd also points the default route at
            // the utun, and the default route is never ours to change.
            ipv4["OverridePrimary"] = 1
            if !s.searchDomains.isEmpty { dns["SearchDomains"] = s.searchDomains }
        } else {
            dns["SupplementalMatchDomains"] = domains
        }
        for (suffix, value) in [("IPv4", ipv4), ("DNS", dns)] {
            let key = "State:/Network/Service/\(serviceID)/\(suffix)"
            guard SCDynamicStoreAddTemporaryValue(store, key as CFString, value as NSDictionary) else {
                throw SystemError("SCDynamicStoreAddTemporaryValue \(key): \(String(cString: SCErrorString(SCError())))", EIO)
            }
            dnsKeys.append(key)
        }
    }

    private func removeDNS() {
        guard let store else { return }
        for k in dnsKeys { SCDynamicStoreRemoveValue(store, k as CFString) }
        dnsKeys = []
    }

    // MARK: Teardown

    /// Removes everything this object added. The utun's own routes would go
    /// with the interface anyway; they're removed here too so a clean stop
    /// doesn't depend on that.
    public func teardown() {
        removeDNS()
        for r in tunnelRoutes { try? RoutingSocket.delete(r) }
        tunnelRoutes = []
        for r in excluded {
            do { try RoutingSocket.delete(r) } catch { log("removing excluded route \(r): \(error)") }
        }
        excluded = []
        excludedWanted = []
        try? FileManager.default.removeItem(at: journal)
    }

    // MARK: Journal

    private func writeJournal(_ routes: Set<RouteSpec>) throws {
        if routes.isEmpty {
            try? FileManager.default.removeItem(at: journal)
            return
        }
        let dir = journal.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o755])
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try enc.encode(Journal(routes: routes.sorted { $0.description < $1.description }))
        try data.write(to: journal, options: .atomic)
    }

    /// Deletes every route a journal lists (left by a run that was killed)
    /// and removes the journal. Returns the routes that were still there.
    @discardableResult
    public static func sweep(journal: URL = NetConfig.defaultJournal, log: (String) -> Void) -> [RouteSpec] {
        guard let data = try? Data(contentsOf: journal) else { return [] }
        guard let j = try? JSONDecoder().decode(Journal.self, from: data) else {
            log("unreadable journal \(journal.path); removed")
            try? FileManager.default.removeItem(at: journal)
            return []
        }
        var removed: [RouteSpec] = []
        for r in j.routes {
            do {
                if try RoutingSocket.delete(r) { removed.append(r) }
            } catch {
                log("sweep: \(r): \(error)")
            }
        }
        try? FileManager.default.removeItem(at: journal)
        if !removed.isEmpty { log("sweep removed \(removed.count) route(s) left by an earlier run: \(removed.map(\.description).joined(separator: ", "))") }
        return removed
    }
}

/// Adds and deletes routes with PF_ROUTE messages, as route(8) does.
public enum RoutingSocket {
    static let rtmAdd: UInt8 = 0x1
    static let rtmDelete: UInt8 = 0x2
    static let rtmVersion: UInt8 = 5
    static let rtfUp: Int32 = 0x1
    static let rtfGateway: Int32 = 0x2
    static let rtfHost: Int32 = 0x4
    static let rtfStatic: Int32 = 0x800
    static let rtaDst: Int32 = 0x1
    static let rtaGateway: Int32 = 0x2
    static let rtaNetmask: Int32 = 0x4

    nonisolated(unsafe) private static var seq: Int32 = 0
    private static let lock = NSLock()

    /// Adds `r`. One that's already there counts as added.
    public static func add(_ r: RouteSpec) throws {
        do {
            try send(rtmAdd, r)
        } catch let e as SystemError where e.code == EEXIST {
            return
        }
    }

    /// Deletes `r`. Returns false if it wasn't there.
    @discardableResult
    public static func delete(_ r: RouteSpec) throws -> Bool {
        do {
            try send(rtmDelete, r)
            return true
        } catch let e as SystemError where e.code == ESRCH {
            return false
        }
    }

    static func send(_ type: UInt8, _ r: RouteSpec) throws {
        let msg = try message(type, r)
        let s = socket(PF_ROUTE, SOCK_RAW, 0)
        guard s >= 0 else { throw SystemError("socket(PF_ROUTE)") }
        defer { close(s) }
        _ = shutdown(s, SHUT_RD)
        let n = msg.withUnsafeBytes { write(s, $0.baseAddress, $0.count) }
        guard n == msg.count else {
            throw SystemError("\(type == rtmAdd ? "add" : "delete") route \(r)")
        }
    }

    static func message(_ type: UInt8, _ r: RouteSpec) throws -> [UInt8] {
        let v6 = r.isIPv6
        let full = v6 ? 128 : 32
        guard let dst = sockaddrBytes(r.destination) else { throw SystemError("bad route destination \(r.destination)", EINVAL) }
        var flags = rtfUp | rtfStatic
        var addrs = rtaDst | rtaGateway
        let gw: [UInt8]
        if let g = r.gateway {
            guard let a = sockaddrBytes(g) else { throw SystemError("bad router \(g)", EINVAL) }
            gw = a
            flags |= rtfGateway
        } else if let ifname = r.interface {
            guard let dl = linkAddress(ifname) else { throw SystemError("no interface \(ifname)", ENXIO) }
            gw = dl
        } else {
            throw SystemError("route \(r) has no gateway or interface", EINVAL)
        }
        var body = pad(dst) + pad(gw)
        if r.prefixLength >= full {
            flags |= rtfHost
        } else {
            addrs |= rtaNetmask
            body += pad(netmask(r.prefixLength, v6: v6))
        }

        var hdr = rt_msghdr()
        let total = MemoryLayout<rt_msghdr>.size + body.count
        hdr.rtm_msglen = UInt16(total)
        hdr.rtm_version = rtmVersion
        hdr.rtm_type = type
        hdr.rtm_flags = flags
        hdr.rtm_addrs = addrs
        hdr.rtm_seq = lock.withLock {
            seq += 1
            return seq
        }
        var out = withUnsafeBytes(of: &hdr) { Array($0) }
        out += body
        return out
    }

    /// Pads a sockaddr to 4 bytes, as the kernel expects (ROUNDUP in route.c).
    static func pad(_ sa: [UInt8]) -> [UInt8] {
        let n = sa.isEmpty ? 4 : (sa.count + 3) & ~3
        return sa + [UInt8](repeating: 0, count: n - sa.count)
    }

    static func sockaddrBytes(_ s: String) -> [UInt8]? {
        if s.contains(":") {
            var a = sockaddr_in6()
            a.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            a.sin6_family = sa_family_t(AF_INET6)
            guard inet_pton(AF_INET6, s, &a.sin6_addr) == 1 else { return nil }
            return withUnsafeBytes(of: &a) { Array($0) }
        }
        var a = sockaddr_in()
        a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        a.sin_family = sa_family_t(AF_INET)
        guard inet_pton(AF_INET, s, &a.sin_addr) == 1 else { return nil }
        return withUnsafeBytes(of: &a) { Array($0) }
    }

    static func netmask(_ len: Int, v6: Bool) -> [UInt8] {
        let bytes = v6 ? 16 : 4
        var mask = [UInt8](repeating: 0, count: bytes)
        for i in 0..<bytes {
            let bits = max(0, min(8, len - i * 8))
            mask[i] = bits == 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - bits))
        }
        if v6 {
            var a = sockaddr_in6()
            a.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            a.sin6_family = sa_family_t(AF_INET6)
            var out = withUnsafeBytes(of: &a) { Array($0) }
            out.replaceSubrange(8..<24, with: mask) // sin6_addr
            return out
        }
        var a = sockaddr_in()
        a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        a.sin_family = sa_family_t(AF_INET)
        var out = withUnsafeBytes(of: &a) { Array($0) }
        out.replaceSubrange(4..<8, with: mask) // sin_addr
        return out
    }

    /// The interface's AF_LINK sockaddr, which a route straight onto an
    /// interface uses as its gateway (route's -interface).
    static func linkAddress(_ ifname: String) -> [UInt8]? {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return nil }
        defer { freeifaddrs(list) }
        var p: UnsafeMutablePointer<ifaddrs>? = first
        while let ifa = p {
            defer { p = ifa.pointee.ifa_next }
            guard let sa = ifa.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_LINK),
                  String(cString: ifa.pointee.ifa_name) == ifname else { continue }
            return Array(UnsafeRawBufferPointer(start: sa, count: Int(sa.pointee.sa_len)))
        }
        return nil
    }
}
#endif
