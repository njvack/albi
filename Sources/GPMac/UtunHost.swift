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
        public typealias Hooks = HostHooks

        public let device: UtunDevice
        public let dnsMode: NetConfig.DNSMode
        private let net: NetConfig
        private let hooks: Hooks
        private let router: @Sendable () -> String?
        private var gatewayHosts: [String]
        /// The gateway hosts' addresses while routes are in, for dialling the
        /// gateway without DNS.
        public let addresses = GatewayAddressBook()
        private let mtu: Int?
        private let routes: [TunnelSettings.IPv4Route]?
        private let traceLimit: Int
        private let traceLock = NSLock()
        private var traced = (out: 0, in: 0)
        private let queue = DispatchQueue(label: "albi.utun-host")
        private let readQueue = DispatchQueue(label: "albi.utun-read")
        // Touched only on `queue`.
        private var settings: TunnelSettings?
        private var applied: TunnelSettings?
        private var shutDown = false
        // Tunnel source addresses, read on `readQueue`.
        private let sourceLock = NSLock()
        private var sources = Sources()
        private var dropped = 0

        /// Opens a utun. `router` gives the physical network's IPv4 router, for
        /// excluded routes and the host routes to the gateway. `gatewayHosts`
        /// are resolved for those host routes, along with getconfig's gw-address.
        public init(
            dnsMode: NetConfig.DNSMode = .split, journal: URL = NetConfig.defaultJournal,
            gatewayHosts: [String] = [], mtu: Int? = nil,
            routes: [TunnelSettings.IPv4Route]? = nil, tracePackets: Int = 0,
            router: @escaping @Sendable () -> String?, hooks: Hooks
        ) throws {
            device = try UtunDevice()
            self.dnsMode = dnsMode
            self.gatewayHosts = gatewayHosts
            self.mtu = mtu
            self.routes = routes
            traceLimit = tracePackets
            self.router = router
            self.hooks = hooks
            net = NetConfig(journal: journal, log: hooks.log)
        }

        public func apply(_ new: TunnelSettings) async throws {
            var s = new
            if let mtu { s.mtu = mtu }
            if let routes { s.includedIPv4 = routes }
            let changed = try queue.sync { () throws -> Bool in
                guard !shutDown else { return false }
                let changed = s != settings
                if let a = s.ipv4Address { try device.setIPv4(a, previous: settings?.ipv4Address) }
                if let a = s.ipv6Address, a != settings?.ipv6Address {
                    try device.addIPv6(a, prefixLength: s.ipv6PrefixLength ?? 128)
                }
                try device.setMTU(s.mtu)
                settings = s
                let src = Sources(
                    v4: s.ipv4Address.flatMap(Self.bytes(v4:)), v6: s.ipv6Address.flatMap(Self.bytes(v6:)))
                sourceLock.withLock { sources = src }
                return changed
            }
            // Reconnects usually bring the same settings; say only what's new.
            if changed {
                hooks.log("tun \(device.name) ipv4=\(s.ipv4Address ?? "-") ipv6=\(s.ipv6Address ?? "-") mtu=\(s.mtu)")
            }
        }

        public func deliver(_ packets: [[UInt8]]) {
            trace(packets, out: false)
            device.write(packets)
        }

        /// Logs the first `traceLimit` packets each way, one line each.
        private func trace(_ packets: [[UInt8]], out: Bool) {
            guard traceLimit > 0 else { return }
            for p in packets {
                let n: Int = traceLock.withLock {
                    if out { traced.out += 1; return traced.out } else { traced.in += 1; return traced.in }
                }
                guard n <= traceLimit else { return }
                hooks.log("\(out ? "out" : "in ") #\(n) \(Self.describe(p))")
            }
        }

        /// One line about an IP packet: addresses, protocol, ports, TCP flags, length.
        static func describe(_ p: [UInt8]) -> String {
            guard let v = p.first.map({ $0 >> 4 }) else { return "empty" }
            let proto: UInt8, l4: Int, src: String, dst: String
            if v == 4, p.count >= 20 {
                proto = p[9]
                l4 = Int(p[0] & 0x0f) * 4
                src = p[12..<16].map(String.init).joined(separator: ".")
                dst = p[16..<20].map(String.init).joined(separator: ".")
            } else if v == 6, p.count >= 40 {
                proto = p[6]
                l4 = 40
                src = sourceString(p)
                dst = stride(from: 24, to: 40, by: 2).map { String(UInt16(p[$0]) << 8 | UInt16(p[$0 + 1]), radix: 16) }
                    .joined(separator: ":")
            } else {
                return "v\(v) len=\(p.count)"
            }
            func port(_ o: Int) -> String {
                p.count >= l4 + o + 2 ? String(Int(p[l4 + o]) << 8 | Int(p[l4 + o + 1])) : "?"
            }
            switch proto {
            case 6:
                var f = ""
                if p.count > l4 + 13 {
                    let b = p[l4 + 13]
                    for (bit, c) in [(0x02, "S"), (0x10, "."), (0x08, "P"), (0x01, "F"), (0x04, "R")]
                    where b & UInt8(bit) != 0 { f += c }
                }
                return "tcp \(src):\(port(0)) > \(dst):\(port(2)) [\(f)] len=\(p.count)"
            case 17: return "udp \(src):\(port(0)) > \(dst):\(port(2)) len=\(p.count)"
            case 1, 58: return "icmp \(src) > \(dst) type=\(p.count > l4 ? String(p[l4]) : "?") len=\(p.count)"
            default: return "proto \(proto) \(src) > \(dst) len=\(p.count)"
            }
        }

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
        /// Packets not from the tunnel's own addresses are dropped: connections
        /// opened before the routes went in keep their old source, and a gateway
        /// may end the session over them.
        public func pumpPackets(to runner: SessionRunner) {
            let (stream, cont) = AsyncStream<[[UInt8]]>.makeStream()
            device.startReading(on: readQueue) { [self] batch in
                let src = sourceLock.withLock { sources }
                let keep = batch.filter { src.allows($0) }
                if keep.count < batch.count {
                    let before = dropped
                    dropped += batch.count - keep.count
                    if before == 0 || before / 1000 != dropped / 1000 {
                        let first = batch.first { !src.allows($0) }.map(Self.sourceString) ?? "?"
                        hooks.log("dropped \(dropped) packet(s) not from the tunnel address (e.g. from \(first))")
                    }
                }
                trace(keep, out: true)
                if !keep.isEmpty { cont.yield(keep) }
            }
            Task {
                for await batch in stream { await runner.send(packets: batch) }
            }
        }

        /// The physical network changed: excluded routes follow the new router.
        public func pathChanged() {
            queue.async {
                guard self.applied != nil, !self.shutDown else { return }
                do { try self.net.updateRouter(self.router()) } catch {
                    self.hooks.log("updating excluded routes: \(error)")
                }
            }
        }

        /// Where to dial a gateway host while the routes are in: the address
        /// saved for it when they went in. nil for other hosts, and when the
        /// routes are out (the system resolver works then). If the gateway's
        /// address changes while the tunnel is down, the reconnect fails.
        public func dialAddress(for host: String) -> String? { addresses.address(for: host) }

        /// Adds a gateway host learnt after the host was made (the gateway login
        /// chose), for the host routes and the address book.
        public func addGatewayHost(_ h: String) {
            queue.async { if !self.gatewayHosts.contains(h) { self.gatewayHosts.append(h) } }
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
            // Once the routes are in, a lookup only works while the tunnel is up.
            let gateways = Self.ipv4Addresses(of: [s.remoteAddress] + gatewayHosts)
            var book: [String: String] = [:]
            for h in gatewayHosts where !h.isEmpty && Self.bytes(v4: h) == nil {
                if let a = Self.ipv4Addresses(of: [h]).first { book[h] = a }
            }
            do {
                try net.apply(s, interface: device.name, router: router(), gateways: gateways, dnsMode: dnsMode)
                applied = s
                addresses.set(book)
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

        struct Sources: Equatable {
            var v4: [UInt8]?
            var v6: [UInt8]?

            func allows(_ p: [UInt8]) -> Bool {
                guard let first = p.first else { return false }
                switch first >> 4 {
                case 4: return v4 != nil && p.count >= 20 && p[12..<16].elementsEqual(v4!)
                case 6: return v6 != nil && p.count >= 40 && p[8..<24].elementsEqual(v6!)
                default: return false
                }
            }
        }

        static func bytes(v4 s: String) -> [UInt8]? {
            var a = in_addr()
            guard inet_pton(AF_INET, s, &a) == 1 else { return nil }
            return withUnsafeBytes(of: &a) { Array($0) }
        }

        static func bytes(v6 s: String) -> [UInt8]? {
            var a = in6_addr()
            guard inet_pton(AF_INET6, s, &a) == 1 else { return nil }
            return withUnsafeBytes(of: &a) { Array($0) }
        }

        static func sourceString(_ p: [UInt8]) -> String {
            if p.first.map({ $0 >> 4 }) == 4, p.count >= 20 {
                return p[12..<16].map(String.init).joined(separator: ".")
            }
            if p.first.map({ $0 >> 4 }) == 6, p.count >= 40 {
                return stride(from: 8, to: 24, by: 2).map { String(UInt16(p[$0]) << 8 | UInt16(p[$0 + 1]), radix: 16) }
                    .joined(separator: ":")
            }
            return "?"
        }

        private func removeNetwork() {
            let had = applied != nil
            addresses.set([:])
            net.teardown()
            applied = nil
            if had { hooks.log("network removed") }
        }
    }

    /// Gateway host names and the address to dial each at. Lookups ignore case.
    public final class GatewayAddressBook: @unchecked Sendable {
        private let lock = NSLock()
        private var map: [String: String] = [:]

        public init() {}

        public func address(for host: String) -> String? { lock.withLock { map[host.lowercased()] } }

        public func set(_ m: [String: String]) {
            let lowered = Dictionary(m.map { ($0.key.lowercased(), $0.value) }) { a, _ in a }
            lock.withLock { map = lowered }
        }
    }
#endif
