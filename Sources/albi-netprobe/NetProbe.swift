// albi-netprobe: settles the root helper's open questions before anything is
// built on them. `up` makes a utun, gives it an address and routes, and
// publishes DNS as temporary dynamic-store keys, then answers DNS queries
// for the tunnel's resolver itself, so a lookup that comes back with
// 192.0.2.53 proves the system resolver used the tunnel. It never cleans up
// on purpose: whatever it changed must vanish when the process ends, on
// SIGTERM or on kill -9 alike. e2e/netprobe.sh checks that it does.
//
// `sm` and `daemon-mark` back scripts/smappservice-probe.sh, which checks
// whether SMAppService registers a daemon from an app signed without a paid
// team.
//
// Addresses and routes go through ifconfig and route here; the helper will
// use the routing socket. What's being tested is how the kernel and configd
// treat the result, not how it was made.

#if os(macOS)
import Darwin
import Foundation
import ServiceManagement
import SystemConfiguration

nonisolated(unsafe) private var stopRequested: Int32 = 0

private let utunControlName = "com.apple.net.utun_control"
private let ctlIoCGInfo: UInt = 0xC064_4E03 // _IOWR('N', 3, struct ctl_info)
private let sysprotoControl: Int32 = 2      // SYSPROTO_CONTROL
private let afSysControl: UInt16 = 2        // AF_SYS_CONTROL
private let utunOptIfname: Int32 = 2        // UTUN_OPT_IFNAME
private let ipBoundIf: Int32 = 25           // IP_BOUND_IF

/// The tunnel's address, its DNS server, and what that server answers.
private let tunnelAddress = "10.99.0.2"
private let tunnelDNS = "10.99.0.53"
private let tunnelNet = "10.99.0.0/16"
private let answerAddress: [UInt8] = [192, 0, 2, 53]
private let matchDomain = "albi-probe.test"

struct ProbeError: Error, CustomStringConvertible {
    var description: String
    init(_ s: String) { description = s }
}

private func say(_ s: String) {
    print(s)
    fflush(stdout)
}

private func errnoString(_ e: Int32 = errno) -> String { String(cString: strerror(e)) }

@main
struct NetProbe {
    static func main() {
        var args = Array(CommandLine.arguments.dropFirst())
        guard !args.isEmpty else { usage() }
        let cmd = args.removeFirst()
        do {
            switch cmd {
            case "up": try up(args)
            case "sm": try sm(args)
            case "daemon-mark": try daemonMark()
            default: usage()
            }
        } catch {
            say("error: \(error)")
            exit(1)
        }
    }

    static func usage() -> Never {
        say("""
        usage: albi-netprobe up --full|--split [--hold SECONDS] [--check-host IPV4]   (as root)
               albi-netprobe sm register|unregister|status PLIST-NAME
               albi-netprobe daemon-mark                                          (run by launchd)
        """)
        exit(2)
    }

    // MARK: up

    static func up(_ args: [String]) throws {
        var full: Bool?
        var hold = 120.0
        var checkHost = "1.1.1.1"
        var it = args.makeIterator()
        while let a = it.next() {
            switch a {
            case "--full": full = true
            case "--split": full = false
            case "--hold": hold = Double(it.next() ?? "") ?? hold
            case "--check-host": checkHost = it.next() ?? checkHost
            default: usage()
            }
        }
        guard let full else { usage() }
        guard getuid() == 0 else { throw ProbeError("up needs root") }

        signal(SIGINT) { _ in stopRequested = 1 }
        signal(SIGTERM) { _ in stopRequested = 1 }

        guard let store = SCDynamicStoreCreate(nil, "albi-netprobe" as CFString, nil, nil) else {
            throw ProbeError("SCDynamicStoreCreate failed")
        }
        let primary = primaryInterface(store)
        say("primary-interface=\(primary ?? "none")")

        let (fd, ifname) = try openUtun()
        say("utun=\(ifname)")
        try run("/sbin/ifconfig", [ifname, "inet", tunnelAddress, tunnelAddress, "netmask", "255.255.255.255",
                                   "mtu", "1400", "up"])
        let routes = full ? ["0.0.0.0/1", "128.0.0.0/1", tunnelNet] : [tunnelNet]
        for r in routes {
            try run("/sbin/route", ["-q", "-n", "add", "-net", r, "-interface", ifname])
        }
        say("routes=\(routes.joined(separator: ","))")

        // DNS, the way vpnc-script does it but with temporary keys: configd
        // drops them when this process's session ends. Full tunnel marks the
        // service OverridePrimary so its resolver becomes the default one.
        let service = "albi-netprobe-\(UUID().uuidString)"
        var ipv4: [String: Any] = [
            "Addresses": [tunnelAddress],
            "SubnetMasks": ["255.255.255.255"],
            "DestAddresses": [tunnelAddress],
            "InterfaceName": ifname,
        ]
        var dns: [String: Any] = ["ServerAddresses": [tunnelDNS]]
        if full {
            ipv4["Router"] = tunnelAddress
            ipv4["OverridePrimary"] = 1
            dns["SearchDomains"] = [matchDomain]
        } else {
            dns["SupplementalMatchDomains"] = [matchDomain]
        }
        for (key, value) in [("IPv4", ipv4), ("DNS", dns)] {
            let k = "State:/Network/Service/\(service)/\(key)"
            guard SCDynamicStoreAddTemporaryValue(store, k as CFString, value as NSDictionary) else {
                throw ProbeError("SCDynamicStoreAddTemporaryValue \(k): \(String(cString: SCErrorString(SCError())))")
            }
        }
        say("service=\(service)")

        // With 0/1 and 128/1 on the utun, a socket pinned to the physical
        // interface should still get out (so the helper needs no host route
        // to the gateway); an unpinned one goes into the tunnel, where
        // nothing answers TCP.
        if full, let primary {
            // configd re-does routes for a moment after the service shows
            // up; retry to measure how long a pinned socket can't get out.
            let start = Date()
            var attempts = 0
            var first = ""
            var result = ""
            repeat {
                attempts += 1
                result = tcpCheck(host: checkHost, port: 443, boundTo: primary, timeoutMs: 2000)
                if first.isEmpty { first = result }
                if result == "connected" { break }
                usleep(100_000)
            } while Date().timeIntervalSince(start) < 8
            let ms = Int(Date().timeIntervalSince(start) * 1000)
            say("bound-check=\(result)")
            say("bound-check-detail=\(attempts) attempts in \(ms) ms, first: \(first)")
            say("unbound-check=\(tcpCheck(host: checkHost, port: 443, boundTo: nil, timeoutMs: 2000))")
        }

        say("READY pid=\(getpid()) utun=\(ifname) service=\(service)")
        let answered = serveDNS(fd: fd, until: Date().addingTimeInterval(hold))
        // No cleanup on purpose. Exit and let the kernel and configd undo it.
        say("exiting (answered \(answered) DNS queries); no cleanup by design")
        withExtendedLifetime(store) {}
        exit(0)
    }

    static func primaryInterface(_ store: SCDynamicStore) -> String? {
        let v = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any]
        return v?["PrimaryInterface"] as? String
    }

    static func openUtun() throws -> (Int32, String) {
        let fd = socket(PF_SYSTEM, SOCK_DGRAM, sysprotoControl)
        guard fd >= 0 else { throw ProbeError("socket(PF_SYSTEM): \(errnoString())") }
        var info = ctl_info()
        withUnsafeMutableBytes(of: &info.ctl_name) { buf in
            for (i, b) in utunControlName.utf8.enumerated() { buf[i] = b }
        }
        let rc = withUnsafeMutablePointer(to: &info) { ioctl(fd, ctlIoCGInfo, $0) }
        guard rc == 0 else { throw ProbeError("CTLIOCGINFO: \(errnoString())") }

        var addr = sockaddr_ctl()
        addr.sc_len = UInt8(MemoryLayout<sockaddr_ctl>.size)
        addr.sc_family = UInt8(AF_SYSTEM)
        addr.ss_sysaddr = afSysControl
        addr.sc_id = info.ctl_id
        addr.sc_unit = 0 // the kernel picks the next free utun
        let crc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_ctl>.size))
            }
        }
        guard crc == 0 else { throw ProbeError("connect utun_control: \(errnoString())") }

        var name = [CChar](repeating: 0, count: 64)
        var len = socklen_t(name.count)
        guard getsockopt(fd, sysprotoControl, utunOptIfname, &name, &len) == 0 else {
            throw ProbeError("UTUN_OPT_IFNAME: \(errnoString())")
        }
        return (fd, String(decoding: name.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self))
    }

    @discardableResult
    static func run(_ path: String, _ args: [String]) throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        try p.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let out = String(decoding: data, as: UTF8.self)
        guard p.terminationStatus == 0 else {
            throw ProbeError("\(path) \(args.joined(separator: " ")) exited \(p.terminationStatus): \(out)")
        }
        return out
    }

    static func tcpCheck(host: String, port: UInt16, boundTo ifname: String?, timeoutMs: Int32) -> String {
        let s = socket(AF_INET, SOCK_STREAM, 0)
        guard s >= 0 else { return "error socket: \(errnoString())" }
        defer { close(s) }
        if let ifname {
            var idx = if_nametoindex(ifname)
            guard setsockopt(s, IPPROTO_IP, ipBoundIf, &idx, socklen_t(MemoryLayout<UInt32>.size)) == 0 else {
                return "error IP_BOUND_IF: \(errnoString())"
            }
        }
        _ = fcntl(s, F_SETFL, O_NONBLOCK)
        var sa = sockaddr_in()
        sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_port = port.bigEndian
        guard inet_pton(AF_INET, host, &sa.sin_addr) == 1 else { return "error bad address \(host)" }
        let rc = withUnsafePointer(to: &sa) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if rc == 0 { return "connected" }
        guard errno == EINPROGRESS else { return "error \(errnoString())" }
        var p = pollfd(fd: s, events: Int16(POLLOUT), revents: 0)
        if poll(&p, 1, timeoutMs) == 0 { return "timeout" }
        var err: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        _ = getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len)
        return err == 0 ? "connected" : "error \(errnoString(err))"
    }

    /// Reads packets from the utun until a signal or the deadline, answering
    /// DNS queries to the tunnel's resolver. Returns how many it answered.
    static func serveDNS(fd: Int32, until deadline: Date) -> Int {
        var buf = [UInt8](repeating: 0, count: 65536)
        let server = ipv4Bytes(tunnelDNS)
        var answered = 0
        while stopRequested == 0 && Date() < deadline {
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&p, 1, 200) > 0 else { continue }
            let n = read(fd, &buf, buf.count)
            guard n > 4 else { continue }
            // Each utun packet starts with a 4-byte protocol family.
            let packet = Array(buf[4..<n])
            guard let reply = dnsReply(to: packet, server: server, answer: answerAddress) else { continue }
            var out: [UInt8] = [0, 0, 0, UInt8(AF_INET)]
            out += reply
            if write(fd, &out, out.count) == out.count { answered += 1 }
        }
        return answered
    }

    static func ipv4Bytes(_ s: String) -> [UInt8] { s.split(separator: ".").compactMap { UInt8($0) } }

    // MARK: sm

    static func sm(_ args: [String]) throws {
        guard args.count == 2 else { usage() }
        let svc = SMAppService.daemon(plistName: args[1])
        switch args[0] {
        case "register":
            do {
                try svc.register()
                say("register: ok")
            } catch {
                say("register: failed: \(error)")
            }
        case "unregister":
            do {
                try svc.unregister()
                say("unregister: ok")
            } catch {
                say("unregister: failed: \(error)")
            }
        case "status": break
        default: usage()
        }
        say("status: \(describe(svc.status))")
    }

    static func describe(_ s: SMAppService.Status) -> String {
        switch s {
        case .notRegistered: "notRegistered"
        case .enabled: "enabled"
        case .requiresApproval: "requiresApproval"
        case .notFound: "notFound"
        @unknown default: "unknown(\(s.rawValue))"
        }
    }

    /// What the probe daemon does when launchd runs it: leave a mark that
    /// says it ran, and as whom.
    static func daemonMark() throws {
        let line = "uid=\(getuid()) at=\(Date())\n"
        try line.write(toFile: "/var/tmp/albi-netprobe-daemon.txt", atomically: true, encoding: .utf8)
    }
}

/// A reply to a DNS query (IPv4, UDP, to `server` port 53) that answers A
/// with `answer` and every other type with no records. nil for anything else.
func dnsReply(to p: [UInt8], server: [UInt8], answer: [UInt8]) -> [UInt8]? {
    guard p.count >= 20, p[0] >> 4 == 4, p[9] == 17 else { return nil }
    let udp = Int(p[0] & 0x0f) * 4
    guard p.count >= udp + 8 + 12, Array(p[16..<20]) == server else { return nil }
    guard p[udp + 2] == 0, p[udp + 3] == 53 else { return nil }
    let q = Array(p[(udp + 8)...])

    var i = 12
    while i < q.count && q[i] != 0 { i += Int(q[i]) + 1 }
    guard i + 5 <= q.count else { return nil }
    let qtype = UInt16(q[i + 1]) << 8 | UInt16(q[i + 2])
    let questionEnd = i + 5

    var dns: [UInt8] = [q[0], q[1], 0x81, 0x80, 0, 1, 0, qtype == 1 ? 1 : 0, 0, 0, 0, 0]
    dns += q[12..<questionEnd]
    if qtype == 1 {
        dns += [0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4]
        dns += answer
    }

    let udpLength = 8 + dns.count
    var udpPart: [UInt8] = [p[udp + 2], p[udp + 3], p[udp], p[udp + 1]]
    udpPart += [UInt8(udpLength >> 8), UInt8(udpLength & 0xFF), 0, 0]
    udpPart += dns

    let total = 20 + udpPart.count
    var ip: [UInt8] = [0x45, 0, UInt8(total >> 8), UInt8(total & 0xFF), 0, 0, 0x40, 0, 64, 17, 0, 0]
    ip += p[16..<20]
    ip += p[12..<16]
    let sum = ipChecksum(ip)
    ip[10] = UInt8(sum >> 8)
    ip[11] = UInt8(sum & 0xFF)
    return ip + udpPart
}

func ipChecksum(_ b: [UInt8]) -> UInt16 {
    var sum: UInt32 = 0
    var i = 0
    while i + 1 < b.count {
        sum += UInt32(b[i]) << 8 | UInt32(b[i + 1])
        i += 2
    }
    if i < b.count { sum += UInt32(b[i]) << 8 }
    while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
    return ~UInt16(sum)
}

#else

@main
struct NetProbe {
    static func main() {
        print("albi-netprobe is macOS only")
    }
}

#endif
