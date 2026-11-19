#if os(macOS)
import Darwin
import dnssd
import Foundation

/// Name lookups scoped to one interface, through mDNSResponder.
///
/// A scoped query uses that interface's own resolvers and goes out that
/// interface whatever the routing table says, so it still works while a full
/// tunnel's 0/1 and 128/1 capture the physical network's DNS servers and the
/// tunnel is down. getaddrinfo (and so URLSession) can't be scoped.
public enum ScopedDNS {
    /// The first IPv4 address for `host` from `interface`'s resolvers, or nil
    /// if none came within `timeout` seconds. Blocks.
    public static func ipv4(_ host: String, interface: String, timeout: Double) -> String? {
        let index = if_nametoindex(interface)
        guard index != 0 else { return nil }
        let box = Box()
        let ctx = Unmanaged.passRetained(box)
        defer { ctx.release() }
        var ref: DNSServiceRef?
        let err = DNSServiceGetAddrInfo(&ref, DNSServiceFlags(kDNSServiceFlagsTimeout), index,
                                        DNSServiceProtocol(kDNSServiceProtocol_IPv4), host, { _, flags, _, err, _, addr, _, ctx in
            guard let ctx else { return }
            let box = Unmanaged<Box>.fromOpaque(ctx).takeUnretainedValue()
            guard err == DNSServiceErrorType(kDNSServiceErr_NoError) else {
                box.done = true
                return
            }
            if let addr, addr.pointee.sa_family == sa_family_t(AF_INET), flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0,
               box.address == nil {
                var sin = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &sin.sin_addr, &buf, socklen_t(buf.count)) != nil {
                    box.address = String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
                }
            }
            if flags & DNSServiceFlags(kDNSServiceFlagsMoreComing) == 0, box.address != nil { box.done = true }
        }, ctx.toOpaque())
        guard err == DNSServiceErrorType(kDNSServiceErr_NoError), let ref else { return nil }
        defer { DNSServiceRefDeallocate(ref) }

        let fd = DNSServiceRefSockFD(ref)
        let deadline = Date().addingTimeInterval(timeout)
        while !box.done {
            let left = deadline.timeIntervalSinceNow
            guard left > 0 else { break }
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let n = poll(&p, 1, Int32(left * 1000) + 1)
            if n < 0 && errno == EINTR { continue }
            guard n > 0 else { break }
            guard DNSServiceProcessResult(ref) == DNSServiceErrorType(kDNSServiceErr_NoError) else { break }
        }
        return box.address
    }

    private final class Box {
        var address: String?
        var done = false
    }
}
#endif
