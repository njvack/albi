/// IPv4 ICMP echo packets, for checking a tunnel from userspace (the
/// command-line harness pings through the tunnel without a utun device).
public enum Ping {
    /// An ICMP echo request from `source` to `destination`.
    public static func request(from source: String, to destination: String, id: UInt16, sequence: UInt16,
                               payload: [UInt8] = Array("albi".utf8)) -> [UInt8]? {
        guard let src = IPv4.parse(source), let dst = IPv4.parse(destination) else { return nil }
        var icmp: [UInt8] = [8, 0, 0, 0, UInt8(id >> 8), UInt8(id & 0xff), UInt8(sequence >> 8), UInt8(sequence & 0xff)] + payload
        let c = checksum(icmp)
        icmp[2] = UInt8(c >> 8)
        icmp[3] = UInt8(c & 0xff)
        let total = 20 + icmp.count
        var ip: [UInt8] = [0x45, 0, UInt8(total >> 8), UInt8(total & 0xff), 0, 0, 0x40, 0, 64, 1, 0, 0]
        ip += bytes(src) + bytes(dst)
        let hc = checksum(ip)
        ip[10] = UInt8(hc >> 8)
        ip[11] = UInt8(hc & 0xff)
        return ip + icmp
    }

    /// The (id, sequence) of an ICMP echo reply addressed to `to`, or nil if
    /// `packet` is something else.
    public static func reply(_ p: [UInt8], to: String) -> (id: UInt16, sequence: UInt16)? {
        guard p.count >= 28, p[0] >> 4 == 4, p[9] == 1, let me = IPv4.parse(to) else { return nil }
        let ihl = Int(p[0] & 0x0f) * 4
        guard p.count >= ihl + 8, Array(p[16..<20]) == bytes(me), p[ihl] == 0 else { return nil }
        return (UInt16(p[ihl + 4]) << 8 | UInt16(p[ihl + 5]), UInt16(p[ihl + 6]) << 8 | UInt16(p[ihl + 7]))
    }

    static func bytes(_ v: UInt32) -> [UInt8] {
        [UInt8(v >> 24), UInt8(v >> 16 & 0xff), UInt8(v >> 8 & 0xff), UInt8(v & 0xff)]
    }

    static func checksum(_ b: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        while i + 1 < b.count {
            sum += UInt32(b[i]) << 8 | UInt32(b[i + 1])
            i += 2
        }
        if i < b.count { sum += UInt32(b[i]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return ~UInt16(sum)
    }
}
