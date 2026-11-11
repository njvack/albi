/// GPST framing for the HTTPS tunnel. Every packet has a 16-byte header:
///
///     0..3   magic 0x1a2b3c4d, big-endian
///     4..5   ethertype: 0x0800 IPv4, 0x86DD IPv6, 0 for keepalive, big-endian
///     6..7   payload length, big-endian
///     8..11  1 for data, 0 for keepalive, little-endian
///     12..15 zero
public enum GPST {
    public static let magic: UInt32 = 0x1a2b3c4d
    public static let headerLength = 16
    public static let etherIPv4: UInt16 = 0x0800
    public static let etherIPv6: UInt16 = 0x86DD

    public enum Frame: Equatable, Sendable {
        case keepalive
        case packet([UInt8])
    }

    /// A keepalive (DPD) frame. The gateway echoes it back.
    public static let keepaliveFrame: [UInt8] = [0x1a, 0x2b, 0x3c, 0x4d] + [UInt8](repeating: 0, count: 12)

    /// Frames one IP packet. The ethertype comes from the IP version nibble.
    public static func encode(packet: [UInt8]) -> [UInt8] {
        let et = (packet.first ?? 0) >> 4 == 6 ? etherIPv6 : etherIPv4
        let n = UInt16(truncatingIfNeeded: packet.count)
        var out: [UInt8] = [0x1a, 0x2b, 0x3c, 0x4d, UInt8(et >> 8), UInt8(et & 0xff), UInt8(n >> 8), UInt8(n & 0xff),
                            1, 0, 0, 0, 0, 0, 0, 0]
        out.reserveCapacity(headerLength + packet.count)
        out += packet
        return out
    }

    public enum DecodeError: Error, Equatable, Sendable {
        case badMagic
        case unknownEthertype(UInt16)
    }

    /// Splits a byte stream into frames. Feed it whatever the TLS connection
    /// returns; it keeps partial frames until the rest arrives.
    public struct Decoder: Sendable {
        private var buffer: [UInt8] = []
        private var start = 0

        public init() {}

        public mutating func append(_ bytes: [UInt8]) { buffer += bytes }

        /// The next complete frame, or nil if more bytes are needed.
        public mutating func next() throws(DecodeError) -> Frame? {
            let avail = buffer.count - start
            guard avail >= headerLength else { compact(); return nil }
            let h = start
            let m = UInt32(buffer[h]) << 24 | UInt32(buffer[h + 1]) << 16 | UInt32(buffer[h + 2]) << 8 | UInt32(buffer[h + 3])
            guard m == magic else { throw .badMagic }
            let et = UInt16(buffer[h + 4]) << 8 | UInt16(buffer[h + 5])
            let n = Int(buffer[h + 6]) << 8 | Int(buffer[h + 7])
            guard avail >= headerLength + n else { compact(); return nil }
            let payload = Array(buffer[(h + headerLength)..<(h + headerLength + n)])
            start += headerLength + n
            switch et {
            case 0: return .keepalive
            case etherIPv4, etherIPv6: return .packet(payload)
            default: throw .unknownEthertype(et)
            }
        }

        private mutating func compact() {
            if start > 0 {
                buffer.removeFirst(start)
                start = 0
            }
        }
    }

    /// The request that turns a TLS connection into a tunnel. Sent raw, with
    /// no Host header, exactly as openconnect does.
    public static func tunnelRequest(path: String, cookie: AuthCookie) -> [UInt8] {
        let q = cookie.form.keeping(["user", "authcookie"]).encoded
        return Array("GET \(path)?\(q) HTTP/1.1\r\n\r\n".utf8)
    }

    /// Reads the gateway's answer to `tunnelRequest`.
    public struct Handshake: Sendable {
        public enum Result: Equatable, Sendable {
            /// Tunnel is up; `leftover` bytes are the start of the frame stream.
            case started(leftover: [UInt8])
            case rejected(GPError)
        }

        private var buffer: [UInt8] = []
        private static let start = Array("START_TUNNEL".utf8)

        public init() {}

        /// Returns nil until there are enough bytes to decide.
        public mutating func feed(_ bytes: [UInt8]) -> Result? {
            buffer += bytes
            let s = Handshake.start
            if buffer.count >= s.count && Array(buffer[0..<s.count]) == s {
                return .started(leftover: Array(buffer[s.count...]))
            }
            if buffer.count < s.count && Array(s[0..<buffer.count]) == buffer {
                return nil
            }
            // Not START_TUNNEL: an HTTP response. Wait for the status line.
            guard let nl = buffer.firstIndex(of: 0x0A) else {
                return buffer.count > 4096 ? .rejected(.malformed("no status line")) : nil
            }
            let line = String(decoding: buffer[..<nl], as: UTF8.self)
            let parts = line.split(separator: " ")
            if parts.count >= 2, parts[0].hasPrefix("HTTP/"), let code = Int(parts[1]) {
                // Gateways answer a bad cookie with 502.
                return .rejected(code == 502 ? .cookieRejected("tunnel request got HTTP 502") : .http(code))
            }
            return .rejected(.malformed("unexpected tunnel response: \(line.prefix(80))"))
        }

        /// Call when the connection ends before `feed` returned a result.
        public func closed() -> GPError {
            buffer.isEmpty ? .server("gateway closed the connection after the tunnel request") :
                .malformed("short tunnel response")
        }
    }
}
