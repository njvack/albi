/// Just enough HTTP/1.1 for the portal and gateway, for transports that can't
/// use URLSession: the root helper pins its gateway connections to the
/// physical interface, which URLSession has no way to do. One request per
/// connection (`Connection: close`), no redirects, no compression.
public enum HTTP1 {
    public enum ParseError: Error, Equatable, Sendable {
        case badStatusLine
        case badHeader
        case badChunk
        case truncated
        case tooLarge
    }

    /// The bytes of `request` for `host` (the Host header: `host` or `host:port`).
    public static func encode(_ request: HTTPRequest, host: String) -> [UInt8] {
        let body = request.method == "POST" ? Array(request.body.encoded.utf8) : []
        var head = "\(request.method) \(request.path) HTTP/1.1\r\n"
        head += "Host: \(host)\r\n"
        head += "User-Agent: \(HTTPRequest.userAgent)\r\n"
        head += "Accept: */*\r\n"
        head += "Connection: close\r\n"
        if request.method == "POST" {
            head += "Content-Type: \(HTTPRequest.contentType)\r\n"
            head += "Content-Length: \(body.count)\r\n"
        }
        head += "\r\n"
        return Array(head.utf8) + body
    }

    /// Reads one response from a byte stream. Feed it what the connection
    /// returns; call `finish()` at end of stream.
    public struct ResponseParser: Sendable {
        public static let maxBody = 16 << 20

        private var buffer: [UInt8] = []
        private var status: Int?
        private var headers: [(String, String)] = []
        private var bodyStart = 0
        private var noBody = false

        public init() {}

        /// The response once it is complete, else nil.
        public mutating func feed(_ bytes: [UInt8]) throws(ParseError) -> HTTPResponse? {
            buffer += bytes
            if status == nil {
                guard let end = Self.find([13, 10, 13, 10], in: buffer) else {
                    if buffer.count > 64 << 10 { throw .tooLarge }
                    return nil
                }
                try parseHead(Array(buffer[0..<end]))
                bodyStart = end + 4
                // A 1xx is followed by the real response.
                if let s = status, s >= 100 && s < 200 {
                    buffer = Array(buffer[bodyStart...])
                    status = nil
                    headers = []
                    return try feed([])
                }
            }
            return try complete(atEOF: false)
        }

        /// The response at end of stream. Throws if it was cut short.
        public mutating func finish() throws(ParseError) -> HTTPResponse {
            guard status != nil else { throw .truncated }
            guard let r = try complete(atEOF: true) else { throw .truncated }
            return r
        }

        private mutating func parseHead(_ head: [UInt8]) throws(ParseError) {
            let lines = String(decoding: head, as: UTF8.self).split(separator: "\r\n", omittingEmptySubsequences: false)
            guard let first = lines.first else { throw .badStatusLine }
            let parts = first.split(separator: " ", maxSplits: 2)
            guard parts.count >= 2, parts[0].hasPrefix("HTTP/1."), let code = Int(parts[1]) else {
                throw .badStatusLine
            }
            status = code
            for l in lines.dropFirst() where !l.isEmpty {
                guard let colon = l.firstIndex(of: ":") else { throw .badHeader }
                let name = String(l[..<colon]).lowercased()
                let value = String(l[l.index(after: colon)...]).trimmingXMLWhitespace()
                headers.append((name, value))
            }
            noBody = code == 204 || code == 304
        }

        private func header(_ name: String) -> String? {
            headers.last(where: { $0.0 == name })?.1
        }

        private func complete(atEOF: Bool) throws(ParseError) -> HTTPResponse? {
            guard let status else { return nil }
            let body = buffer[bodyStart...]
            if noBody { return HTTPResponse(status: status, body: "") }
            if header("transfer-encoding")?.lowercased().contains("chunked") == true {
                guard let decoded = try Self.dechunk(Array(body)) else {
                    if atEOF { throw .truncated }
                    return nil
                }
                return HTTPResponse(status: status, body: String(decoding: decoded, as: UTF8.self))
            }
            if let cl = header("content-length") {
                guard let n = Int(cl), n >= 0 else { throw .badHeader }
                guard n <= Self.maxBody else { throw .tooLarge }
                guard body.count >= n else {
                    if atEOF { throw .truncated }
                    return nil
                }
                return HTTPResponse(status: status, body: String(decoding: body.prefix(n), as: UTF8.self))
            }
            // No length: the body runs to end of stream.
            if body.count > Self.maxBody { throw .tooLarge }
            guard atEOF else { return nil }
            return HTTPResponse(status: status, body: String(decoding: body, as: UTF8.self))
        }

        /// The decoded body, or nil if the last chunk hasn't arrived.
        static func dechunk(_ b: [UInt8]) throws(ParseError) -> [UInt8]? {
            var out: [UInt8] = []
            var i = 0
            while true {
                guard let lineEnd = find([13, 10], in: b, from: i) else { return nil }
                let sizeText =
                    String(decoding: b[i..<lineEnd], as: UTF8.self)
                    .split(separator: ";", maxSplits: 1).first.map { String($0).trimmingXMLWhitespace() } ?? ""
                guard let size = Int(sizeText, radix: 16), size >= 0 else { throw .badChunk }
                i = lineEnd + 2
                if size == 0 { return out }
                guard out.count + size <= maxBody else { throw .tooLarge }
                guard b.count >= i + size + 2 else { return nil }
                out += b[i..<(i + size)]
                i += size + 2
            }
        }

        static func find(_ needle: [UInt8], in hay: [UInt8], from start: Int = 0) -> Int? {
            guard hay.count >= needle.count, start <= hay.count - needle.count else { return nil }
            var i = start
            while i <= hay.count - needle.count {
                if hay[i] == needle[0] && Array(hay[i..<(i + needle.count)]) == needle { return i }
                i += 1
            }
            return nil
        }
    }
}
