import Foundation

public struct HTTPHeader: Equatable, Sendable {
    public var name: String
    public var value: String
}

/// One HTTP request openconnect sent, and the answer if it logged one.
public struct Exchange: Equatable, Sendable {
    public var time: String?
    public var method: String
    /// Path and query, as sent.
    public var target: String
    public var requestHeaders: [HTTPHeader] = []
    public var requestBody = ""
    /// The status line, e.g. `HTTP/1.1 200 OK`.
    public var statusLine: String?
    public var responseHeaders: [HTTPHeader] = []
    public var responseBody: String?

    public var status: Int? {
        guard let s = statusLine?.split(separator: " "), s.count >= 2 else { return nil }
        return Int(s[1])
    }

    public var host: String? { requestHeaders.first { $0.name.lowercased() == "host" }?.value }
    public var path: String { String(target.split(separator: "?", maxSplits: 1).first ?? "") }
    public var query: String? {
        let parts = target.split(separator: "?", maxSplits: 1)
        return parts.count == 2 ? String(parts[1]) : nil
    }

    /// A short name for fixture files: `portal-prelogin`, `gateway-getconfig`, `tunnel-connect`.
    public var label: String {
        let p = path
        func last() -> String {
            let name = p.split(separator: "/").last.map(String.init) ?? "root"
            return String(name.split(separator: ".").first ?? "root")
        }
        if p.hasPrefix("/global-protect/") { return "portal-" + last() }
        if p.hasPrefix("/ssl-vpn/") { return "gateway-" + last() }
        if p.hasPrefix("/ssl-tunnel-connect") { return "tunnel-connect" }
        let cleaned = last().map { $0.isLetter || $0.isNumber ? $0 : "-" }
        return "other-" + String(cleaned)
    }
}

/// A line of openconnect output that is not part of an HTTP dump.
public struct LogEvent: Equatable, Sendable {
    public var time: String?
    public var text: String
    /// The exchange that this line follows, if any (index into `exchanges`).
    public var after: Int?
}

/// The output of `openconnect -v --timestamp --dump-http-traffic`, split into
/// HTTP exchanges and everything else.
public struct CaptureLog: Sendable {
    public var exchanges: [Exchange] = []
    public var events: [LogEvent] = []

    private enum State { case idle, requestHeaders, requestBody, responseHeaders, responseBody }

    public init(parsing text: String) {
        var state = State.idle
        var current: Int?
        var bodyLines: [String] = []

        func finishBody() {
            if let i = current, state == .responseBody {
                exchanges[i].responseBody = bodyLines.joined(separator: "\n")
            }
            if let i = current, state == .requestBody {
                exchanges[i].requestBody = bodyLines.joined(separator: "\n")
            }
            bodyLines = []
        }

        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            var line = Substring(raw)
            if line.hasSuffix("\r") { line = line.dropLast() }
            var time: String?
            if line.hasPrefix("["), line.count >= 22, line.dropFirst(20).hasPrefix("] "),
               line.dropFirst(1).prefix(19).allSatisfy({ $0.isNumber || $0 == "-" || $0 == ":" || $0 == " " }) {
                time = String(line.dropFirst(1).prefix(19))
                line = line.dropFirst(22)
            }
            let text = String(line)

            if text.hasPrefix("> ") || text == ">" {
                let content = String(text.dropFirst(min(2, text.count)))
                if Self.isHexDump(content) && state != .requestHeaders && state != .requestBody { continue }
                if let (method, target) = Self.requestLine(content),
                   state != .requestHeaders {
                    finishBody()
                    exchanges.append(Exchange(time: time, method: method, target: target))
                    current = exchanges.count - 1
                    state = .requestHeaders
                    continue
                }
                switch state {
                case .requestHeaders:
                    if content.isEmpty {
                        state = .requestBody
                    } else if let h = Self.header(content), let i = current {
                        exchanges[i].requestHeaders.append(h)
                    }
                case .requestBody:
                    bodyLines.append(content)
                default:
                    break
                }
                continue
            }
            if text.hasPrefix("< ") || text == "<" {
                let content = String(text.dropFirst(min(2, text.count)))
                if state == .responseHeaders {
                    state = .responseBody
                    bodyLines = []
                }
                if state == .responseBody {
                    bodyLines.append(content)
                }
                continue
            }

            // Not a dump line.
            if state == .requestHeaders || state == .requestBody || state == .responseBody {
                finishBody()
                state = .idle
            }
            if text.hasPrefix("Got HTTP response: "), let i = Self.lastUnanswered(exchanges) {
                exchanges[i].statusLine = String(text.dropFirst("Got HTTP response: ".count))
                current = i
                state = .responseHeaders
                continue
            }
            if state == .responseHeaders {
                if text.hasPrefix("HTTP body ") { continue }
                if let h = Self.header(text), let i = current {
                    exchanges[i].responseHeaders.append(h)
                    continue
                }
            }
            events.append(LogEvent(time: time, text: text, after: exchanges.isEmpty ? nil : exchanges.count - 1))
        }
        finishBody()
        if let last = events.last, last.text.isEmpty { events.removeLast() }
    }

    static func lastUnanswered(_ xs: [Exchange]) -> Int? {
        guard let i = xs.indices.last, xs[i].statusLine == nil else { return nil }
        return i
    }

    static func requestLine(_ s: String) -> (String, String)? {
        let parts = s.split(separator: " ")
        guard parts.count == 3, parts[2].hasPrefix("HTTP/1."),
              parts[0].allSatisfy({ $0.isUppercase }), parts[1].hasPrefix("/") else { return nil }
        return (String(parts[0]), String(parts[1]))
    }

    static func header(_ s: String) -> HTTPHeader? {
        guard let colon = s.firstIndex(of: ":"), colon != s.startIndex else { return nil }
        let name = s[..<colon]
        guard name.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" }) else { return nil }
        var value = s[s.index(after: colon)...]
        if value.hasPrefix(" ") { value = value.dropFirst() }
        return HTTPHeader(name: String(name), value: String(value))
    }

    /// openconnect's `dump_buf_hex` lines: `0000:  01 02 …  |..|`.
    static func isHexDump(_ s: String) -> Bool {
        let b = Array(s.utf8)
        guard b.count > 6, b[4] == UInt8(ascii: ":") else { return false }
        return b[0..<4].allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    /// The parsed XML of each exchange's answer, where it is XML.
    public func responseXML(_ i: Int) -> String? {
        exchanges[i].responseBody
    }
}
