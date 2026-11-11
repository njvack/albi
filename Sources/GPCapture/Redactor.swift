import Foundation
import GPCore

/// Replaces everything in a capture that identifies the user, their machine
/// or their organization with consistent test values, so the result still
/// parses as the same conversation: one real authcookie becomes one fake
/// authcookie everywhere it appears, addresses keep their subnets, and host
/// names keep their domains.
///
/// It learns what to hide from the protocol itself (form fields and XML
/// elements known to carry cookies, keys, names and addresses), then sweeps
/// every text for host names under the learned domains, e-mail addresses,
/// IPv4 and IPv6 addresses, MAC addresses, PEM blocks and phone numbers.
/// `leaks(in:)` checks the output for anything it learned.
public struct Redactor {
    public enum Kind: String, Sendable, CaseIterable {
        case secret, password, user, computer, domainName, portal, authSource, gatewayName, word
    }

    struct Literal {
        var original: String
        var fake: String
        var kind: Kind
    }

    private(set) var literals: [String: Literal] = [:]  // keyed by original
    private var counters: [Kind: Int] = [:]
    /// DNS domains whose host names are hidden, most specific first.
    private(set) var domains: [String] = []
    private var domainFakes: [String: String] = [:]
    private var hostFakes: [String: String] = [:]
    private var emailFakes: [String: String] = [:]
    private var ipv4: IPv4Map = IPv4Map()
    private var ipv6: IPv6Map = IPv6Map()
    private var macFakes: [String: String] = [:]
    private var password: String?

    /// Words that should never appear in output, such as the organization's
    /// name. Replaced case-insensitively, along with the rest of any word
    /// they are part of.
    public private(set) var words: [String] = []

    public init(password: String? = nil, words: [String] = []) {
        if let p = password, !p.isEmpty { self.password = p }
        for w in words { addWord(w) }
    }

    // MARK: Learning

    /// The capturing machine's own account and host names, which turn up in
    /// paths and HIP reports even when they differ from the VPN login.
    public mutating func learnLocal(account: String?, hostNames: [String]) {
        if let a = account, a.count >= 3, a != "root" { add(a, .user) }
        for h in hostNames {
            let short = String(h.split(separator: ".").first ?? "")
            if short.count >= 3, short.lowercased() != "localhost" { add(short, .computer) }
        }
    }

    /// Learns from every exchange in the log.
    public mutating func learn(_ log: CaptureLog) {
        for x in log.exchanges {
            if let h = x.host { learnHost(h) }
            if let q = x.query { learnForm(q) }
            if x.requestHeaders.contains(where: { $0.name.lowercased() == "content-type" && $0.value.contains("form") }) {
                learnForm(x.requestBody)
            }
            if let b = x.responseBody, let doc = XMLElement.parse(b) { learnXML(doc) }
        }
        // openconnect names these in its own log lines.
        for e in log.events {
            if let r = e.text.range(of: "authentication-source=") {
                add(String(e.text[r.upperBound...]).trimmingCharacters(in: .whitespaces), .authSource)
            }
        }
    }

    public mutating func learnHost(_ hostPort: String) {
        var host = hostPort
        if host.hasPrefix("[") { return }  // IPv6 literal
        if let colon = host.lastIndex(of: ":") { host = String(host[..<colon]) }
        host = host.lowercased()
        guard host.contains("."), !IPv4Map.isAddress(host) else { return }
        addDomain(Self.registrableDomain(host))
    }

    mutating func learnForm(_ encoded: String) {
        for (name, value) in Form.parse(encoded).fields {
            learnField(name.lowercased(), value)
        }
    }

    mutating func learnField(_ name: String, _ value: String) {
        let v = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !v.isEmpty, v != "(null)", v != "-1" else { return }
        switch name {
        case "passwd", "password":
            // Only the form field is replaced; a short second-factor answer
            // must not be replaced everywhere it happens to occur.
            break
        case "user", "username", "user-name":
            add(v, .user)
        case "computer", "host-name", "hostname":
            add(v, .computer)
        case "domain":
            if v.contains(".") { addDomain(v) } else { add(v, .domainName) }
        case "portal", "portal-name":
            add(v, .portal)
        case "server":
            learnHost(v)
        case "report":
            if let doc = XMLElement.parse(v) { learnXML(doc) }
        case "authentication-source":
            add(v, .authSource)
        default:
            if Self.isSecretName(name) || name.hasSuffix("-spi") { add(v, .secret) }
        }
    }

    mutating func learnXML(_ x: XMLElement) {
        let name = x.name.lowercased()
        if name == "jnlp", let desc = x.child("application-desc") {
            for (i, a) in desc.children("argument").enumerated() {
                let v = Form.unescape(a.trimmedText)
                switch i {
                case 1, 2, 16, 17: learnField("authcookie", v)
                case 3: learnField("portal", v)
                case 4: learnField("user", v)
                case 5: learnField("authentication-source", v)
                case 7: learnField("domain", v)
                default: if Self.looksLikeToken(v) { learnField("authcookie", v) }
                }
            }
            return
        }
        if name == "dns-suffix" || name == "dns-suffix-v6" || name == "domain-suffix" {
            for m in x.members(x.name) where !m.isEmpty { addDomain(m.lowercased()) }
            for m in x.children("member") { addDomain(m.trimmedText.lowercased()) }
        }
        if name == "gateways" {
            // A portal's gateway list: <entry name="host"><description>Name</description>.
            func entries(_ e: XMLElement) {
                for c in e.elements {
                    if c.name == "entry", let n = c.attributes["name"] {
                        learnHost(n)
                        if let d = c.value("description") { add(d, .gatewayName) }
                    }
                    entries(c)
                }
            }
            entries(x)
        }
        let children = x.elements
        if children.isEmpty {
            learnField(name, x.trimmedText)
        }
        if name.hasPrefix("ekey") || name.hasPrefix("akey") {
            // ESP keys: <ekey-c2s><bits>128</bits><val>hex</val></ekey-c2s>
            for c in children where c.name == "val" { add(c.trimmedText, .secret) }
        }
        for c in children { learnXML(c) }
    }

    static func isSecretName(_ n: String) -> Bool {
        let n = n.lowercased()
        return n.contains("cookie") || n.contains("token") || n.contains("secret") || n.hasSuffix("key")
            || ["md5", "md5-sum", "inputstr", "host-id", "serial-number", "udid", "sessid"].contains(n)
    }

    static func isMAC(_ v: String) -> Bool {
        let p = v.split(separator: ":", omittingEmptySubsequences: false)
        let q = v.split(separator: "-", omittingEmptySubsequences: false)
        return [p, q].contains { $0.count == 6 && $0.allSatisfy { $0.count == 2 && $0.allSatisfy(\.isHexDigit) } }
    }

    static func looksLikeToken(_ v: String) -> Bool {
        v.count >= 16 && v.allSatisfy { $0.isHexDigit }
    }

    mutating func add(_ value: String, _ kind: Kind) {
        let v = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !v.isEmpty, v != "(null)", v != "-1", literals[v] == nil else { return }
        // Addresses and host names are handled by the sweeps.
        if IPv4Map.isAddress(v) || IPv6Map.parse(v) != nil || Self.isMAC(v) { return }
        if kind == .secret, v.count < 4 { return }
        if kind != .secret, v.count < 2 { return }
        let n = (counters[kind] ?? 0) + 1
        counters[kind] = n
        literals[v] = Literal(original: v, fake: Self.fake(for: v, kind: kind, n: n), kind: kind)
    }

    public mutating func addWord(_ w: String) {
        let w = w.lowercased()
        guard w.count >= 3, !words.contains(w) else { return }
        words.append(w)
    }

    mutating func addDomain(_ d: String) {
        var d = d.lowercased()
        while d.hasPrefix(".") { d.removeFirst() }
        guard d.contains("."), !IPv4Map.isAddress(d), !domains.contains(d), !Self.isTestDomain(d) else { return }
        domains.append(d)
        domains.sort { $0.count > $1.count }
        if domainFakes[d] == nil {
            let n = domainFakes.count + 1
            domainFakes[d] = n == 1 ? "example.test" : "example\(n).test"
        }
        // The organization's own name is usually the domain's first label.
        let reg = Self.registrableDomain(d)
        if let first = reg.split(separator: ".").first, !Self.genericLabels.contains(String(first)) {
            addWord(String(first))
        }
    }

    static let genericLabels: Set<String> = [
        "vpn", "gp", "portal", "gateway", "corp", "net", "com", "org", "edu", "gov", "mail", "www", "ad", "local",
        "internal", "example", "test", "lan", "home", "cloud", "global", "remote", "access", "secure", "sso",
    ]

    static func isTestDomain(_ d: String) -> Bool {
        d.hasSuffix(".test") || d == "test" || d.hasSuffix(".example") || d.hasSuffix(".invalid")
            || d.hasSuffix("example.com") || d.hasSuffix("example.org") || d.hasSuffix("example.net")
    }

    /// `vpn.cs.example.ac.uk` → `example.ac.uk`; `vpn.example.edu` → `example.edu`.
    static func registrableDomain(_ host: String) -> String {
        let labels = host.lowercased().split(separator: ".").map(String.init)
        guard labels.count > 2 else { return labels.joined(separator: ".") }
        let tld = labels[labels.count - 1], second = labels[labels.count - 2]
        let take = tld.count == 2 && ["co", "ac", "edu", "gov", "org", "net", "com", "or", "ne", "go"].contains(second) ? 3 : 2
        return labels.suffix(take).joined(separator: ".")
    }

    static func fake(for v: String, kind: Kind, n: Int) -> String {
        switch kind {
        case .secret:
            if v.hasPrefix("0x"), v.count > 2, v.dropFirst(2).allSatisfy({ $0.isHexDigit }) {
                return "0x" + fake(for: String(v.dropFirst(2)), kind: kind, n: n)
            }
            if v.allSatisfy({ $0.isHexDigit }) {
                // Same length, still hex, so parsers that check either keep working.
                let upper = v.contains { $0.isUppercase } && !v.contains { $0.isLowercase }
                let seed = String(n, radix: 16)
                var s = String(repeating: "0", count: max(0, v.count - seed.count - 2))
                s = "fa" + s + seed
                s = String(s.suffix(v.count))
                if s.count < v.count { s = String(repeating: "0", count: v.count - s.count) + s }
                return upper ? s.uppercased() : s
            }
            let base = "REDACTED\(n)"
            return v.count > base.count ? base + String(repeating: "x", count: v.count - base.count) : base
        case .password: return "REDACTED"
        case .user: return "user\(n)"
        case .computer: return "computer\(n)"
        case .domainName: return "domain\(n)"
        case .portal: return "portal\(n)"
        case .authSource: return "auth-source\(n)"
        case .gatewayName: return "Gateway \(n)"
        case .word: return "example"
        }
    }

    // MARK: Redacting

    /// Redacts a request or response body, or a log line.
    public mutating func redact(_ text: String) -> String {
        var s = text
        s = Self.replacePEM(s)
        s = redactFormPasswords(s)
        s = replaceEmails(s)
        s = replaceHosts(s)
        s = replaceLiterals(s)
        s = replaceWords(s)
        s = replaceIPv4(s)
        s = replaceIPv6(s)
        s = replaceMACs(s)
        s = Self.replacePhones(s)
        return s
    }

    /// Redacts an `application/x-www-form-urlencoded` body or query field by
    /// field: values are decoded first, so names and addresses inside an
    /// encoded HIP report are found, and re-encoded only where they changed.
    public mutating func redactForm(_ encoded: String) -> String {
        encoded.split(separator: "&", omittingEmptySubsequences: false).map { piece -> String in
            guard let eq = piece.firstIndex(of: "=") else { return redact(String(piece)) }
            let key = String(piece[..<eq]), value = String(piece[piece.index(after: eq)...])
            if ["passwd", "password"].contains(key.lowercased()) { return value.isEmpty ? String(piece) : key + "=REDACTED" }
            let decoded = Form.unescape(value)
            let red = redact(decoded)
            return key + "=" + (red == decoded ? value : Form.escape(red))
        }.joined(separator: "&")
    }

    /// Redacts a request target, treating its query as a form.
    public mutating func redactTarget(_ target: String) -> String {
        guard let q = target.firstIndex(of: "?") else { return redact(target) }
        return redact(String(target[..<q])) + "?" + redactForm(String(target[target.index(after: q)...]))
    }

    /// The mapping from real to fake values, for the local raw folder only.
    public var report: String {
        var lines: [String] = []
        for l in literals.values.sorted(by: { ($0.kind.rawValue, $0.fake) < ($1.kind.rawValue, $1.fake) }) {
            lines.append("\(l.kind.rawValue)\t\(l.original)\t\(l.fake)")
        }
        for d in domains { lines.append("dns-domain\t\(d)\t\(domainFakes[d]!)") }
        for (h, f) in hostFakes.sorted(by: { $0.value < $1.value }) { lines.append("host\t\(h)\t\(f)") }
        for (e, f) in emailFakes.sorted(by: { $0.value < $1.value }) { lines.append("email\t\(e)\t\(f)") }
        for (a, f) in ipv4.assigned.sorted(by: { $0.value < $1.value }) { lines.append("ipv4\t\(a)\t\(f)") }
        for (a, f) in ipv6.assigned.sorted(by: { $0.value < $1.value }) { lines.append("ipv6\t\(a)\t\(f)") }
        for (a, f) in macFakes.sorted(by: { $0.value < $1.value }) { lines.append("mac\t\(a)\t\(f)") }
        for w in words { lines.append("word\t\(w)\texample") }
        if password != nil { lines.append("password\t(the password you typed)\tREDACTED") }
        return lines.joined(separator: "\n") + "\n"
    }

    /// Learned values that still appear in `text`, described by their fake
    /// value so the description itself is safe to print.
    public func leaks(in text: String) -> [String] {
        let decoded = Form.unescape(text)
        var found = leaksIn(text)
        if decoded != text { found += leaksIn(decoded).filter { !found.contains($0) } }
        return found
    }

    func leaksIn(_ text: String) -> [String] {
        let bytes = Array(text.utf8)
        var found: [String] = []
        for l in literals.values where l.original.count >= 3 {
            let hit = l.kind == .secret ? text.contains(l.original)
                : Self.find(Array(l.original.utf8), in: bytes, caseInsensitive: true)
            if hit {
                found.append("\(l.kind.rawValue) shown as \(l.fake)")
            }
        }
        let lower = text.lowercased()
        for d in domains where lower.contains(d) { found.append("domain shown as \(domainFakes[d]!)") }
        for w in words where lower.contains(w) { found.append("the word \(w.prefix(1))… (\(w.count) letters)") }
        for (a, f) in ipv4.assigned where a != f && Self.find(Array(a.utf8), in: bytes, caseInsensitive: false) {
            found.append("address shown as \(f)")
        }
        for (a, f) in ipv6.assigned where a != f && lower.contains(a.lowercased()) {
            found.append("address shown as \(f)")
        }
        if let p = password, p.count >= 4, text.contains(p) { found.append("the password") }
        return found
    }

    mutating func redactFormPasswords(_ s: String) -> String {
        guard s.contains("passwd=") || s.contains("password=") else { return s }
        return Self.regexReplace(s, #"(?<=[?&\s]|^)(passwd|password)=[^&\s]*"#) { m in
            let key = m.split(separator: "=", maxSplits: 1)[0]
            return "\(key)=REDACTED"
        }
    }

    mutating func replaceLiterals(_ s: String) -> String {
        var needles: [(needle: [UInt8], fake: String, ci: Bool)] = []
        for l in literals.values {
            let ci = l.kind != .secret
            var forms = [l.original]
            let esc = Form.escape(l.original)
            if esc != l.original { forms.append(esc) }
            let xml = Self.xmlEscape(l.original)
            if xml != l.original { forms.append(xml) }
            for (i, f) in forms.enumerated() {
                let fake = i == 1 ? Form.escape(l.fake) : i == 2 ? Self.xmlEscape(l.fake) : l.fake
                needles.append((Array(f.utf8), fake, ci))
            }
        }
        if let p = password, p.count >= 4 {
            needles.append((Array(p.utf8), "REDACTED", false))
            let esc = Form.escape(p)
            if esc != p { needles.append((Array(esc.utf8), "REDACTED", false)) }
        }
        guard !needles.isEmpty else { return s }
        needles.sort { $0.needle.count > $1.needle.count }
        let b = Array(s.utf8)
        var out: [UInt8] = []
        out.reserveCapacity(b.count)
        var i = 0
        outer: while i < b.count {
            let atStart = i == 0 || !Self.isWordByte(b[i - 1])
            for n in needles where i + n.needle.count <= b.count && (atStart || !n.ci) {
                if Self.matches(n.needle, b, at: i, ci: n.ci),
                   !n.ci || i + n.needle.count == b.count || !Self.isWordByte(b[i + n.needle.count]) {
                    out.append(contentsOf: n.fake.utf8)
                    i += n.needle.count
                    continue outer
                }
            }
            out.append(b[i])
            i += 1
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Letters, digits and `.`, `_`, `-` join a word: `test` is not replaced
    /// inside `fake.test` or `test-1`.
    static func isWordByte(_ c: UInt8) -> Bool {
        (48...57).contains(c) || (65...90).contains(c) || (97...122).contains(c) || c == 95 || c == 45 || c == 46
            || c >= 0x80
    }

    static func matches(_ n: [UInt8], _ b: [UInt8], at i: Int, ci: Bool) -> Bool {
        for j in 0..<n.count {
            var x = b[i + j], y = n[j]
            if ci {
                if (65...90).contains(x) { x += 32 }
                if (65...90).contains(y) { y += 32 }
            }
            if x != y { return false }
        }
        return true
    }

    static func find(_ n: [UInt8], in b: [UInt8], caseInsensitive: Bool) -> Bool {
        guard !n.isEmpty, n.count <= b.count else { return false }
        for i in 0...(b.count - n.count) where i == 0 || !isWordByte(b[i - 1]) {
            if matches(n, b, at: i, ci: caseInsensitive), i + n.count == b.count || !isWordByte(b[i + n.count]) {
                return true
            }
        }
        return false
    }

    mutating func replaceEmails(_ s: String) -> String {
        Self.regexReplace(s, #"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"#) { m in
            let lower = m.lowercased()
            if Self.isTestDomain(String(lower.split(separator: "@").last ?? "")) { return m }
            if let f = emailFakes[lower] { return f }
            let domain = String(lower.split(separator: "@")[1])
            addDomain(Self.registrableDomain(domain))
            let f = "person\(emailFakes.count + 1)@\(domainFake(domain))"
            emailFakes[lower] = f
            return f
        }
    }

    func domainFake(_ host: String) -> String {
        let h = host.lowercased()
        for d in domains where h == d || h.hasSuffix("." + d) { return domainFakes[d]! }
        return "example.test"
    }

    mutating func replaceHosts(_ s: String) -> String {
        guard !domains.isEmpty else { return s }
        return Self.regexReplace(s, #"(?<![A-Za-z0-9.-])([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.[A-Za-z]{2,}(?![A-Za-z0-9-])"#) { m in
            let h = m.lowercased()
            guard let d = domains.first(where: { h == $0 || h.hasSuffix("." + $0) }) else { return m }
            if h == d { return domainFakes[d]! }
            if let f = hostFakes[h] { return f }
            let f = "host\(hostFakes.count + 1).\(domainFakes[d]!)"
            hostFakes[h] = f
            return f
        }
    }

    func replaceWords(_ s: String) -> String {
        var s = s
        for w in words {
            let pattern = "[A-Za-z0-9]*" + NSRegularExpression.escapedPattern(for: w) + "[A-Za-z0-9]*"
            s = Self.regexReplace(s, "(?i)" + pattern) { _ in "example" }
        }
        return s
    }

    mutating func replaceIPv4(_ s: String) -> String {
        Self.regexReplace(s, #"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9]|\.[0-9])"#) { m in
            IPv4Map.isAddress(m) ? ipv4.map(m) : m
        }
    }

    mutating func replaceIPv6(_ s: String) -> String {
        Self.regexReplace(s, #"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"#) { m in
            ipv6.map(m) ?? m
        }
    }

    mutating func replaceMACs(_ s: String) -> String {
        Self.regexReplace(s, #"(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}(?![0-9A-Fa-f:-])"#) { m in
            let key = m.lowercased().replacingOccurrences(of: "-", with: ":")
            if key == "00:00:00:00:00:00" || key == "ff:ff:ff:ff:ff:ff" { return m }
            let sep = m.contains("-") ? "-" : ":"
            if let f = macFakes[key] { return f.replacingOccurrences(of: ":", with: sep) }
            let n = macFakes.count + 1
            let f = String(format: "02:00:00:00:%02x:%02x", (n >> 8) & 0xff, n & 0xff)
            macFakes[key] = f
            return f.replacingOccurrences(of: ":", with: sep)
        }
    }

    static func replacePEM(_ s: String) -> String {
        regexReplace(s, #"-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----"#) { m in
            let kind = m.dropFirst("-----BEGIN ".count).prefix { $0 != "-" }
            return "-----BEGIN \(kind)-----\nREDACTED\n-----END \(kind)-----"
        }
    }

    static func replacePhones(_ s: String) -> String {
        var s = regexReplace(s, #"(?i)(?<=x{3}-x{3}-)[0-9]{4}"#) { _ in "0000" }
        s = regexReplace(s, #"(?<![0-9A-Za-z.:-])\(?[0-9]{3}\)?[-. ][0-9]{3}[-.][0-9]{4}(?![0-9A-Za-z.:-])"#) { _ in "555-555-0100" }
        return s
    }

    static func xmlEscape(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&apos;")
    }

    static func regexReplace(_ s: String, _ pattern: String, _ f: (String) -> String) -> String {
        guard let re = try? NSRegularExpression(pattern: pattern) else { fatalError("bad pattern \(pattern)") }
        let ns = s as NSString
        var out = ""
        var last = 0
        for m in re.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
            out += ns.substring(with: NSRange(location: last, length: m.range.location - last))
            out += f(ns.substring(with: m.range))
            last = m.range.location + m.range.length
        }
        out += ns.substring(from: last)
        return out
    }
}

/// Maps IPv4 addresses so that addresses sharing leading octets still share
/// them afterwards: a host stays inside its route, a route inside its
/// supernet. Private and special ranges stay in their ranges; netmasks,
/// 0.0.0.0, loopback and broadcast are kept.
struct IPv4Map {
    private var children: [String: [Int: Int]] = [:]
    private(set) var assigned: [String: String] = [:]

    static func isAddress(_ s: String) -> Bool { octets(s) != nil }

    static func octets(_ s: String) -> [Int]? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var o: [Int] = []
        for p in parts {
            guard !p.isEmpty, p.count <= 3, let v = Int(p), v <= 255 else { return nil }
            o.append(v)
        }
        return o
    }

    static func isNetmask(_ o: [Int]) -> Bool {
        let v = o.reduce(0) { $0 << 8 | $1 }
        guard o[0] == 255 else { return false }
        let inv = ~v & 0xffff_ffff
        return inv & (inv + 1) == 0
    }

    mutating func map(_ s: String) -> String {
        guard let o = Self.octets(s) else { return s }
        if o == [0, 0, 0, 0] || o[0] == 127 || Self.isNetmask(o) || o[0] >= 224 { return s }
        if let a = assigned[s] { return a }
        var out: [Int]
        if Self.isSpecial(o) {
            // Private, CGNAT and link-local addresses stay in their ranges.
            switch o[0] {
            case 192: out = [192, 168]
            case 169: out = [169, 254]
            case 172: out = [172, pick("172.", o[1], Array(16...31))]
            case 100: out = [100, pick("100.", o[1], Array(64...127))]
            default: out = [10, pick("10.", o[1], Array(0...254))]
            }
        } else {
            // Each public /16 becomes its own /16 under 198.18.0.0/15 and up.
            out = [198, pick("public", o[0] << 8 | o[1], Array(18...254))]
        }
        let key2 = "\(o[0]).\(o[1])."
        out.append(pick(key2, o[2], Array(1...254)))
        out.append(pick(key2 + "\(o[2]).", o[3], Array(1...254)))
        let r = out.map(String.init).joined(separator: ".")
        assigned[s] = r
        return r
    }

    /// The replacement for `v` among the siblings under `key`. 0 and 255
    /// stay (network and broadcast addresses), except in the pools that
    /// stand for a whole range.
    private mutating func pick(_ key: String, _ v: Int, _ pool: [Int]) -> Int {
        if key != "public", v == 0 || v == 255 { return v }
        var table = children[key] ?? [:]
        if let m = table[v] { return m }
        let used = Set(table.values)
        let next = pool.first { !used.contains($0) && $0 != 0 && $0 != 255 } ?? (1...254).first { !used.contains($0) } ?? v
        table[v] = next
        children[key] = table
        return next
    }

    static func isSpecial(_ o: [Int]) -> Bool {
        switch o[0] {
        case 10: return true
        case 172: return (16...31).contains(o[1])
        case 192: return o[1] == 168
        case 100: return (64...127).contains(o[1])
        case 169: return o[1] == 254
        default: return false
        }
    }
}

/// The IPv6 counterpart of `IPv4Map`, by 16-bit group. Global addresses
/// move into 2001:db8::/32; unique-local and link-local stay in their ranges.
struct IPv6Map {
    private var children: [String: [Int: Int]] = [:]
    private(set) var assigned: [String: String] = [:]

    static func parse(_ s: String) -> [Int]? {
        guard s.contains(":"), s.count >= 2 else { return nil }
        let halves = s.components(separatedBy: "::")
        guard halves.count <= 2 else { return nil }
        func groups(_ h: String) -> [Int]? {
            if h.isEmpty { return [] }
            var out: [Int] = []
            for g in h.split(separator: ":", omittingEmptySubsequences: false) {
                guard !g.isEmpty, g.count <= 4, let v = Int(g, radix: 16) else { return nil }
                out.append(v)
            }
            return out
        }
        guard let a = groups(halves[0]) else { return nil }
        if halves.count == 1 { return a.count == 8 ? a : nil }
        guard let b = groups(halves[1]), a.count + b.count < 8 else { return nil }
        return a + Array(repeating: 0, count: 8 - a.count - b.count) + b
    }

    static func format(_ g: [Int]) -> String {
        // Compress the longest run of two or more zero groups.
        var best = (start: -1, len: 0), i = 0
        while i < 8 {
            if g[i] == 0 {
                var j = i
                while j < 8 && g[j] == 0 { j += 1 }
                if j - i > best.len { best = (i, j - i) }
                i = j
            } else { i += 1 }
        }
        let hex = g.map { String($0, radix: 16) }
        if best.len < 2 { return hex.joined(separator: ":") }
        let head = hex[..<best.start].joined(separator: ":")
        let tail = hex[(best.start + best.len)...].joined(separator: ":")
        return head + "::" + tail
    }

    mutating func map(_ s: String) -> String? {
        guard let g = Self.parse(s) else { return nil }
        if g.allSatisfy({ $0 == 0 }) || g == [0, 0, 0, 0, 0, 0, 0, 1] { return s }
        if let a = assigned[s] { return a }
        var out: [Int] = []
        var key = ""
        for (i, v) in g.enumerated() {
            if i == 0 {
                if (0xfe80...0xfebf).contains(v) { out.append(0xfe80) }
                else if (0xfc00...0xfdff).contains(v) { out.append(0xfd00) }
                else { out.append(0x2001) }
            } else if i == 1 && out[0] == 0x2001 {
                out.append(0xdb8)
            } else if v == 0 || v == 0xffff {
                out.append(v)
            } else {
                var table = children[key] ?? [:]
                if let m = table[v] {
                    out.append(m)
                } else {
                    let next = table.count + 1
                    table[v] = next
                    children[key] = table
                    out.append(next)
                }
            }
            key += String(v, radix: 16) + ":"
        }
        let r = Self.format(out)
        assigned[s] = r
        return r
    }
}
