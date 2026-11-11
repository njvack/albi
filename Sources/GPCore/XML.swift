/// A small, lenient XML reader for GlobalProtect responses.
///
/// Gateways send short documents, sometimes not well formed (openconnect parses
/// them with libxml2's recover mode). This parser never throws: it skips what it
/// cannot read, closes unclosed elements at the end, and ignores stray end tags.
/// It behaves the same on Linux and macOS, which FoundationXML does not quite.
public struct XMLElement: Equatable, Sendable {
    public enum Node: Equatable, Sendable {
        case element(XMLElement)
        case text(String)
    }

    public var name: String
    public var attributes: [String: String]
    public var children: [Node]

    public init(name: String, attributes: [String: String] = [:], children: [Node] = []) {
        self.name = name
        self.attributes = attributes
        self.children = children
    }

    /// Child elements, in order.
    public var elements: [XMLElement] {
        children.compactMap { if case .element(let e) = $0 { e } else { nil } }
    }

    /// The first child element with this name.
    public func child(_ name: String) -> XMLElement? {
        elements.first { $0.name == name }
    }

    /// Every child element with this name.
    public func children(_ name: String) -> [XMLElement] {
        elements.filter { $0.name == name }
    }

    /// All text inside this element, recursively.
    public var text: String {
        children.map {
            switch $0 {
            case .text(let s): s
            case .element(let e): e.text
            }
        }.joined()
    }

    /// `text` without leading and trailing whitespace.
    public var trimmedText: String { text.trimmingXMLWhitespace() }

    /// The trimmed text of the first child with this name, or nil if there is none.
    public func value(_ name: String) -> String? { child(name)?.trimmedText }

    /// The trimmed text of each `<member>` child of the first child with this name.
    public func members(_ name: String) -> [String] {
        child(name)?.children("member").map(\.trimmedText).filter { !$0.isEmpty } ?? []
    }

    /// Parses `source` and returns its root element, or nil if it has none.
    public static func parse(_ source: String) -> XMLElement? {
        var p = XMLParserState(Array(source.utf8))
        return p.parseDocument()
    }
}

extension String {
    func trimmingXMLWhitespace() -> String {
        let ws: Set<Character> = [" ", "\t", "\n", "\r"]
        var s = Substring(self)
        while let f = s.first, ws.contains(f) { s.removeFirst() }
        while let l = s.last, ws.contains(l) { s.removeLast() }
        return String(s)
    }
}

private struct XMLParserState {
    let b: [UInt8]
    var i = 0

    init(_ bytes: [UInt8]) { b = bytes }

    // Stack of open elements; index 0 is a synthetic document node.
    var stack: [XMLElement] = [XMLElement(name: "#document")]

    mutating func parseDocument() -> XMLElement? {
        while i < b.count {
            if b[i] == UInt8(ascii: "<") {
                parseMarkup()
            } else {
                let start = i
                while i < b.count && b[i] != UInt8(ascii: "<") { i += 1 }
                appendText(decodeEntities(b[start..<i]))
            }
        }
        while stack.count > 1 { closeTop() }
        return stack[0].elements.first
    }

    mutating func appendText(_ s: String) {
        guard !s.isEmpty, stack.count > 1 else { return }
        if case .text(let prev)? = stack[stack.count - 1].children.last {
            stack[stack.count - 1].children[stack[stack.count - 1].children.count - 1] = .text(prev + s)
        } else {
            stack[stack.count - 1].children.append(.text(s))
        }
    }

    mutating func closeTop() {
        let e = stack.removeLast()
        stack[stack.count - 1].children.append(.element(e))
    }

    func hasPrefix(_ s: String) -> Bool {
        let u = Array(s.utf8)
        return i + u.count <= b.count && Array(b[i..<i + u.count]) == u
    }

    mutating func skip(past terminator: String) -> Range<Int> {
        let u = Array(terminator.utf8)
        let start = i
        while i < b.count {
            if i + u.count <= b.count && Array(b[i..<i + u.count]) == u {
                let r = start..<i
                i += u.count
                return r
            }
            i += 1
        }
        return start..<b.count
    }

    mutating func parseMarkup() {
        if hasPrefix("<!--") {
            i += 4
            _ = skip(past: "-->")
        } else if hasPrefix("<![CDATA[") {
            i += 9
            let r = skip(past: "]]>")
            appendText(String(decoding: b[r], as: UTF8.self))
        } else if hasPrefix("<?") {
            i += 2
            _ = skip(past: "?>")
        } else if hasPrefix("<!") {
            i += 2
            _ = skip(past: ">")
        } else if hasPrefix("</") {
            i += 2
            let name = readName()
            _ = skip(past: ">")
            if let idx = stack.lastIndex(where: { $0.name == name }), idx > 0 {
                while stack.count > idx { closeTop() }
            }
        } else {
            i += 1
            let name = readName()
            if name.isEmpty {
                appendText("<")
                return
            }
            var el = XMLElement(name: name)
            var selfClosing = false
            while i < b.count {
                skipSpace()
                guard i < b.count else { break }
                if b[i] == UInt8(ascii: ">") { i += 1; break }
                if hasPrefix("/>") { i += 2; selfClosing = true; break }
                let attr = readName()
                if attr.isEmpty { i += 1; continue }
                skipSpace()
                var value = ""
                if i < b.count && b[i] == UInt8(ascii: "=") {
                    i += 1
                    skipSpace()
                    if i < b.count && (b[i] == UInt8(ascii: "\"") || b[i] == UInt8(ascii: "'")) {
                        let q = b[i]
                        i += 1
                        let start = i
                        while i < b.count && b[i] != q { i += 1 }
                        value = decodeEntities(b[start..<i])
                        if i < b.count { i += 1 }
                    } else {
                        let start = i
                        while i < b.count && !isSpace(b[i]) && b[i] != UInt8(ascii: ">") { i += 1 }
                        value = decodeEntities(b[start..<i])
                    }
                }
                el.attributes[attr] = value
            }
            if selfClosing {
                stack[stack.count - 1].children.append(.element(el))
            } else {
                stack.append(el)
            }
        }
    }

    func isSpace(_ c: UInt8) -> Bool { c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D }

    mutating func skipSpace() { while i < b.count && isSpace(b[i]) { i += 1 } }

    mutating func readName() -> String {
        let start = i
        while i < b.count {
            let c = b[i]
            if isSpace(c) || c == UInt8(ascii: ">") || c == UInt8(ascii: "/") || c == UInt8(ascii: "=") || c == UInt8(ascii: "<") {
                break
            }
            i += 1
        }
        return String(decoding: b[start..<i], as: UTF8.self)
    }
}

func decodeEntities(_ bytes: ArraySlice<UInt8>) -> String {
    let s = String(decoding: bytes, as: UTF8.self)
    guard s.contains("&") else { return s }
    var out = ""
    var rest = Substring(s)
    while let amp = rest.firstIndex(of: "&") {
        out += rest[..<amp]
        let after = rest[rest.index(after: amp)...]
        if let semi = after.firstIndex(of: ";"), after.distance(from: after.startIndex, to: semi) <= 10 {
            let ent = after[..<semi]
            var decoded: String?
            switch ent {
            case "lt": decoded = "<"
            case "gt": decoded = ">"
            case "amp": decoded = "&"
            case "quot": decoded = "\""
            case "apos": decoded = "'"
            default:
                if ent.hasPrefix("#x") || ent.hasPrefix("#X"), let v = UInt32(ent.dropFirst(2), radix: 16), let u = Unicode.Scalar(v) {
                    decoded = String(Character(u))
                } else if ent.hasPrefix("#"), let v = UInt32(ent.dropFirst()), let u = Unicode.Scalar(v) {
                    decoded = String(Character(u))
                }
            }
            if let d = decoded {
                out += d
                rest = after[after.index(after: semi)...]
                continue
            }
        }
        out += "&"
        rest = after
    }
    out += rest
    return out
}
