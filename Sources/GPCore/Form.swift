/// An ordered list of `application/x-www-form-urlencoded` fields.
///
/// Encoding matches openconnect's `buf_append_urlencoded`: only ASCII letters,
/// digits and `-_.~` pass through; everything else becomes lowercase `%xx`.
public struct Form: Equatable, Sendable, ExpressibleByDictionaryLiteral {
    public var fields: [(name: String, value: String)]

    public init(_ fields: [(String, String)] = []) {
        self.fields = fields.map { (name: $0.0, value: $0.1) }
    }

    public init(dictionaryLiteral elements: (String, String)...) {
        self.init(elements)
    }

    public mutating func append(_ name: String, _ value: String?) {
        if let value { fields.append((name: name, value: value)) }
    }

    public mutating func append(contentsOf other: Form) {
        fields += other.fields
    }

    /// The first value for `name`.
    public subscript(name: String) -> String? {
        fields.first { $0.name == name }?.value
    }

    /// A copy without the named fields.
    public func removing(_ names: Set<String>) -> Form {
        var f = self
        f.fields.removeAll { names.contains($0.name) }
        return f
    }

    /// A copy with only the named fields, in their original order.
    public func keeping(_ names: Set<String>) -> Form {
        var f = self
        f.fields.removeAll { !names.contains($0.name) }
        return f
    }

    public var encoded: String {
        fields.map { Form.escape($0.name) + "=" + Form.escape($0.value) }.joined(separator: "&")
    }

    public static func escape(_ s: String) -> String {
        var out = ""
        let hex = Array("0123456789abcdef")
        for c in s.utf8 {
            switch c {
            case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"),
                 UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "-"), UInt8(ascii: "_"),
                 UInt8(ascii: "."), UInt8(ascii: "~"):
                out.append(Character(Unicode.Scalar(c)))
            default:
                out.append("%")
                out.append(hex[Int(c >> 4)])
                out.append(hex[Int(c & 0xF)])
            }
        }
        return out
    }

    /// Decodes `%xx` escapes and `+` as space. Invalid escapes are kept as is.
    public static func unescape(_ s: String) -> String {
        var bytes: [UInt8] = []
        let u = Array(s.utf8)
        var i = 0
        while i < u.count {
            if u[i] == UInt8(ascii: "%"), i + 2 < u.count, let h = hexValue(u[i + 1]), let l = hexValue(u[i + 2]) {
                bytes.append(h << 4 | l)
                i += 3
            } else if u[i] == UInt8(ascii: "+") {
                bytes.append(0x20)
                i += 1
            } else {
                bytes.append(u[i])
                i += 1
            }
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// Parses an encoded form.
    public static func parse(_ s: String) -> Form {
        Form(s.split(separator: "&").map { part in
            let kv = part.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            return (unescape(String(kv[0])), kv.count > 1 ? unescape(String(kv[1])) : "")
        })
    }

    private static func hexValue(_ c: UInt8) -> UInt8? {
        switch c {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): c - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): c - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): c - UInt8(ascii: "A") + 10
        default: nil
        }
    }

    public static func == (a: Form, b: Form) -> Bool {
        a.fields.map(\.name) == b.fields.map(\.name) && a.fields.map(\.value) == b.fields.map(\.value)
    }
}
