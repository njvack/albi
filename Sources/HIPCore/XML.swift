/// A minimal XML element: attributes in order, and either text or
/// children. `document` serializes it the way `xmllint --format` does, so
/// the output can be compared with hipreport.zsh's byte for byte.
public final class Node {
    public var name: String
    public var attrs: [(String, String)]
    public var text: String
    public var children: [Node]

    public init(_ name: String, attrs: [(String, String)] = [], text: String = "", _ children: [Node] = []) {
        self.name = name
        self.attrs = attrs
        self.text = text
        self.children = children
    }

    static func text(_ name: String, _ text: String) -> Node { Node(name, text: text) }

    /// GP's <entry name="..."> wrapper.
    static func entry(_ name: String, _ children: [Node] = []) -> Node {
        Node("entry", attrs: [("name", name)], children)
    }

    @discardableResult
    func add(_ more: Node...) -> Node {
        children += more
        return self
    }

    public var document: String {
        var out = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        write(&out, depth: 0)
        return out
    }

    private func write(_ out: inout String, depth: Int) {
        let pad = String(repeating: "  ", count: depth)
        out += pad + "<" + name
        for (k, v) in attrs { out += " \(k)=\"\(escapeAttr(v))\"" }
        if !children.isEmpty {
            out += ">\n"
            for c in children { c.write(&out, depth: depth + 1) }
            out += pad + "</\(name)>\n"
        } else if !text.isEmpty {
            out += ">\(escapeText(text))</\(name)>\n"
        } else {
            out += "/>\n"
        }
    }
}

/// Drops characters XML 1.0 cannot carry at all.
private func valid(_ s: String) -> String.UnicodeScalarView {
    String.UnicodeScalarView(s.unicodeScalars.filter { u in
        u == "\t" || u == "\n" || u == "\r" || (u.value >= 0x20 && u.value != 0xFFFE && u.value != 0xFFFF)
    })
}

func escapeText(_ s: String) -> String {
    var out = ""
    for u in valid(s) {
        switch u {
        case "&": out += "&amp;"
        case "<": out += "&lt;"
        case ">": out += "&gt;"
        case "\r": out += "&#13;"
        default: out.unicodeScalars.append(u)
        }
    }
    return out
}

func escapeAttr(_ s: String) -> String {
    var out = ""
    for u in valid(s) {
        switch u {
        case "&": out += "&amp;"
        case "<": out += "&lt;"
        case ">": out += "&gt;"
        case "\"": out += "&quot;"
        case "\n": out += "&#10;"
        case "\r": out += "&#13;"
        case "\t": out += "&#9;"
        default: out.unicodeScalars.append(u)
        }
    }
    return out
}
