import Foundation
import TOMLDecoder

/// What the gateway is expected to require. The gateway never says pass or
/// fail, so the expectations come from the firewall admins, written down as
/// a policy file. Each requirement must be met by some product.
public struct Policy: Sendable {
    public var require: [Requirement]

    /// Matches products by category (and optionally vendor and name) and
    /// tests one field. With no test, a matching product being present is
    /// enough. Field "drive:NAME" tests a disk-encryption drive's state, for
    /// example drive:All.
    public struct Requirement: Sendable {
        public var description = ""
        public var category = ""
        public var vendor = ""
        public var name = ""
        public var field = ""
        public var equals = ""
        public var matches = ""
        public var minVersion = ""
    }

    public struct Result: Sendable, Codable {
        public var requirement: String
        public var pass: Bool
        /// One line per product examined, or why none matched.
        public var detail: [String]
    }

    public static func parse(_ text: String) throws -> Policy {
        let doc: [String: Any]
        do {
            doc = try [String: Any](TOMLTable(source: text))
        } catch {
            throw CheckError("\(error)")
        }
        var r = Reader(doc, at: "")
        var reqs: [Requirement] = []
        for (i, t) in (try r.tables("require") ?? []).enumerated() {
            var rr = Reader(t, at: "require[\(i)].")
            var q = Requirement()
            q.description = try rr.string("description") ?? ""
            q.category = try rr.string("category") ?? ""
            q.vendor = try rr.string("vendor") ?? ""
            q.name = try rr.string("name") ?? ""
            q.field = try rr.string("field") ?? ""
            q.equals = try rr.string("equals") ?? ""
            q.matches = try rr.string("matches") ?? ""
            q.minVersion = try rr.string("min_version") ?? ""
            try rr.finish()
            if q.category.isEmpty { throw CheckError("require[\(i)]: missing category") }
            if !(q.equals + q.matches + q.minVersion).isEmpty && q.field.isEmpty {
                throw CheckError("require[\(i)]: a test needs a field")
            }
            if !q.matches.isEmpty && (try? NSRegularExpression(pattern: q.matches)) == nil {
                throw CheckError("require[\(i)]: invalid regular expression \"\(q.matches)\"")
            }
            reqs.append(q)
        }
        try r.finish()
        return Policy(require: reqs)
    }

    public func check(_ products: [Product]) -> [Result] {
        require.map { q in
            var pass = false
            var detail: [String] = []
            for p in products where p.category == q.category
                && (q.vendor.isEmpty || p.vendor == q.vendor) && (q.name.isEmpty || p.name == q.name) {
                let label = (p.vendor + " " + p.name).trimmingCharacters(in: .whitespaces)
                if q.field.isEmpty {
                    pass = true
                    detail.append("\(label): present (\(p.source))")
                    continue
                }
                guard let v = fieldValue(p, q.field) else {
                    detail.append("\(label): no field \(q.field)")
                    continue
                }
                if q.test(v.value) { pass = true }
                var line = "\(label): \(q.field) = \"\(v.value)\" via \(v.how)"
                if let e = v.error { line += " (\(e))" }
                detail.append(line)
            }
            if detail.isEmpty { detail = ["no matching product reported"] }
            return Result(requirement: q.summary, pass: pass, detail: detail)
        }
    }

    private func fieldValue(_ p: Product, _ field: String) -> Value? {
        if field.hasPrefix("drive:") {
            let name = String(field.dropFirst("drive:".count))
            guard let d = p.fields["drives"], let drive = d.drives?.first(where: { $0.name == name }) else { return nil }
            return Value(drive.state, how: d.how)
        }
        return p.fields[field]
    }
}

extension Policy.Requirement {
    var summary: String {
        if !description.isEmpty { return description }
        var s = [category, vendor, name, field].filter { !$0.isEmpty }.joined(separator: " ")
        if !equals.isEmpty { s += " = " + equals }
        else if !matches.isEmpty { s += " ~ " + matches }
        else if !minVersion.isEmpty { s += " >= " + minVersion }
        else { s += " present" }
        return s
    }

    func test(_ v: String) -> Bool {
        if !equals.isEmpty { return v == equals }
        if !matches.isEmpty {
            guard let re = try? NSRegularExpression(pattern: matches) else { return false }
            return re.firstMatch(in: v, range: NSRange(v.startIndex..., in: v)) != nil
        }
        if !minVersion.isEmpty { return compareVersions(v, minVersion) >= 0 }
        return true
    }
}

/// Compares dotted numeric versions such as 5329 or 27.1.2. A non-numeric
/// part compares as text; a missing part counts as 0.
public func compareVersions(_ a: String, _ b: String) -> Int {
    if a.isEmpty { return -1 }
    let sep: (Character) -> Bool = { $0 == "." || $0 == "-" || $0 == "_" }
    let pa = a.split(whereSeparator: sep).map(String.init), pb = b.split(whereSeparator: sep).map(String.init)
    for i in 0..<max(pa.count, pb.count) {
        let x = i < pa.count ? pa[i] : "0", y = i < pb.count ? pb[i] : "0"
        if let nx = UInt64(x), let ny = UInt64(y) {
            if nx != ny { return nx < ny ? -1 : 1 }
        } else if x != y {
            return x < y ? -1 : 1
        }
    }
    return 0
}
