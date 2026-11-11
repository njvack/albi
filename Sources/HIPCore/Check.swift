import Foundation
import TOMLDecoder

/// Says how to find one field's value.
public struct Probe: Sendable, Equatable {
    public var probe = ""
    /// A constant; no probe.
    public var value: String?
    public var path = ""
    public var key = ""
    public var label = ""
    public var fact = ""
    public var argv: [String] = []
    public var map: [MapEntry] = []
    public var defaultValue: String?
    /// Seconds; 0 means the default.
    public var timeout = 0
    public var all: [Probe] = []

    public init(probe: String = "", value: String? = nil, path: String = "", key: String = "", label: String = "",
                fact: String = "", argv: [String] = [], map: [MapEntry] = [], defaultValue: String? = nil,
                timeout: Int = 0, all: [Probe] = []) {
        self.probe = probe
        self.value = value
        self.path = path
        self.key = key
        self.label = label
        self.fact = fact
        self.argv = argv
        self.map = map
        self.defaultValue = defaultValue
        self.timeout = timeout
        self.all = all
    }
}

/// Maps command output matching a regular expression to a value.
public struct MapEntry: Sendable, Equatable {
    public var match: String
    public var value: String

    public init(match: String, value: String) {
        self.match = match
        self.value = value
    }
}

/// One parsed check file: one product in one HIP category.
///
/// A check names its vendor and product, an optional condition for
/// reporting it at all, and one probe per field the category needs.
/// Probes are a fixed vocabulary; check files cannot run code except
/// through the command probe, which takes an absolute path and runs it
/// with a fixed environment and a timeout.
public struct Check: Sendable {
    public var category = ""
    public var vendor = ""
    public var name = ""
    public var disabled = false
    /// Every path must exist for the product to be reported.
    public var whenExists: [String] = []
    public var fields: [String: Probe] = [:]

    // custom-plist only
    public var path = ""
    public var keys: [String] = []

    /// Path relative to its source; a later source's file with the same ID replaces it.
    public var id = ""
    /// Where it was loaded from, for messages.
    public var source = ""
    public var trusted = true

    public init() {}
}

public struct CheckError: Error, CustomStringConvertible, Equatable {
    public var description: String
    public init(_ description: String) { self.description = description }
}

/// Probe names and the parameters each requires.
let probeParams: [String: [String]] = [
    "bundle_version": ["path"],
    "plist": ["path", "key"],
    "mtime": ["path"],
    "exists": ["path"],
    "process": ["path"],
    "launchd": ["label"],
    "command": ["argv", "map"],
    "volumes": [],
    "os_version": [],
    "privileged": ["fact"],
    "all": ["all"],
]

// MARK: - Parsing

extension Check {
    /// Parses one check file, rejecting unknown keys and wrong types.
    public static func parse(_ text: String) throws -> Check {
        let doc: [String: Any]
        do {
            doc = try [String: Any](TOMLTable(source: text))
        } catch {
            throw CheckError("\(error)")
        }
        var r = Reader(doc, at: "")
        var c = Check()
        c.category = try r.string("category") ?? ""
        c.vendor = try r.string("vendor") ?? ""
        c.name = try r.string("name") ?? ""
        c.disabled = try r.bool("disabled") ?? false
        c.path = try r.string("path") ?? ""
        c.keys = try r.strings("keys") ?? []
        if let w = try r.table("when") {
            var wr = Reader(w, at: "when.")
            c.whenExists = try wr.stringOrStrings("exists") ?? []
            try wr.finish()
        }
        if let f = try r.table("fields") {
            for (name, raw) in f {
                guard let t = raw as? [String: Any] else {
                    throw CheckError("fields.\(name): expected a table such as { value = \"yes\" } or { probe = \"...\" }")
                }
                c.fields[name] = try parseProbe(t, at: "fields.\(name).")
            }
        }
        try r.finish()
        return c
    }

    static func parseProbe(_ t: [String: Any], at prefix: String) throws -> Probe {
        var r = Reader(t, at: prefix)
        var p = Probe()
        p.probe = try r.string("probe") ?? ""
        p.value = try r.string("value")
        p.path = try r.string("path") ?? ""
        p.key = try r.string("key") ?? ""
        p.label = try r.string("label") ?? ""
        p.fact = try r.string("fact") ?? ""
        p.argv = try r.strings("argv") ?? []
        p.defaultValue = try r.string("default")
        p.timeout = try r.int("timeout") ?? 0
        if let m = try r.tables("map") {
            for (i, e) in m.enumerated() {
                var er = Reader(e, at: "\(prefix)map[\(i)].")
                p.map.append(MapEntry(match: try er.string("match") ?? "", value: try er.string("value") ?? ""))
                try er.finish()
            }
        }
        if let a = try r.tables("all") {
            p.all = try a.enumerated().map { try parseProbe($1, at: "\(prefix)all[\($0)].") }
        }
        try r.finish()
        return p
    }
}

/// Typed access to a TOML table that remembers which keys were read, so
/// unknown keys can be reported.
struct Reader {
    let t: [String: Any]
    let prefix: String
    var used: Set<String> = []

    init(_ t: [String: Any], at prefix: String) {
        self.t = t
        self.prefix = prefix
    }

    private mutating func get(_ k: String) -> Any? {
        used.insert(k)
        return t[k]
    }

    private func wrong(_ k: String, _ want: String) -> CheckError {
        CheckError("\(prefix)\(k): expected \(want)")
    }

    mutating func string(_ k: String) throws -> String? {
        guard let v = get(k) else { return nil }
        guard let s = v as? String else { throw wrong(k, "a string") }
        return s
    }

    mutating func bool(_ k: String) throws -> Bool? {
        guard let v = get(k) else { return nil }
        guard let b = v as? Bool else { throw wrong(k, "true or false") }
        return b
    }

    mutating func int(_ k: String) throws -> Int? {
        guard let v = get(k) else { return nil }
        guard let n = v as? Int64 else { throw wrong(k, "an integer") }
        return Int(n)
    }

    mutating func strings(_ k: String) throws -> [String]? {
        guard let v = get(k) else { return nil }
        guard let a = v as? [Any], let s = a as? [String], s.count == a.count else {
            throw wrong(k, "an array of strings")
        }
        return s
    }

    mutating func stringOrStrings(_ k: String) throws -> [String]? {
        if let s = t[k] as? String {
            used.insert(k)
            return [s]
        }
        return try strings(k)
    }

    mutating func table(_ k: String) throws -> [String: Any]? {
        guard let v = get(k) else { return nil }
        guard let d = v as? [String: Any] else { throw wrong(k, "a table") }
        return d
    }

    mutating func tables(_ k: String) throws -> [[String: Any]]? {
        guard let v = get(k) else { return nil }
        guard let a = v as? [Any], let d = a as? [[String: Any]], d.count == a.count else {
            throw wrong(k, "an array of tables")
        }
        return d
    }

    func finish() throws {
        let unknown = Set(t.keys).subtracting(used).sorted()
        if !unknown.isEmpty {
            throw CheckError("unknown keys: \(unknown.map { prefix + $0 }.joined(separator: ", "))")
        }
    }
}

// MARK: - Validation

extension Check {
    /// Every problem with a check, in the order found.
    public func validate() -> [CheckError] {
        var errs: [CheckError] = []
        func bad(_ s: String) { errs.append(CheckError(s)) }

        if category == customPlist {
            if !path.hasPrefix("/") { bad("custom-plist needs an absolute path") }
            if !fields.isEmpty { bad("custom-plist takes path and keys, not fields") }
            if keys.contains("") { bad("empty key") }
            return errs
        }
        guard let def = HIPCore.category(named: category) else {
            let names = (categories.map(\.name) + [customPlist]).joined(separator: ", ")
            bad("unknown category \"\(category)\" (want one of \(names))")
            return errs
        }
        if vendor.isEmpty { bad("missing vendor") }
        if name.isEmpty { bad("missing name") }
        if !path.isEmpty || !keys.isEmpty { bad("path and keys are only for custom-plist") }
        for p in whenExists where !p.hasPrefix("/") {
            bad("when.exists: \"\(p)\" is not an absolute path")
        }
        for f in def.fields where f.required && fields[f.name] == nil {
            bad("\(category) needs field \"\(f.name)\"")
        }
        for (name, p) in fields.sorted(by: { $0.key < $1.key }) {
            guard let f = def.field(name) else {
                bad("\(category) has no field \"\(name)\"")
                continue
            }
            for e in p.validate() { bad("field \(name): \(e)") }
            if f.drives != (p.probe == "volumes") {
                bad(f.drives ? "field \(name): needs the volumes probe"
                    : "field \(name): the volumes probe only fits a drives field")
            }
        }
        return errs
    }
}

extension Probe {
    func validate() -> [CheckError] {
        var errs: [CheckError] = []
        func bad(_ s: String) { errs.append(CheckError(s)) }

        if value != nil {
            if !probe.isEmpty { bad("give either value or probe, not both") }
            return errs
        }
        guard let params = probeParams[probe] else {
            bad(probe.isEmpty ? "needs a probe or a value" : "unknown probe \"\(probe)\"")
            return errs
        }
        let has: [String: Bool] = [
            "path": !path.isEmpty, "key": !key.isEmpty, "label": !label.isEmpty, "fact": !fact.isEmpty,
            "argv": !argv.isEmpty, "map": !map.isEmpty, "all": !all.isEmpty,
        ]
        for k in params where has[k] != true { bad("probe \(probe) needs \(k)") }
        for (k, v) in has.sorted(by: { $0.key < $1.key }) where v && !params.contains(k) {
            bad("probe \(probe) does not take \(k)")
        }
        if defaultValue != nil && probe != "command" { bad("only the command probe takes a default") }
        if timeout != 0 && probe != "command" { bad("only the command probe takes a timeout") }
        if !path.isEmpty && !path.hasPrefix("/") { bad("path \"\(path)\" is not absolute") }
        if let exe = argv.first, !exe.hasPrefix("/") { bad("command \"\(exe)\" is not an absolute path") }
        for m in map {
            do {
                _ = try NSRegularExpression(pattern: m.match)
            } catch {
                bad("map: invalid regular expression \"\(m.match)\"")
            }
        }
        if !label.isEmpty && !label.contains("/") {
            bad("launchd label \"\(label)\" needs a domain, such as system/\(label) or gui/\(label)")
        }
        if !fact.isEmpty && privilegedFacts[fact] == nil { bad("unknown privileged fact \"\(fact)\"") }
        for (i, sub) in all.enumerated() {
            if sub.probe == "all" || sub.probe == "volumes" { bad("all: \(sub.probe) cannot be nested") }
            for e in sub.validate() { bad("all[\(i)]: \(e)") }
        }
        return errs
    }
}
