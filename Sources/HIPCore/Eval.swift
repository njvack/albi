import Foundation

/// What a field reports when its state cannot be determined.
public let notAvailable = "n/a"

/// One volume's encryption state.
public struct Drive: Sendable, Equatable, Codable {
    public var name: String
    /// encrypted, unencrypted or unknown
    public var state: String
}

/// One field's result, with how it was found.
public struct Value: Sendable, Equatable, Codable {
    public var value: String
    public var drives: [Drive]?
    /// The probe and what it read.
    public var how: String
    /// Why a probe fell back, if it did.
    public var error: String?

    public init(_ value: String, how: String, error: String? = nil, drives: [Drive]? = nil) {
        self.value = value
        self.how = how
        self.error = error
        self.drives = drives
    }
}

/// A custom plist check's result.
public struct PlistResult: Sendable, Equatable, Codable {
    public var path: String
    public var exists: Bool
    public var keys: [KeyValue]
}

public struct KeyValue: Sendable, Equatable, Codable {
    public var key: String
    public var exists: Bool
    public var value: String
}

/// One check's evaluated result.
public struct Product: Sendable, Codable {
    public var id: String
    public var source: String
    public var trusted: Bool
    public var category: String
    public var vendor: String
    public var name: String
    public var fields: [String: Value]
    public var plist: PlistResult?
}

/// Carries the system and per-run caches into probes.
public final class Env {
    public let sys: System
    /// If set, receives every command and its output.
    public var debug: ((String) -> Void)?
    private var cache: [[String]: RunResult] = [:]

    public init(_ sys: System) { self.sys = sys }

    /// Runs a command once per Env and caches the result. Commands always
    /// go through here, so their stderr never reaches the report.
    public func run(_ argv: [String], timeout: TimeInterval = 0) -> RunResult {
        if let r = cache[argv] { return r }
        let r = sys.run(argv, timeout: timeout > 0 ? timeout : defaultTimeout)
        debug?("$ \(argv.joined(separator: " ")) (exit \(r.exitCode.map(String.init) ?? "none"))\n\(r.stdout)")
        cache[argv] = r
        return r
    }

    public func exists(_ path: String) -> Bool { sys.stat(path) != nil }

    public func readPlist(_ path: String) -> [String: Any]? {
        sys.readFile(path).flatMap(decodePlist)
    }

    /// CFBundleShortVersionString of an app or bundle.
    public func bundleVersion(_ bundle: String) -> (String, String?) {
        guard let m = readPlist(bundle + "/Contents/Info.plist") else {
            return ("", "cannot read \(bundle)/Contents/Info.plist")
        }
        guard let v = m["CFBundleShortVersionString"] as? String else {
            return ("", "no CFBundleShortVersionString")
        }
        return (v, nil)
    }

    /// The macOS product version, such as 27.1.
    public func osVersion() -> String {
        run(["/usr/bin/sw_vers", "-productVersion"]).stdout.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private lazy var running: Set<String> = Set(
        run(["/bin/ps", "-axo", "comm="]).stdout
            .split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty })

    // MARK: Probes

    public func eval(_ p: Probe) -> Value {
        if let v = p.value { return Value(v, how: "value") }
        var how = p.probe
        func result(_ v: String, _ err: String? = nil) -> Value { Value(v, how: how, error: err) }

        switch p.probe {
        case "bundle_version":
            how += " " + p.path
            let (v, err) = bundleVersion(p.path)
            return result(v, err)
        case "plist":
            how += " \(p.path) \(p.key)"
            guard let m = readPlist(p.path) else { return result("", "cannot read \(p.path)") }
            guard let raw = lookup(m, p.key) else { return result("", "no key \(p.key)") }
            guard let s = plistString(raw) else { return result("", "key \(p.key) is not a scalar") }
            return result(s)
        case "mtime":
            how += " " + p.path
            guard let st = sys.stat(p.path) else { return result("", "cannot stat \(p.path)") }
            return result(String(Int64(st.modified.timeIntervalSince1970.rounded(.down))))
        case "exists":
            how += " " + p.path
            return result(yesNo(exists(p.path)))
        case "process":
            how += " " + p.path
            return result(yesNo(running.contains(p.path)))
        case "launchd":
            var target = p.label
            if target.hasPrefix("gui/") {
                target = "gui/\(sys.uid())/" + target.dropFirst(4)
            }
            how += " " + target
            return result(yesNo(run(["/bin/launchctl", "print", target]).succeeded))
        case "command":
            how += " " + p.argv.joined(separator: " ")
            let r = run(p.argv, timeout: TimeInterval(p.timeout))
            for m in p.map {
                if let re = try? NSRegularExpression(pattern: m.match),
                   re.firstMatch(in: r.stdout, range: NSRange(r.stdout.startIndex..., in: r.stdout)) != nil {
                    return result(m.value)
                }
            }
            let why: String
            switch r.exitCode {
            case nil: why = "did not run or timed out"
            case 0: why = "output matched nothing"
            case let code?: why = "exit \(code), output matched nothing"
            }
            return result(p.defaultValue ?? notAvailable, why)
        case "os_version":
            return result(osVersion())
        case "volumes":
            let (drives, err) = volumes()
            return Value("", how: how, error: err, drives: drives)
        case "privileged":
            how += " " + p.fact
            guard let f = privilegedFacts[p.fact] else { return result(notAvailable, "unknown fact \(p.fact)") }
            guard sys.uid() == 0 else { return result(notAvailable, "needs root (the HIP helper)") }
            let (v, err) = f(self)
            return result(v, err)
        case "all":
            // yes if every part is yes; no if any is no; otherwise n/a.
            var state = "yes"
            var parts: [String] = []
            for sub in p.all {
                let v = eval(sub)
                parts.append("\(v.how)=\(v.value)")
                if v.value == "no" {
                    state = "no"
                } else if v.value != "yes" && state == "yes" {
                    state = notAvailable
                }
            }
            how += " [" + parts.joined(separator: "; ") + "]"
            return result(state)
        default:
            return result(notAvailable, "unknown probe \"\(p.probe)\"")
        }
    }

    /// Runs a check. Returns nil if its when condition says the product is
    /// not installed.
    public func evaluate(_ c: Check) -> Product? {
        for path in c.whenExists where !exists(path) { return nil }
        var p = Product(id: c.id, source: c.source, trusted: c.trusted, category: c.category,
                        vendor: c.vendor, name: c.name, fields: [:], plist: nil)
        if c.category == customPlist {
            p.plist = customPlistResult(c)
            return p
        }
        for f in HIPCore.category(named: c.category)?.fields ?? [] {
            if let probe = c.fields[f.name] {
                p.fields[f.name] = eval(probe)
            } else {
                p.fields[f.name] = Value(f.defaultValue, how: "default")
            }
        }
        return p
    }

    private func customPlistResult(_ c: Check) -> PlistResult {
        let m = readPlist(c.path)
        let keys = c.keys.map { k -> KeyValue in
            if let m, let raw = lookup(m, k), let s = plistString(raw) {
                return KeyValue(key: k, exists: true, value: s)
            }
            return KeyValue(key: k, exists: false, value: "")
        }
        return PlistResult(path: c.path, exists: exists(c.path), keys: keys)
    }

    // MARK: Volumes

    /// FileVault state for the boot volume, its Data half, and browsable
    /// internal disks under /Volumes, then an "All" entry: encrypted only if
    /// every one is, unencrypted if any is not, otherwise unknown.
    public func volumes() -> ([Drive], String?) {
        let r = run(["/sbin/mount"])
        if r.stdout.isEmpty {
            return ([Drive(name: "All", state: "unknown")], "mount gave no output")
        }
        var drives: [Drive] = []
        var all = "encrypted"
        for line in r.stdout.split(separator: "\n").map(String.init) {
            guard let (mp, flags) = parseMountLine(line), flags.contains("local") else { continue }
            let info = diskInfo(mp)
            let label: String
            if mp == "/" {
                label = info["VolumeName"].flatMap(plistString) ?? ""
            } else if mp == "/System/Volumes/Data" {
                label = "Data"
            } else if mp.hasPrefix("/Volumes/") {
                if flags.contains("nobrowse") || plistBool(info["Internal"]) != true { continue }
                label = (mp as NSString).lastPathComponent
            } else {
                continue
            }
            let state: String
            switch plistBool(info["FileVault"]) {
            case true?: state = "encrypted"
            case false?: state = "unencrypted"
            case nil: state = "unknown"
            }
            drives.append(Drive(name: label, state: state))
            if state == "unencrypted" {
                all = "unencrypted"
            } else if state == "unknown" && all != "unencrypted" {
                all = "unknown"
            }
        }
        let err = drives.isEmpty ? "no local volumes found" : nil
        return (drives + [Drive(name: "All", state: all)], err)
    }

    private func diskInfo(_ mp: String) -> [String: Any] {
        decodePlist(Data(run(["/usr/sbin/diskutil", "info", "-plist", mp]).stdout.utf8)) ?? [:]
    }
}

/// "DEV on MOUNTPOINT (flag, flag, ...)" as printed by mount(8).
func parseMountLine(_ line: String) -> (String, [String])? {
    guard line.hasSuffix(")"), let open = line.range(of: " (", options: .backwards),
          let on = line.range(of: " on ", range: line.startIndex..<open.lowerBound) else { return nil }
    let mp = String(line[on.upperBound..<open.lowerBound])
    let flags = line[open.upperBound..<line.index(before: line.endIndex)]
        .split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
    return mp.isEmpty ? nil : (mp, flags)
}

func yesNo(_ b: Bool) -> String { b ? "yes" : "no" }

/// Decodes plist data, XML or binary, whose root is a dictionary.
public func decodePlist(_ data: Data) -> [String: Any]? {
    (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
}

/// A dotted key path in a plist dictionary.
func lookup(_ m: [String: Any], _ key: String) -> Any? {
    var cur: Any = m
    for part in key.split(separator: ".", omittingEmptySubsequences: false) {
        guard let d = cur as? [String: Any], let next = d[String(part)] else { return nil }
        cur = next
    }
    return cur
}

/// A plist boolean; nil for anything else, including integers.
func plistBool(_ v: Any?) -> Bool? {
    guard let v, !(v is String), let n = v as? NSNumber, isBool(n) else { return nil }
    return n.boolValue
}

private func isBool(_ n: NSNumber) -> Bool {
    let t = String(cString: n.objCType)
    return t == "c" || t == "B"
}

/// A plist value rendered the way `plutil -extract KEY raw` does.
public func plistString(_ v: Any) -> String? {
    if let s = v as? String { return s }
    if let d = v as? Date {
        let f = ISO8601DateFormatter()
        f.timeZone = TimeZone(secondsFromGMT: 0)
        return f.string(from: d)
    }
    if let n = v as? NSNumber {
        if isBool(n) { return n.boolValue ? "true" : "false" }
        let t = String(cString: n.objCType)
        if t == "d" || t == "f" {
            let d = n.doubleValue
            return d == d.rounded() && abs(d) < 1e15 ? String(Int64(d)) : String(d)
        }
        return n.stringValue
    }
    return nil
}

/// Facts only root can read. They are answered in process when hipreport
/// runs as root (as it will inside the HIP helper), and reported as n/a
/// otherwise. None takes input from check files.
let privilegedFacts: [String: @Sendable (Env) -> (String, String?)] = [
    "pf.enabled": { env in
        let r = env.run(["/sbin/pfctl", "-s", "info"])
        if r.stdout.contains("Status: Enabled") { return ("yes", nil) }
        if r.stdout.contains("Status: Disabled") { return ("no", nil) }
        return (notAvailable, "pfctl gave no status")
    },
]
