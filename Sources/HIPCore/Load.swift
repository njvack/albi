import Foundation

/// A place checks come from.
public struct Source: Sendable {
    /// A directory on disk; nil means the built-in library.
    public var dir: String?
    /// Load without trust checks, and mark results untrusted.
    public var dev: Bool

    public init(dir: String? = nil, dev: Bool = false) {
        self.dir = dir
        self.dev = dev
    }

    public static let builtin = Source()
}

/// The checks that will run, in report order.
public struct CheckSet: Sendable {
    public var checks: [Check] = []
    /// False if any check came from a dev source.
    public var trusted = true

    public init(checks: [Check] = [], trusted: Bool = true) {
        self.checks = checks
        self.trusted = trusted
    }
}

/// Reads every source in order. A file in a later source replaces one with
/// the same relative path in an earlier source, so a local file can fix or
/// (with disabled = true) remove a built-in one. Missing directories are
/// skipped; files that fail trust checks or validation are skipped and
/// returned as errors.
public func loadChecks(_ sys: System, _ sources: [Source]) -> (CheckSet, [CheckError]) {
    var byID: [String: Check] = [:]
    var errs: [CheckError] = []
    var set = CheckSet()
    for src in sources {
        let (checks, e) = loadSource(sys, src)
        errs += e
        for c in checks {
            byID[c.id] = c
            if src.dev { set.trusted = false }
        }
    }
    set.checks = byID.values.filter { !$0.disabled }.sorted { a, b in
        let (ra, rb) = (categoryRank(a.category), categoryRank(b.category))
        if ra != rb { return ra < rb }
        let (ba, bb) = ((a.id as NSString).lastPathComponent, (b.id as NSString).lastPathComponent)
        if ba != bb { return ba < bb }
        return a.id < b.id
    }
    return (set, errs)
}

func loadSource(_ sys: System, _ src: Source) -> ([Check], [CheckError]) {
    var files: [(id: String, where: String, text: String?)] = []
    var errs: [CheckError] = []

    if let dir = src.dir {
        let abs = cleanPath(dir.hasPrefix("/") ? dir : FileManager.default.currentDirectoryPath + "/" + dir)
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: abs, isDirectory: &isDir) else { return ([], []) }
        guard isDir.boolValue else { return ([], [CheckError("\(abs): not a directory")]) }
        if !src.dev, let e = checkTrusted(sys, abs) { return ([], [e]) }
        let rels = (FileManager.default.enumerator(atPath: abs)?.allObjects as? [String] ?? [])
            .filter { $0.hasSuffix(".toml") }.sorted()
        for rel in rels {
            let full = abs + "/" + rel
            if !src.dev, let e = checkTrusted(sys, full) {
                errs.append(e)
                continue
            }
            files.append((rel, full, FileManager.default.contents(atPath: full).map { String(decoding: $0, as: UTF8.self) }))
        }
    } else {
        files = builtinLibrary.map { ($0.path, "built-in:" + $0.path, $0.text) }
    }

    var checks: [Check] = []
    for f in files {
        guard let text = f.text else {
            errs.append(CheckError("\(f.where): cannot read"))
            continue
        }
        var c: Check
        do {
            c = try Check.parse(text)
        } catch {
            errs.append(CheckError("\(f.where): \(error)"))
            continue
        }
        c.id = f.id
        c.source = f.where
        c.trusted = !src.dev
        if !c.disabled {
            let ve = c.validate()
            if !ve.isEmpty {
                errs += ve.map { CheckError("\(f.where): \($0)") }
                continue
            }
        }
        checks.append(c)
    }
    return (checks, errs)
}

/// Refuses a path unless it and every directory above it are owned by root
/// and writable by nobody else, the way sudo treats sudoers. A
/// group-writable directory is allowed only if its group is wheel (0).
/// Symlinks are followed, and the target is held to the same rule.
/// Returns nil if the path is trusted.
public func checkTrusted(_ sys: System, _ path: String) -> CheckError? {
    guard path.hasPrefix("/") else { return CheckError("\(path): not an absolute path") }
    var budget = 64
    func check(_ p: String) -> CheckError? {
        budget -= 1
        if budget < 0 { return CheckError("\(p): too many symlinks") }
        var cur = cleanPath(p)
        while true {
            guard let st = sys.lstat(cur) else { return CheckError("\(cur): does not exist") }
            if st.uid != 0 {
                return CheckError("\(cur): untrusted, owned by uid \(st.uid), not root")
            }
            if !st.isSymlink {
                if st.permissions & 0o002 != 0 { return CheckError("\(cur): untrusted, writable by anyone") }
                if st.permissions & 0o020 != 0 && st.gid != 0 {
                    return CheckError("\(cur): untrusted, writable by group \(st.gid)")
                }
            } else {
                guard var target = sys.readlink(cur) else { return CheckError("\(cur): cannot read link") }
                if !target.hasPrefix("/") { target = dirname(cur) + "/" + target }
                if let e = check(target) { return e }
            }
            if cur == "/" { return nil }
            cur = dirname(cur)
        }
    }
    return check(path)
}
