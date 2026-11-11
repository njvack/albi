import Foundation
import TOMLDecoder

/// A System that answers from recorded data: a fixture file, written by
/// `hipreport record` or by hand. The format is shared with the Go reporter
/// in njvack/openconnect-hipreports.
public final class FakeSystem: System {
    public struct Command: Sendable {
        public var argv: [String]
        public var stdout: String
        public var exit: Int32

        public init(argv: [String], stdout: String = "", exit: Int32 = 0) {
            self.argv = argv
            self.stdout = stdout
            self.exit = exit
        }
    }

    public struct File: Sendable {
        public var path: String
        public var isDirectory = false
        public var missing = false
        public var content = ""
        /// Permission bits; 0 means 0o644, or 0o755 for a directory.
        public var mode: UInt32 = 0
        public var uid: UInt32 = 0
        public var gid: UInt32 = 0
        public var modified = Date(timeIntervalSince1970: 0)
        public var symlink: String?

        public init(path: String, isDirectory: Bool = false, missing: Bool = false, content: String = "",
                    mode: UInt32 = 0, uid: UInt32 = 0, gid: UInt32 = 0,
                    modified: Date = Date(timeIntervalSince1970: 0), symlink: String? = nil) {
            self.path = path
            self.isDirectory = isDirectory
            self.missing = missing
            self.content = content
            self.mode = mode
            self.uid = uid
            self.gid = gid
            self.modified = modified
            self.symlink = symlink
        }
    }

    public var host: String
    public var userID: UInt32
    public var time: Date
    public var zone: TimeZone
    public var commands: [Command]
    public var files: [File]

    public init(host: String = "", uid: UInt32 = 0, now: Date = Date(timeIntervalSince1970: 0),
                zone: TimeZone = TimeZone(secondsFromGMT: 0)!, commands: [Command] = [], files: [File] = []) {
        self.host = host
        self.userID = uid
        self.time = now
        self.zone = zone
        self.commands = commands
        self.files = files
    }

    public func run(_ argv: [String], timeout: TimeInterval) -> RunResult {
        guard let c = commands.first(where: { $0.argv == argv }) else {
            return RunResult(stdout: "", exitCode: nil)
        }
        return RunResult(stdout: c.stdout, exitCode: c.exit)
    }

    private func file(_ path: String) -> File? {
        let p = cleanPath(path)
        if let f = files.first(where: { cleanPath($0.path) == p }) {
            return f.missing ? nil : f
        }
        // A directory exists implicitly if any file lives under it.
        let prefix = p == "/" ? "/" : p + "/"
        if files.contains(where: { !$0.missing && cleanPath($0.path).hasPrefix(prefix) }) {
            return File(path: p, isDirectory: true)
        }
        return nil
    }

    private func resolve(_ path: String) -> File? {
        var p = path
        for _ in 0..<10 {
            guard let f = file(p) else { return nil }
            guard let target = f.symlink else { return f }
            p = target.hasPrefix("/") ? target : (dirname(p) as NSString).appendingPathComponent(target)
        }
        return nil
    }

    private func info(_ f: File) -> FileStat {
        var perm = f.mode & 0o777
        if f.mode == 0 { perm = f.isDirectory ? 0o755 : 0o644 }
        return FileStat(isDirectory: f.isDirectory && f.symlink == nil, isSymlink: f.symlink != nil,
                        permissions: perm, uid: f.uid, gid: f.gid, modified: f.modified)
    }

    public func readFile(_ path: String) -> Data? {
        guard let f = resolve(path), !f.isDirectory else { return nil }
        return Data(f.content.utf8)
    }

    public func stat(_ path: String) -> FileStat? { resolve(path).map(info) }
    public func lstat(_ path: String) -> FileStat? { file(path).map(info) }
    public func readlink(_ path: String) -> String? { file(path)?.symlink }
    public func hostname() -> String { host }
    public func uid() -> UInt32 { userID }
    public func now() -> Date { time }
    public func timeZone() -> TimeZone { zone }
}

func cleanPath(_ p: String) -> String {
    var parts: [String] = []
    for c in p.split(separator: "/", omittingEmptySubsequences: true) {
        switch c {
        case ".": continue
        case "..": if !parts.isEmpty { parts.removeLast() }
        default: parts.append(String(c))
        }
    }
    return "/" + parts.joined(separator: "/")
}

func dirname(_ p: String) -> String {
    let c = cleanPath(p)
    guard let slash = c.lastIndex(of: "/"), c != "/" else { return "/" }
    let d = String(c[..<slash])
    return d.isEmpty ? "/" : d
}

// MARK: - Fixture files

public struct FixtureError: Error, CustomStringConvertible {
    public var description: String
}

extension FakeSystem {
    /// Reads a fixture file.
    public static func load(fixture path: String) throws -> FakeSystem {
        guard let data = FileManager.default.contents(atPath: path) else {
            throw FixtureError(description: "\(path): cannot read")
        }
        return try parse(fixture: String(decoding: data, as: UTF8.self), name: path)
    }

    public static func parse(fixture text: String, name: String = "fixture") throws -> FakeSystem {
        let doc: [String: Any]
        do {
            doc = try [String: Any](TOMLTable(source: text))
        } catch {
            throw FixtureError(description: "\(name): \(error)")
        }
        let f = FakeSystem()
        f.host = doc["hostname"] as? String ?? ""
        f.userID = UInt32(doc["uid"] as? Int64 ?? 0)
        if let t = doc["now"] as? OffsetDateTime {
            f.time = Date(timeIntervalSince1970: t.timeIntervalSince1970)
            f.zone = TimeZone(secondsFromGMT: Int(t.offset) * 60) ?? f.zone
        }
        for c in doc["command"] as? [Any] ?? [] {
            guard let c = c as? [String: Any] else { continue }
            f.commands.append(Command(
                argv: (c["argv"] as? [Any] ?? []).compactMap { $0 as? String },
                stdout: c["stdout"] as? String ?? "",
                exit: Int32(c["exit"] as? Int64 ?? 0)))
        }
        for x in doc["file"] as? [Any] ?? [] {
            guard let x = x as? [String: Any], let p = x["path"] as? String else { continue }
            var file = File(path: p)
            file.isDirectory = x["dir"] as? Bool ?? false
            file.missing = x["missing"] as? Bool ?? false
            file.content = x["content"] as? String ?? ""
            file.mode = UInt32(x["mode"] as? Int64 ?? 0)
            file.uid = UInt32(x["owner_uid"] as? Int64 ?? 0)
            file.gid = UInt32(x["owner_gid"] as? Int64 ?? 0)
            if let t = x["mtime"] as? OffsetDateTime {
                file.modified = Date(timeIntervalSince1970: t.timeIntervalSince1970)
            }
            file.symlink = x["symlink"] as? String
            f.files.append(file)
        }
        return f
    }

    /// The fixture as TOML, in the format `parse` reads.
    public func fixtureText() -> String {
        var out = "hostname = \(tomlString(host))\nuid = \(userID)\nnow = \(tomlDate(time, zone: zone))\n"
        for c in commands {
            out += "\n[[command]]\nargv = [\(c.argv.map(tomlString).joined(separator: ", "))]\n"
            out += "stdout = \(tomlString(c.stdout))\n"
            if c.exit != 0 { out += "exit = \(c.exit)\n" }
        }
        for f in files {
            out += "\n[[file]]\npath = \(tomlString(f.path))\n"
            if f.missing {
                out += "missing = true\n"
                continue
            }
            if f.isDirectory { out += "dir = true\n" }
            if f.mode != 0 { out += "mode = \(f.mode)\n" }
            out += "owner_uid = \(f.uid)\nowner_gid = \(f.gid)\nmtime = \(tomlDate(f.modified, zone: zone))\n"
            if let s = f.symlink { out += "symlink = \(tomlString(s))\n" }
            if !f.content.isEmpty { out += "content = \(tomlString(f.content))\n" }
        }
        return out
    }
}

func tomlString(_ s: String) -> String {
    var out = "\""
    for u in s.unicodeScalars {
        switch u {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        case "\n": out += "\\n"
        case "\t": out += "\\t"
        case "\r": out += "\\r"
        default:
            if u.value < 0x20 || u.value == 0x7f {
                out += String(format: "\\u%04X", u.value)
            } else {
                out.unicodeScalars.append(u)
            }
        }
    }
    return out + "\""
}

func tomlDate(_ d: Date, zone: TimeZone) -> String {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.timeZone = zone
    f.dateFormat = "yyyy-MM-dd'T'HH:mm:ssXXXXX"
    return f.string(from: d)
}

// MARK: - Recording

/// Wraps a System and remembers every answer it gives, so a run on a real
/// Mac can be replayed in tests as a FakeSystem.
public final class Recorder: System {
    private let inner: System
    public let recording: FakeSystem

    public init(_ inner: System) {
        self.inner = inner
        recording = FakeSystem(host: inner.hostname(), uid: inner.uid(),
                               now: Date(timeIntervalSince1970: inner.now().timeIntervalSince1970.rounded(.down)),
                               zone: inner.timeZone())
    }

    public func run(_ argv: [String], timeout: TimeInterval) -> RunResult {
        let r = inner.run(argv, timeout: timeout)
        if !recording.commands.contains(where: { $0.argv == argv }) {
            recording.commands.append(.init(argv: argv, stdout: r.stdout, exit: r.exitCode ?? 127))
        }
        return r
    }

    private func note(_ path: String, _ st: FileStat?, content: Data?) {
        if let i = recording.files.firstIndex(where: { $0.path == path }) {
            if let content { recording.files[i].content = textForFixture(content) }
            return
        }
        var f = FakeSystem.File(path: path)
        if let st {
            f.isDirectory = st.isDirectory
            f.mode = st.permissions
            f.uid = st.uid
            f.gid = st.gid
            f.modified = st.modified
        } else {
            f.missing = true
        }
        if let content { f.content = textForFixture(content) }
        recording.files.append(f)
    }

    public func readFile(_ path: String) -> Data? {
        let d = inner.readFile(path)
        note(path, inner.stat(path), content: d)
        return d
    }

    public func stat(_ path: String) -> FileStat? {
        let s = inner.stat(path)
        note(path, s, content: nil)
        return s
    }

    public func lstat(_ path: String) -> FileStat? { inner.lstat(path) }
    public func readlink(_ path: String) -> String? { inner.readlink(path) }
    public func hostname() -> String { recording.host }
    public func uid() -> UInt32 { recording.userID }
    public func now() -> Date { recording.time }
    public func timeZone() -> TimeZone { recording.zone }
}

/// Fixtures are text, so a binary plist is stored as the equivalent XML plist.
func textForFixture(_ data: Data) -> String {
    if data.starts(with: Array("bplist".utf8)),
       let obj = try? PropertyListSerialization.propertyList(from: data, format: nil),
       let xml = try? PropertyListSerialization.data(fromPropertyList: obj, format: .xml, options: 0) {
        return String(decoding: xml, as: UTF8.self)
    }
    return String(decoding: data, as: UTF8.self)
}
