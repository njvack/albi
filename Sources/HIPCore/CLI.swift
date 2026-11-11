import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// The name of the user running us, when USER is unset.
func loginName() -> String {
    guard let pw = getpwuid(getuid()), let name = pw.pointee.pw_name else { return "" }
    return String(cString: name)
}

/// Local check files. Must be owned by root and writable by nobody else.
public let defaultChecksDir = "/Library/Application Support/Albi/checks.d"

public let usage = """
usage:
  hipreport [--md5 X --cookie X ...]   write a HIP report (openconnect --csd-wrapper compatible)
  hipreport facts [--json]             what each check found, and how
  hipreport check --policy FILE [--json]  compare facts with an expected policy
  hipreport lint [PATH...]             validate check files
  hipreport record [-o FILE]           record this machine as a test fixture
  hipreport version

options:
  --checks-dir DIR         trusted check directory (repeatable; default \(defaultChecksDir))
  --dev-checks DIR         load checks without trust checks; output is marked untrusted
  --no-builtin             skip the built-in check library
  --host-id-interface DEV  interface whose MAC is the host-id (default en0)
  --fixture FILE           answer from a recorded fixture instead of this machine
  --debug                  log commands and their output to stderr (or HIPREPORT_DEBUG=1)

"""

public let hipreportVersion = "0.1.0"

/// The hipreport command line. Output goes to `out` and `err`; the result
/// is the exit status.
public struct CLI {
    public var system: System
    public var environment: [String: String]
    public var out: (String) -> Void
    public var err: (String) -> Void

    public init(system: System, environment: [String: String],
                out: @escaping (String) -> Void, err: @escaping (String) -> Void) {
        self.system = system
        self.environment = environment
        self.out = out
        self.err = err
    }

    struct Options {
        var req = Request()
        var checksDirs: [String] = []
        var devDirs: [String] = []
        var noBuiltin = false
        var debug = false
        var json = false
        var policy = ""
        var output = ""
        var fixture = ""
        var rest: [String] = []
    }

    /// Lenient: openconnect may grow new options, and a HIP report should
    /// still go out, so unknown options are warned about and skipped.
    func parse(_ args: [String]) throws -> Options {
        var o = Options()
        let valueFlags: [String: (inout Options, String) -> Void] = [
            "--cookie": { $0.req.cookie = $1 },
            "--client-ip": { $0.req.clientIP = $1 },
            "--client-ipv6": { $0.req.clientIPv6 = $1 },
            "--md5": { $0.req.md5 = $1 },
            "--client-os": { $0.req.clientOS = $1 },
            "--client-version": { $0.req.clientVersion = $1 },
            "--host-id-interface": { $0.req.hostIDDevice = $1 },
            "--checks-dir": { $0.checksDirs.append($1) },
            "--dev-checks": { $0.devDirs.append($1) },
            "--policy": { $0.policy = $1 },
            "-o": { $0.output = $1 },
            "--fixture": { $0.fixture = $1 },
        ]
        var i = 0
        while i < args.count {
            let a = args[i]
            let (name, inline): (String, String?) = {
                guard let eq = a.firstIndex(of: "="), a.hasPrefix("-") else { return (a, nil) }
                return (String(a[..<eq]), String(a[a.index(after: eq)...]))
            }()
            if let set = valueFlags[name] {
                var v = inline
                if v == nil {
                    guard i + 1 < args.count else { throw CheckError("\(name) needs a value") }
                    i += 1
                    v = args[i]
                }
                set(&o, v!)
            } else if a == "--debug" {
                o.debug = true
            } else if a == "--json" {
                o.json = true
            } else if a == "--no-builtin" {
                o.noBuiltin = true
            } else if a.hasPrefix("-") {
                err("hipreport: ignoring unknown option \(a)\n")
                if inline == nil, i + 1 < args.count, !args[i + 1].hasPrefix("-") { i += 1 }
            } else {
                o.rest.append(a)
            }
            i += 1
        }
        if environment["HIPREPORT_DEBUG"] == "1" { o.debug = true }
        // openconnect passes its --version-string here.
        if o.req.clientVersion.isEmpty { o.req.clientVersion = environment["APP_VERSION"] ?? "" }
        if o.checksDirs.isEmpty { o.checksDirs = [defaultChecksDir] }
        return o
    }

    public func run(_ argv: [String]) -> Int32 {
        var args = argv
        var cmd = "report"
        if let first = args.first, !first.hasPrefix("-") {
            cmd = first
            args.removeFirst()
        }
        var o: Options
        do {
            o = try parse(args)
        } catch {
            err("hipreport: \(error)\n")
            return 2
        }
        var sys = system
        if !o.fixture.isEmpty {
            do {
                sys = try FakeSystem.load(fixture: o.fixture)
            } catch {
                err("hipreport: \(error)\n")
                return 2
            }
        }
        switch cmd {
        case "report": return report(o, sys)
        case "facts": return facts(o, sys)
        case "check": return check(o, sys)
        case "lint": return lint(&o, sys)
        case "record": return record(o, sys)
        case "version":
            out("hipreport \(hipreportVersion)\n")
            return 0
        case "help":
            out(usage)
            return 0
        default:
            err("hipreport: unknown command \"\(cmd)\"\n\(usage)")
            return 2
        }
    }

    func sources(_ o: Options) -> [Source] {
        (o.noBuiltin ? [] : [.builtin]) + o.checksDirs.map { Source(dir: $0) } + o.devDirs.map { Source(dir: $0, dev: true) }
    }

    func gather(_ o: Options, _ sys: System, quiet: Bool = false) -> Facts {
        let (set, errs) = loadChecks(sys, sources(o))
        if !quiet {
            for e in errs { err("hipreport: skipping: \(e)\n") }
            if !set.trusted { err("hipreport: warning: using --dev-checks; this report is untrusted\n") }
        }
        let env = Env(sys)
        if o.debug && !quiet { env.debug = { [err] in err("hipreport: \($0)\n") } }
        var req = o.req
        if req.userName.isEmpty { req.userName = environment["USER"] ?? loginName() }
        return collect(env, set, req)
    }

    func report(_ o: Options, _ sys: System) -> Int32 {
        if o.req.md5.isEmpty { err("hipreport: warning: no --md5 given; the gateway will reject this\n") }
        out(gather(o, sys).xml.document)
        return 0
    }

    func encodeJSON<T: Encodable>(_ v: T) -> String {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        return String(decoding: (try? enc.encode(v)) ?? Data(), as: UTF8.self) + "\n"
    }

    func facts(_ o: Options, _ sys: System) -> Int32 {
        let f = gather(o, sys)
        if o.json {
            out(encodeJSON(f))
            return 0
        }
        out("host \(f.hostName) (\(f.computer)), macOS \(f.osVersion), host-id \(f.hostID), trusted=\(f.trusted)\n")
        for p in f.products {
            if let r = p.plist {
                out("\ncustom plist \(r.path) exists=\(r.exists)  [\(p.source)]\n")
                for k in r.keys { out("  \(k.key.padding(toLength: 24, withPad: " ", startingAt: 0)) exists=\(k.exists) \"\(k.value)\"\n") }
                continue
            }
            out("\n\(p.category): \(p.vendor) \(p.name)  [\(p.source)]\n")
            for (n, v) in p.fields.sorted(by: { $0.key < $1.key }) {
                let val = v.drives.map { $0.map { "\($0.name)=\($0.state)" }.joined(separator: " ") } ?? "\"\(v.value)\""
                var line = "  \(n.padding(toLength: 22, withPad: " ", startingAt: 0)) \(val)  via \(v.how)"
                if let e = v.error { line += "  (\(e))" }
                out(line + "\n")
            }
        }
        return 0
    }

    func check(_ o: Options, _ sys: System) -> Int32 {
        guard !o.policy.isEmpty else {
            err("hipreport: check needs --policy FILE\n")
            return 2
        }
        guard let data = FileManager.default.contents(atPath: o.policy) else {
            err("hipreport: \(o.policy): cannot read\n")
            return 2
        }
        let pol: Policy
        do {
            pol = try Policy.parse(String(decoding: data, as: UTF8.self))
        } catch {
            err("hipreport: \(o.policy): \(error)\n")
            return 2
        }
        let results = pol.check(gather(o, sys).products)
        let failed = results.filter { !$0.pass }.count
        if o.json {
            out(encodeJSON(results))
        } else {
            for r in results {
                out("\(r.pass ? "PASS" : "FAIL")  \(r.requirement)\n")
                for d in r.detail { out("      \(d)\n") }
            }
            if failed > 0 { out("\(failed) of \(results.count) requirements failed\n") }
        }
        return failed > 0 ? 1 : 0
    }

    /// Validates the built-in library and configured directories (with
    /// trust checks), plus any paths given, which are checked as dev sources.
    func lint(_ o: inout Options, _ sys: System) -> Int32 {
        var errs: [CheckError] = []
        var n = 0
        var files: [String] = []
        for p in o.rest {
            var isDir: ObjCBool = false
            if FileManager.default.fileExists(atPath: p, isDirectory: &isDir), !isDir.boolValue {
                files.append(p)
            } else {
                o.devDirs.append(p)
            }
        }
        for src in sources(o) {
            let (set, e) = loadChecks(sys, [src])
            errs += e
            n += set.checks.count
        }
        for f in files {
            guard let data = FileManager.default.contents(atPath: f) else {
                errs.append(CheckError("\(f): cannot read"))
                continue
            }
            do {
                let ve = try Check.parse(String(decoding: data, as: UTF8.self)).validate()
                if ve.isEmpty { n += 1 } else { errs += ve.map { CheckError("\(f): \($0)") } }
            } catch {
                errs.append(CheckError("\(f): \(error)"))
            }
        }
        for e in errs { err("\(e)\n") }
        out("\(n) check files ok, \(errs.count) problems\n")
        return errs.isEmpty ? 0 : 1
    }

    /// Runs every check against the system and writes the answers as a
    /// fixture. It holds this machine's host name, MACs and addresses; scrub
    /// them before committing one.
    func record(_ o: Options, _ sys: System) -> Int32 {
        let rec = Recorder(sys)
        _ = gather(o, rec, quiet: true)
        let text = rec.recording.fixtureText()
        if o.output.isEmpty {
            out(text)
        } else if !FileManager.default.createFile(atPath: o.output, contents: Data(text.utf8)) {
            err("hipreport: cannot write \(o.output)\n")
            return 1
        }
        return 0
    }
}
