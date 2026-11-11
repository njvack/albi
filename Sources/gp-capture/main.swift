// gp-capture: records one real session with a GlobalProtect portal and
// gateway as redacted test fixtures.
//
// It runs openconnect (which already works against the gateway) with
// --dump-http-traffic and a do-nothing script, so routes and DNS are never
// touched, keeps the tunnel up for a while, logs out, and writes:
//
//   OUT/raw/       the unredacted log and the real-to-fake mapping. Local only.
//   OUT/fixtures/  one file per request and response, the rest of the log and
//                  a summary, with cookies, keys, names, hosts and addresses
//                  replaced by consistent test values.

import Foundation
import GPCapture
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

let usage = """
    usage: gp-capture [options] SERVER [-- extra openconnect options]
           gp-capture --from-log RAWLOG [options]

    Connects to SERVER (a portal, or a gateway) with openconnect, keeps the
    tunnel up for --duration seconds, logs out, and writes redacted fixtures.

      --user NAME           user name (asked for if missing)
      --second-factor TEXT  answer to the second-factor challenge, e.g. 1 for a
                            Duo push (asked for; leave empty if there is none)
      --hip-wrapper PATH    HIP report script (openconnect --csd-wrapper)
      --gateway NAME        gateway to pick from the portal's list (--authgroup)
      --servercert PIN      passed to openconnect
      --duration SECONDS    how long to keep the tunnel up (default 120)
      --openconnect PATH    openconnect binary (default: found on PATH)
      --out DIR             output folder (default ./gp-capture-DATE)
      --scrub WORD          also replace WORD everywhere, e.g. your
                            organization's name (repeatable)
      --from-log FILE       redact an existing raw log instead of connecting

    openconnect needs root for its tun device; gp-capture runs it with sudo
    unless it is already root. Disconnect any other VPN first.
    """

struct Options {
    var server: String?
    var user: String?
    var secondFactor: String?
    var hipWrapper: String?
    var gateway: String?
    var servercert: String?
    var duration = 120
    var openconnect: String?
    var out: String?
    var scrub: [String] = []
    var fromLog: String?
    var extra: [String] = []
}

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write(Data("gp-capture: \(msg)\n".utf8))
    exit(1)
}

func parseOptions() -> Options {
    var o = Options()
    var args = Array(CommandLine.arguments.dropFirst())
    func value(_ flag: String) -> String {
        guard !args.isEmpty else { fail("\(flag) needs a value") }
        return args.removeFirst()
    }
    while !args.isEmpty {
        let a = args.removeFirst()
        switch a {
        case "-h", "--help": print(usage); exit(0)
        case "--user": o.user = value(a)
        case "--second-factor": o.secondFactor = value(a)
        case "--hip-wrapper": o.hipWrapper = value(a)
        case "--gateway": o.gateway = value(a)
        case "--servercert": o.servercert = value(a)
        case "--duration": o.duration = Int(value(a)) ?? { fail("--duration takes seconds") }()
        case "--openconnect": o.openconnect = value(a)
        case "--out": o.out = value(a)
        case "--scrub": o.scrub.append(value(a))
        case "--from-log": o.fromLog = value(a)
        case "--": o.extra = args; args = []
        default:
            if a.hasPrefix("-") { fail("unknown option \(a)\n\n\(usage)") }
            guard o.server == nil else { fail("one SERVER only") }
            o.server = a
        }
    }
    if o.server == nil && o.fromLog == nil { fail(usage) }
    return o
}

func prompt(_ label: String) -> String {
    FileHandle.standardError.write(Data(label.utf8))
    return readLine() ?? ""
}

func secret(_ label: String) -> String {
    guard let p = getpass(label) else { return "" }
    return String(cString: p)
}

func findExecutable(_ name: String) -> String? {
    let path = (ProcessInfo.processInfo.environment["PATH"] ?? "") + ":/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin"
    for dir in path.split(separator: ":") {
        let p = "\(dir)/\(name)"
        if FileManager.default.isExecutableFile(atPath: p) { return p }
    }
    return nil
}

// Set by SIGINT/SIGTERM. openconnect gets the same Ctrl-C (it is in our
// process group) and logs out; we keep going to write what it logged.
nonisolated(unsafe) var interrupted: sig_atomic_t = 0
func onSignal(_: Int32) { interrupted = 1 }

/// Collects openconnect's output, echoing the readable part to the terminal.
final class OutputCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    private var partial = Data()
    private(set) var tunnelUp = false
    var hostLine: ((String) -> Void)?

    func append(_ chunk: Data) {
        lock.lock()
        data.append(chunk)
        partial.append(chunk)
        var shown: [String] = []
        while let nl = partial.firstIndex(of: UInt8(ascii: "\n")) {
            let line = String(decoding: partial[partial.startIndex..<nl], as: UTF8.self)
            partial.removeSubrange(partial.startIndex...nl)
            if line.contains("Configured as ") || line.contains("ESP session established")
                || line.contains("ESP tunnel connected") {
                tunnelUp = true
            }
            if Self.isQuiet(line) { continue }
            shown.append(line)
        }
        // Prompts end without a newline; show them so the user sees what
        // openconnect is waiting for.
        var promptText: String?
        if !partial.isEmpty {
            let p = String(decoding: partial, as: UTF8.self)
            if p.hasSuffix(": ") { promptText = p }
        }
        lock.unlock()
        for l in shown { FileHandle.standardError.write(Data("  \(l)\n".utf8)) }
        if let p = promptText { FileHandle.standardError.write(Data("  \(p)\n".utf8)) }
    }

    /// HTTP dumps and protocol chatter stay out of the terminal; they are in the log.
    static func isQuiet(_ line: String) -> Bool {
        var l = Substring(line)
        if l.hasPrefix("["), let close = l.firstIndex(of: "]") { l = l[l.index(after: close)...].drop { $0 == " " } }
        if l.hasPrefix("> ") || l.hasPrefix("< ") || l == ">" || l == "<" { return true }
        if l.contains(" key 0x") { return true }
        let chatter = ["Content-", "Date: ", "Set-Cookie", "HTTP body", "Server: ", "X-", "Cache-", "Connection: ",
                       "Pragma", "Expires", "Strict-Transport", "Keep-Alive", "Transfer-Encoding", "ETag", "Vary"]
        return chatter.contains { l.hasPrefix($0) }
    }

    var contents: Data {
        lock.lock()
        defer { lock.unlock() }
        return data
    }
}

func runOpenConnect(_ o: Options, out: URL, rawDir: URL) -> (log: String, password: String) {
    guard let oc = o.openconnect ?? findExecutable("openconnect") else {
        fail("openconnect not found; install it (brew install openconnect) or pass --openconnect")
    }
    let user = o.user ?? prompt("Username: ")
    // GP_CAPTURE_PASSWORD is for scripted runs against a fake gateway.
    let password = ProcessInfo.processInfo.environment["GP_CAPTURE_PASSWORD"] ?? secret("Password for \(user): ")
    let second = o.secondFactor ?? prompt("Second-factor answer (e.g. 1 for a Duo push; empty if none): ")
    let noop = findExecutable("true") ?? "/usr/bin/true"

    var args = [
        "--protocol=gp", "-v", "--timestamp", "--dump-http-traffic",
        // A script that does nothing: no routes, no DNS, no interface addresses.
        "--script=\(noop)",
        "--user=\(user)",
    ]
    if let h = o.hipWrapper { args.append("--csd-wrapper=\(h)") }
    if let g = o.gateway { args.append("--authgroup=\(g)") }
    if let c = o.servercert { args.append("--servercert=\(c)") }
    args += o.extra
    args.append(o.server!)

    let isRoot = getuid() == 0
    let process = Process()
    if isRoot {
        process.executableURL = URL(fileURLWithPath: oc)
        process.arguments = args
    } else {
        FileHandle.standardError.write(Data("openconnect needs root for its tun device; sudo may ask for your Mac password.\n".utf8))
        let v = Process()
        v.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        v.arguments = ["-v"]
        do { try v.run() } catch { fail("sudo: \(error)") }
        v.waitUntilExit()
        if v.terminationStatus != 0 { fail("sudo failed") }
        process.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        process.arguments = ["-n", "--", oc] + args
    }

    let stdin = Pipe(), output = Pipe()
    process.standardInput = stdin
    process.standardOutput = output
    process.standardError = output
    let collector = OutputCollector()
    output.fileHandleForReading.readabilityHandler = { h in
        let d = h.availableData
        if !d.isEmpty { collector.append(d) }
    }

    signal(SIGINT, onSignal)
    signal(SIGTERM, onSignal)
    FileHandle.standardError.write(Data("Running openconnect (Ctrl-C ends the capture early; it still logs out).\n".utf8))
    do { try process.run() } catch { fail("could not start openconnect: \(error)") }
    // openconnect reads each answer from stdin when it asks: the password,
    // then the challenge answer.
    var answers = password + "\n"
    if !second.isEmpty { answers += second + "\n" }
    stdin.fileHandleForWriting.write(Data(answers.utf8))
    try? stdin.fileHandleForWriting.close()

    var upSince: Date?
    var stopSent: Date?
    var reported = false
    while process.isRunning {
        usleep(200_000)
        if collector.tunnelUp && upSince == nil {
            upSince = Date()
            FileHandle.standardError.write(Data("Tunnel is up; capturing for \(o.duration) s.\n".utf8))
        }
        let due = upSince.map { Date().timeIntervalSince($0) >= Double(o.duration) } ?? false
        if (due || interrupted != 0) && stopSent == nil {
            if interrupted == 0 { FileHandle.standardError.write(Data("Logging out.\n".utf8)) }
            stopSent = Date()
            process.terminate()  // sudo passes SIGTERM on; openconnect logs out
        }
        if let s = stopSent, Date().timeIntervalSince(s) > 20, !reported {
            reported = true
            FileHandle.standardError.write(Data("openconnect has not exited; sending SIGKILL.\n".utf8))
            kill(process.processIdentifier, SIGKILL)
        }
    }
    output.fileHandleForReading.readabilityHandler = nil
    let rest = output.fileHandleForReading.readDataToEndOfFile()
    if !rest.isEmpty { collector.append(rest) }
    signal(SIGINT, SIG_DFL)
    signal(SIGTERM, SIG_DFL)
    let log = String(decoding: collector.contents, as: UTF8.self)
    let rawLog = rawDir.appendingPathComponent("openconnect.log")
    _ = FileManager.default.createFile(atPath: rawLog.path, contents: Data(log.utf8), attributes: [.posixPermissions: 0o600])
    FileHandle.standardError.write(Data("openconnect exited with status \(process.terminationStatus).\n".utf8))
    return (log, password)
}

let opts = parseOptions()
let stamp: String = {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.dateFormat = "yyyyMMdd-HHmmss"
    return f.string(from: Date())
}()
let out = URL(fileURLWithPath: opts.out ?? "gp-capture-\(stamp)")
let rawDir = out.appendingPathComponent("raw")
let fixturesDir = out.appendingPathComponent("fixtures")
do {
    try FileManager.default.createDirectory(at: rawDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
} catch { fail("cannot create \(rawDir.path): \(error)") }

let logText: String
var password: String?
if let f = opts.fromLog {
    guard let d = FileManager.default.contents(atPath: f) else { fail("cannot read \(f)") }
    logText = String(decoding: d, as: UTF8.self)
    if FileManager.default.fileExists(atPath: rawDir.appendingPathComponent("openconnect.log").path) == false {
        _ = FileManager.default.createFile(atPath: rawDir.appendingPathComponent("openconnect.log").path, contents: d,
                                       attributes: [.posixPermissions: 0o600])
    }
} else {
    let r = runOpenConnect(opts, out: out, rawDir: rawDir)
    logText = r.log
    password = r.password
}

let log = CaptureLog(parsing: logText)
if log.exchanges.isEmpty { fail("openconnect logged no HTTP traffic; see \(rawDir.path)/openconnect.log") }
var redactor = Redactor(password: password, words: opts.scrub)
let sudoUser = ProcessInfo.processInfo.environment["SUDO_USER"]
redactor.learnLocal(account: sudoUser ?? NSUserName(), hostNames: [ProcessInfo.processInfo.hostName])
let set = FixtureSet(log: log, redactor: redactor)
do {
    try set.write(to: fixturesDir)
    _ = FileManager.default.createFile(atPath: rawDir.appendingPathComponent("redactions.tsv").path,
                                   contents: Data(set.redactor.report.utf8), attributes: [.posixPermissions: 0o600])
} catch { fail("cannot write fixtures: \(error)") }

print(set.files.first { $0.name == "summary.txt" }!.contents)
print("Fixtures: \(fixturesDir.path) (\(set.files.count) files, \(log.exchanges.count) exchanges)")
print("Raw log and the real-to-fake mapping: \(rawDir.path). Keep these on your Mac.")
let leaks = set.leaks
if leaks.isEmpty {
    print("Leak check: none of the learned values remain in the fixtures. Read them before sharing anyway;")
    print("free text such as portal messages is only scrubbed for host names, addresses and --scrub words.")
} else {
    print("Leak check FAILED; do not share the fixtures yet:")
    for l in leaks { print("  \(l.file): \(l.what.joined(separator: ", "))") }
    exit(2)
}
