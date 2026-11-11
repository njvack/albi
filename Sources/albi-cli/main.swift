// albi-cli: the client core and macOS I/O layer in a command-line harness,
// with no extension, no utun and no root. It pings through the tunnel from
// userspace, which is enough to test against gp-fake-gateway.
//
//   printf 'test\n' | albi-cli connect 127.0.0.1:8443 --user test \
//       --pin pin-sha256:... --second-factor 1 --ping 10.99.0.1
//
// Output lines start with "albi: " so scripts can grep them. Exit status:
// 0 stopped normally, 1 error, 2 the cookie was rejected and a login is needed.

#if canImport(Network)
import Darwin
import Diagnostics
import Foundation
import GPCore
import GPMac

struct Options {
    var server = ""
    var target: (String) -> Login.Target = { .auto($0) }
    var user: String?
    var pins: [String] = []
    var secondFactor: String?
    var hipWrapper: String?
    var ping: String?
    var duration: Double?
    var logout = true
    var reauth = false
    var hipInterval: Double?
    var policy = SessionPolicy()
    var diagnostics: String?
    var diagPolicy = FlightRecorder.Policy()

    static let usage = """
    usage: albi-cli connect SERVER [options]
      --user NAME            username (else read from stdin)
      --portal | --gateway   treat SERVER as a portal or a gateway (default: try portal first)
      --pin PIN              accept only this certificate (pin-sha256:BASE64); repeatable
      --second-factor ANSWER answer to the challenge (else read from stdin)
      --hip-wrapper PATH     run PATH as an openconnect --csd-wrapper for HIP reports
      --ping ADDR            ping ADDR through the tunnel once a second
      --duration SECONDS     stop (and log out) after this long
      --no-logout            leave the cookie valid when stopping
      --reauth               log in again with the same password when the cookie ends
      --dpd SECONDS          keepalive interval (default 10)
      --hip-interval SECONDS HIP recheck interval (default: the portal's, else 3600)
      --hip-retry SECONDS    first retry delay after a failed HIP check (default 30)
      --diagnostics DIR      diagnostics mode: write incident files to DIR (SIGUSR1 saves one now)
      --diag-grace SECONDS   outage that counts as an incident (default 60)
      --diag-window SECONDS  history to keep (default 600)
    The password is read from the first line of stdin.
    """

    static func parse(_ args: [String]) -> Options {
        var o = Options()
        var it = args.makeIterator()
        guard it.next() == "connect", let server = it.next() else { fail(usage) }
        o.server = server
        func value(_ flag: String) -> String {
            guard let v = it.next() else { fail("\(flag) needs a value\n\(usage)") }
            return v
        }
        while let a = it.next() {
            switch a {
            case "--user", "-u": o.user = value(a)
            case "--portal": o.target = { .portal($0) }
            case "--gateway": o.target = { .gateway($0) }
            case "--pin", "--servercert": o.pins.append(value(a))
            case "--second-factor": o.secondFactor = value(a)
            case "--hip-wrapper", "--csd-wrapper": o.hipWrapper = value(a)
            case "--ping": o.ping = value(a)
            case "--duration": o.duration = Double(value(a))
            case "--no-logout": o.logout = false
            case "--reauth": o.reauth = true
            case "--dpd": o.policy.dpdInterval = Double(value(a)) ?? 10
            case "--hip-interval": o.hipInterval = Double(value(a))
            case "--hip-retry": o.policy.hipRetryInitialDelay = Double(value(a)) ?? 30
            case "--diagnostics": o.diagnostics = value(a)
            case "--diag-grace": o.diagPolicy.grace = Double(value(a)) ?? 60
            case "--diag-window": o.diagPolicy.window = Double(value(a)) ?? 600
            default: fail("unknown option \(a)\n\(usage)")
            }
        }
        o.policy.canReauthenticate = o.reauth
        return o
    }
}

func say(_ s: String) {
    print("albi: \(s)")
    fflush(stdout)
}

func fail(_ s: String) -> Never {
    FileHandle.standardError.write(Data((s + "\n").utf8))
    exit(1)
}

/// Answers prompts from stdin and the command line, and remembers the
/// password so `--reauth` can log in again without asking.
final class CLICredentials: CredentialProvider, @unchecked Sendable {
    private let lock = NSLock()
    let user: String?
    let secondFactor: String?
    private(set) var password: String?

    init(user: String?, secondFactor: String?) {
        self.user = user
        self.secondFactor = secondFactor
    }

    func answer(_ prompt: CredentialPrompt) async throws -> String {
        switch prompt {
        case .username:
            if let user { return user }
            return try line("username")
        case .password(_, _, _, let retry):
            if retry { throw GPError.badCredentials("password rejected") }
            let p = try line("password")
            lock.withLock { password = p }
            return p
        case .challenge(let msg):
            say("challenge: \(msg)")
            if let secondFactor { return secondFactor }
            return try line("challenge answer")
        }
    }

    func line(_ what: String) throws -> String {
        guard let l = readLine(strippingNewline: true) else { throw GPError.cancelled }
        _ = what
        return l
    }

    var stored: StoredCredentials? {
        lock.withLock {
            guard let user, let password else { return nil }
            return StoredCredentials(username: user, password: password, secondFactor: secondFactor)
        }
    }
}

/// A userspace TunnelHost: prints settings and state, and checks ping replies.
final class CLIHost: TunnelHost, @unchecked Sendable {
    private let lock = NSLock()
    let options: Options
    let connector: any GatewayConnector
    let credentials: CLICredentials
    private(set) var replies = 0
    var myIPv4: String?

    init(options: Options, connector: any GatewayConnector, credentials: CLICredentials) {
        self.options = options
        self.connector = connector
        self.credentials = credentials
    }

    func apply(_ s: TunnelSettings) async throws {
        lock.withLock { myIPv4 = s.ipv4Address }
        say("settings ipv4=\(s.ipv4Address ?? "-") routes=\(s.includedIPv4.map { "\($0.address)/\($0.prefixLength)" }.joined(separator: ",")) dns=\(s.dnsServers.joined(separator: ",")) match=\(s.matchDomains?.joined(separator: ",") ?? "*") mtu=\(s.mtu)")
    }

    func deliver(_ packets: [[UInt8]]) {
        let me = lock.withLock { myIPv4 }
        for p in packets {
            if let me, let r = Ping.reply(p, to: me) {
                lock.withLock { replies += 1 }
                say("ping reply seq=\(r.sequence)")
            }
        }
    }

    func stateChanged(_ state: SessionState) { say("state \(state)") }

    func hipReport(_ c: HIPContext) async throws -> String? {
        guard let path = options.hipWrapper else { return nil }
        var args = ["--cookie", c.cookie.form.encoded]
        if let v4 = c.clientIPv4 { args += ["--client-ip", v4] }
        if let v6 = c.clientIPv6 { args += ["--client-ipv6", v6] }
        args += ["--md5", c.md5, "--client-os", c.clientOS]
        let report = try await run(path, args, env: ["APP_VERSION": c.appVersion])
        say("hip report generated (\(report.utf8.count) bytes)")
        return report
    }

    func reauthenticate() async throws -> AuthCookie {
        guard options.reauth, let stored = credentials.stored else { throw StoredCredentials.NeedsUser() }
        let login = Login(transport: connector, credentials: stored, client: client, username: stored.username)
        let r = try await login.run(options.target(options.server))
        say("logged in again")
        return r.cookie
    }

    func saveCookie(_ c: AuthCookie?) { say(c == nil ? "cookie cleared" : "cookie saved") }

    func log(_ m: String) {
        FileHandle.standardError.write(Data("albi: \(m)\n".utf8))
    }

    var client: ClientInfo { ClientInfo(computer: ProcessInfo.processInfo.hostName) }
}

/// Runs a program and returns its stdout. Fails on a non-zero exit.
func run(_ path: String, _ args: [String], env: [String: String]) async throws -> String {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    p.environment = ProcessInfo.processInfo.environment.merging(env) { _, b in b }
    let out = Pipe()
    p.standardOutput = out
    try p.run()
    let data = out.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    guard p.terminationStatus == 0 else { throw GPError.server("\(path) exited with status \(p.terminationStatus)") }
    return String(decoding: data, as: UTF8.self)
}

let options = Options.parse(Array(CommandLine.arguments.dropFirst()))
let trust: TrustPolicy = options.pins.isEmpty ? .system : .pinned(options.pins)
let clock = ContinuousSessionClock()
let diagnostics: Diagnostics? = options.diagnostics.map { dir in
    var settings = DiagnosticsSettings(enabled: true)
    settings.keep = 100
    let d = Diagnostics(settings: settings, directory: URL(fileURLWithPath: dir), clock: clock,
                        secrets: KnownSecrets(servers: [options.server], computer: ProcessInfo.processInfo.hostName,
                                              localAccount: NSUserName()),
                        policy: options.diagPolicy) { _, line in say("diagnostics: \(line)") }
    d.minimumInterval = 0
    d.start(every: .milliseconds(500))
    return d
}
let base = NWGatewayConnector(trust: trust)
let connector: any GatewayConnector = diagnostics.map { RecordingConnector(base, recorder: $0.recorder, clock: clock) } ?? base
let credentials = CLICredentials(user: options.user, secondFactor: options.secondFactor)
let host = CLIHost(options: options, connector: connector, credentials: credentials)
var client = host.client

let login: LoginResult
do {
    login = try await Login(transport: connector, credentials: credentials, client: client, username: options.user)
        .run(options.target(options.server))
} catch {
    fail("albi: login failed: \(error)")
}
say("logged in to \(login.gateway) as \(login.cookie.user)")
if let v = login.portal?.version { client.appVersion = v }
diagnostics?.updateSecrets {
    $0.password = credentials.stored?.password
    $0.cookies.append(login.cookie)
    $0.servers.append(login.gateway)
}
diagnostics?.recorder.setInfo("portal-version", login.portal?.version)

let hipInterval = options.hipInterval ?? login.portal?.hipReportInterval.map(Double.init)
let runner = SessionRunner(server: login.gateway, client: client,
                           session: Session(cookie: login.cookie, policy: options.policy, hipInterval: hipInterval),
                           io: connector, host: host, clock: clock, recorder: diagnostics?.recorder)

let watcher = PathWatcher { [runner] usable in
    say("network path changed (usable=\(usable))")
    Task { await runner.post(.pathChanged(usable: usable)) }
}
watcher.start()

// SIGINT/SIGTERM: stop and log out (unless --no-logout). SIGHUP: stop, keep
// the cookie. SIGUSR2: reconnect now, as openconnect does. SIGUSR1: save a
// diagnostics file now.
var sources: [DispatchSourceSignal] = []
if let diagnostics {
    signal(SIGUSR1, SIG_IGN)
    let src = DispatchSource.makeSignalSource(signal: SIGUSR1, queue: .main)
    src.setEventHandler { diagnostics.saveNow(reason: "SIGUSR1") }
    src.resume()
    sources.append(src)
}
for (sig, logout) in [(SIGINT, options.logout), (SIGTERM, options.logout), (SIGHUP, false), (SIGUSR2, false)] {
    signal(sig, SIG_IGN)
    let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
    src.setEventHandler { [runner] in
        Task {
            if sig == SIGUSR2 {
                await runner.post(.pathChanged(usable: true))
                return
            }
            await runner.stop(logout: logout)
        }
    }
    src.resume()
    sources.append(src)
}

await runner.start()

if let target = options.ping {
    Task {
        var seq: UInt16 = 0
        while true {
            try? await Task.sleep(for: .seconds(1))
            guard await runner.state == .connected, let me = await runner.config?.ipv4,
                  let pkt = Ping.request(from: me, to: target, id: 0xa1b1, sequence: seq) else { continue }
            seq &+= 1
            await runner.send(packets: [pkt])
        }
    }
}

if let d = options.duration {
    Task {
        try? await Task.sleep(for: .seconds(d))
        say("duration elapsed")
        await runner.stop(logout: options.logout)
    }
}

let final = await runner.waitUntilFinished()
// Let a logout started by a signal finish.
try? await Task.sleep(for: .milliseconds(500))
say("finished: \(final)")
watcher.stop()
switch final {
case .needsLogin: exit(2)
default: exit(0)
}
#else
print("albi-cli needs macOS (Network.framework)")
#endif
