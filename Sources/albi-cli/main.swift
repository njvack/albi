// albi-cli: the client core and macOS I/O layer in a command-line harness.
// By default there's no utun and no root: it pings through the tunnel from
// userspace, which is enough to test against gp-fake-gateway.
//
//   printf 'test\n' | albi-cli connect 127.0.0.1:8443 --user test \
//       --pin pin-sha256:... --second-factor 1 --ping 10.99.0.1
//
// With --tun (as root) it brings up the real tunnel the root helper will:
// a utun, routes on it, DNS as temporary dynamic-store keys, the gateway
// connection pinned to the physical interface. Everything it changes goes
// away when it exits, however it exits; excluded routes, the one exception,
// are journaled and swept on the next start (or by `albi-cli sweep`).
//
//   sudo albi-cli connect --tun vpn.example.edu
//
// Output lines start with "albi: " and the local time, so scripts can grep
// them and overnight logs show when things happened. Exit status:
// 0 stopped normally, 1 error, 2 the cookie was rejected and a login is needed.

#if canImport(Network)
import AlbiConstants
import Darwin
import Diagnostics
import Foundation
import GPCore
import GPMac
import Network

struct Options {
    var server = ""
    var target: (String) -> Login.Target = { .auto($0) }
    var gateway: String?
    var gatewayOnly = false
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
    var tun = false
    var dnsMode = NetConfig.DNSMode.split
    var journal = NetConfig.defaultJournal
    var pinInterface = false
    var mtu: Int?
    var routes: [TunnelSettings.IPv4Route]?
    var trace = 0
    var verbose = false
    var reportVersion: String?

    static let usage = """
    usage: albi-cli connect SERVER [options]
           albi-cli sweep [--journal PATH]   remove excluded routes a killed --tun run left (root)
      --user NAME            username (else read from stdin)
      --portal               treat SERVER as a portal (default: try portal, then gateway)
      --gateway NAME         gateway to pick from the portal's list, by name or address
                             (default: lowest priority number)
      --gateway-only         skip the portal and log in straight to the gateway: the
                             --gateway address if given, else SERVER. One second-factor
                             prompt instead of two when both ask.
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
      --tun                  real tunnel: utun, routes and DNS (root)
      --dns split|full       with --tun: split (default) sends only the gateway's domains to its
                             DNS, unless the gateway sends a full tunnel; full sends every name
      --pin-interface        with --tun: also pin gateway connections to the physical
                             interface (the host route to the gateway goes in either way)
      --mtu N                with --tun: utun MTU (default: the gateway's, else 1361)
      --route A.B.C.D/N      with --tun: route only this through the tunnel instead of
                             the gateway's routes; repeatable (for debugging)
      --trace N              with --tun: log the first N packets each way
      --report-version V     report GlobalProtect version V at login and in HIP reports, whatever
                             the portal says (default: the portal's version, else \(AlbiVersion.globalProtect))
      -v, --verbose          also log connection phases, HIP report generation and cookie saves
      --journal PATH         with --tun: excluded-route journal
                             (default \(AlbiPaths.helperJournal))
    The password is read from the first line of stdin.
    """

    static func parse(_ args: [String]) -> Options {
        var o = Options()
        if args.contains(where: { $0 == "--help" || $0 == "-h" }) {
            print(usage)
            exit(0)
        }
        var it = args.makeIterator()
        func value(_ flag: String) -> String {
            guard let v = it.next() else { fail("\(flag) needs a value\n\(usage)") }
            return v
        }
        let command = it.next()
        if command == "sweep" {
            while let a = it.next() {
                switch a {
                case "--journal": o.journal = URL(fileURLWithPath: value(a))
                default: fail("unknown option \(a)\n\(usage)")
                }
            }
            NetConfig.sweep(journal: o.journal) { say($0) }
            say("sweep done")
            exit(0)
        }
        var positional: [String] = []
        guard command == "connect" else { fail(usage) }
        while let a = it.next() {
            switch a {
            case "--user", "-u": o.user = value(a)
            case "--portal": o.target = { .portal($0) }
            case "--gateway": o.gateway = value(a)
            case "--gateway-only": o.gatewayOnly = true
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
            case "--tun": o.tun = true
            case "--dns":
                guard let m = NetConfig.DNSMode(rawValue: value(a)) else { fail("--dns is split or full") }
                o.dnsMode = m
            case "--journal": o.journal = URL(fileURLWithPath: value(a))
            case "--pin-interface": o.pinInterface = true
            case "--no-pin": o.pinInterface = false
            case "--mtu": o.mtu = Int(value(a))
            case "--route":
                let v = value(a)
                guard let r = ipv4Route(v) else { fail("albi: bad --route \(v)") }
                o.routes = (o.routes ?? []) + [r]
            case "--trace": o.trace = Int(value(a)) ?? 0
            case "--report-version": o.reportVersion = value(a)
            case "-v", "--verbose": o.verbose = true
            default:
                if a.hasPrefix("-") { fail("unknown option \(a)\n\(usage)") }
                positional.append(a)
            }
        }
        guard positional.count == 1 else { fail(usage) }
        o.server = positional[0]
        if o.tun && o.ping != nil { fail("--ping is for the userspace tunnel; with --tun, use ping(8)") }
        o.policy.canReauthenticate = o.reauth
        if o.gatewayOnly {
            let gw = o.gateway ?? o.server
            o.target = { _ in .gateway(gw) }
        }
        return o
    }

    /// Picks `--gateway` from the portal's list, else the default.
    var chooseGateway: @Sendable ([PortalConfig.Gateway]) -> PortalConfig.Gateway {
        { [gateway] gws in
        say("portal gateways: " + gws.map { "\($0.description ?? "-") (\($0.address))" }.joined(separator: ", "))
        guard let name = gateway else { return Login.defaultGateway(gws) }
        guard let gw = gws.first(where: { $0.description == name || $0.address == name }) else {
            fail("albi: no gateway named \(name) in the portal's list")
        }
        return gw
        }
    }
}

func say(_ s: String) {
    print("albi: \(timestamp()) \(s)")
    fflush(stdout)
}

/// Local time to the second, like `2026-11-20 08:14:03`.
func timestamp() -> String {
    var t = time(nil)
    var parts = tm()
    localtime_r(&t, &parts)
    var buf = [CChar](repeating: 0, count: 32)
    let n = strftime(&buf, buf.count, "%Y-%m-%d %H:%M:%S", &parts)
    return String(decoding: buf[..<n].map { UInt8(bitPattern: $0) }, as: UTF8.self)
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

    func stateChanged(_ state: SessionState) {
        if case .connecting(let phase) = state {
            if options.verbose { say("state connecting (\(phase))") }
            return
        }
        say("state \(state)")
    }

    func hipReport(_ c: HIPContext) async throws -> String? {
        guard let path = options.hipWrapper else { return nil }
        var args = ["--cookie", c.cookie.form.encoded]
        if let v4 = c.clientIPv4 { args += ["--client-ip", v4] }
        if let v6 = c.clientIPv6 { args += ["--client-ipv6", v6] }
        args += ["--md5", c.md5, "--client-os", c.clientOS]
        let report = try await run(path, args, env: ["APP_VERSION": c.appVersion])
        if options.verbose { say("hip report generated (\(report.utf8.count) bytes)") }
        return report
    }

    func reauthenticate() async throws -> AuthCookie {
        guard options.reauth, let stored = credentials.stored else { throw StoredCredentials.NeedsUser() }
        let login = Login(transport: connector, credentials: stored, client: client, username: stored.username,
                          chooseGateway: options.chooseGateway)
        let r = try await login.run(options.target(options.server))
        say("logged in again")
        return r.cookie
    }

    func saveCookie(_ c: AuthCookie?) {
        if options.verbose { say(c == nil ? "cookie cleared" : "cookie saved") }
    }

    func log(_ m: String) {
        // The runner logs each state too; stateChanged already printed it.
        if m.hasPrefix("state: ") { return }
        FileHandle.standardError.write(Data("albi: \(timestamp()) \(m)\n".utf8))
    }

    var client: ClientInfo { ClientInfo(computer: ProcessInfo.processInfo.hostName, reportedVersion: options.reportVersion) }
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
/// Lets callbacks made before the runner exists reach it once it does.
final class RunnerBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: SessionRunner?
    var runner: SessionRunner? {
        get { lock.withLock { value } }
        set { lock.withLock { value = newValue } }
    }

    func post(_ e: Session.Event) {
        guard let r = runner else { return }
        Task { await r.post(e) }
    }
}
let box = RunnerBox()
nonisolated(unsafe) var utunHost: UtunHost?
nonisolated(unsafe) var watcherRef: PathWatcher?

let watcher = PathWatcher { usable in
    say("network path changed (usable=\(usable)): \(watcherRef?.summary ?? "")")
    // Excluded routes follow the new router before the session reconnects.
    utunHost?.pathChanged()
    box.post(.pathChanged(usable: usable))
}
watcherRef = watcher
watcher.start()

if options.tun {
    guard getuid() == 0 else { fail("albi: --tun needs root") }
    NetConfig.sweep(journal: options.journal) { say($0) }
}

// With --tun, every gateway connection is pinned to the physical interface,
// so 0/1 and 128/1 on the utun can't capture it. A loopback gateway (the
// e2e fake) is never captured, so it isn't pinned.
let gatewayHost = splitHostPort(options.server).0
let loopbackGateway = gatewayHost == "localhost" || gatewayHost == "::1" || gatewayHost.hasPrefix("127.")
/// Logs the interface gateway connections are pinned to when it changes.
final class PinLog: @unchecked Sendable {
    private let lock = NSLock()
    private var last: String?? = .none
    func note(_ name: String?) {
        let changed = lock.withLock {
            defer { last = .some(name) }
            return last != .some(name)
        }
        if changed { say("gateway connections pinned to \(name ?? "nothing (unpinned)")") }
    }
}
let pinLog = PinLog()
var pin: (@Sendable () -> NWInterface?)?
if options.tun && options.pinInterface {
    pin = { [watcher] in
        let i = loopbackGateway ? nil : watcher.primaryInterface
        pinLog.note(i?.name)
        return i
    }
}
let base = NWGatewayConnector(trust: trust, requiredInterface: pin,
                              address: { utunHost?.dialAddress(for: $0) })
let connector: any GatewayConnector = diagnostics.map { RecordingConnector(base, recorder: $0.recorder, clock: clock) } ?? base
let credentials = CLICredentials(user: options.user, secondFactor: options.secondFactor)
let cliHost = CLIHost(options: options, connector: connector, credentials: credentials)
var client = cliHost.client
if options.tun {
    do {
        utunHost = try UtunHost(dnsMode: options.dnsMode, journal: options.journal,
                                gatewayHosts: [gatewayHost] + (options.gateway.map { [splitHostPort($0).0] } ?? []),
                                mtu: options.mtu, routes: options.routes, tracePackets: options.trace,
                                router: { [watcher] in watcher.ipv4Router },
                                hooks: .init(hipReport: { try await cliHost.hipReport($0) },
                                             reauthenticate: { try await cliHost.reauthenticate() },
                                             saveCookie: { cliHost.saveCookie($0) },
                                             stateChanged: { cliHost.stateChanged($0) },
                                             log: { if !$0.hasPrefix("state: ") { say($0) } }))
    } catch {
        fail("albi: opening a utun failed: \(error)")
    }
    say("tun \(utunHost!.device.name) opened pid=\(getpid())")
}
let host: any TunnelHost = utunHost.map { $0 as any TunnelHost } ?? cliHost

let login: LoginResult
do {
    login = try await Login(transport: connector, credentials: credentials, client: client, username: options.user,
                            chooseGateway: options.chooseGateway)
        .run(options.target(options.server))
} catch {
    fail("albi: login failed: \(error)")
}
say("logged in to \(login.gateway) as \(login.cookie.user)")
utunHost?.addGatewayHost(splitHostPort(login.gateway).0)
client.adopt(version: login.portal?.version)
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

box.runner = runner
utunHost?.pumpPackets(to: runner)

let power = PowerWatcher { event in
    switch event {
    case .willSleep:
        say("system will sleep")
        box.post(.sleep)
    case .didWake:
        say("system woke")
        box.post(.wake)
    }
}
if !power.start() { say("could not watch for sleep and wake") }

// SIGINT/SIGTERM: stop and log out (unless --no-logout). SIGHUP: stop, keep
// the cookie. SIGUSR2: reconnect now, as openconnect does. SIGUSR1: save a
// diagnostics file now (without --diagnostics it only says so; the default
// action would kill us with routes and DNS still in).
// A closed stdout (`| tee` killed by the same Ctrl-C) must not kill us before logout.
signal(SIGPIPE, SIG_IGN)
var sources: [DispatchSourceSignal] = []
do {
    signal(SIGUSR1, SIG_IGN)
    let src = DispatchSource.makeSignalSource(signal: SIGUSR1, queue: .main)
    src.setEventHandler {
        if let diagnostics { diagnostics.saveNow(reason: "SIGUSR1") } else { say("SIGUSR1: no --diagnostics, nothing saved") }
    }
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
utunHost?.shutdown()
watcher.stop()
power.stop()
switch final {
case .needsLogin: exit(2)
default: exit(0)
}

/// "10.0.0.0/8" as a route; a bare address is a /32.
func ipv4Route(_ s: String) -> TunnelSettings.IPv4Route? {
    let parts = s.split(separator: "/", maxSplits: 1).map(String.init)
    let len = parts.count == 2 ? Int(parts[1]) : 32
    guard let len, (0...32).contains(len) else { return nil }
    let octets = parts[0].split(separator: ".", omittingEmptySubsequences: false).compactMap { UInt8($0) }
    guard octets.count == 4 else { return nil }
    let m: UInt32 = len == 0 ? 0 : ~UInt32(0) << (32 - len)
    let mask = [24, 16, 8, 0].map { String((m >> UInt32($0)) & 0xff) }.joined(separator: ".")
    return TunnelSettings.IPv4Route(address: parts[0], mask: mask, prefixLength: len)
}
#else
print("albi-cli needs macOS (Network.framework)")
#endif
