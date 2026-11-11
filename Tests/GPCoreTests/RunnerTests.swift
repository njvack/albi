import Synchronization
import Testing
@testable import GPCore

/// An in-memory gateway that answers like gp-fake-gateway.
final class FakeGateway: GatewayConnector, @unchecked Sendable {
    private let lock = Lock()
    var portal = true
    var password = "test"
    var challengeAnswer: String? = "1"
    var hipNeeded = false
    var rejectCookies = false
    var ip = "10.99.0.2"
    private var _requests: [String] = []
    private var _hipReports: [String] = []
    private var _loggedOut: [String] = []
    private var _tunnels: [FakeTunnel] = []
    var requests: [String] { lock.with { _requests } }
    var hipReports: [String] { lock.with { _hipReports } }
    var loggedOut: [String] { lock.with { _loggedOut } }
    var tunnels: [FakeTunnel] { lock.with { _tunnels } }
    private var issued = 0
    private var challenges: Set<String> = []

    func set(_ f: (FakeGateway) -> Void) { lock.with { f(self) } }

    func send(_ req: HTTPRequest, to server: String) async throws -> HTTPResponse {
        lock.with { respond(req) }
    }

    private func respond(_ req: HTTPRequest) -> HTTPResponse {
        let path = String(req.path.split(separator: "?")[0])
        _requests.append(path)
        let f = req.body
        func ok(_ s: String) -> HTTPResponse { HTTPResponse(status: 200, body: s) }
        let badCookie = ok(#"<response status="error"><error>Invalid authentication cookie</error></response>"#)
        switch path {
        case "/global-protect/prelogin.esp" where !portal:
            return ok("<prelogin-response><status>Error</status><msg>GlobalProtect portal does not exist</msg></prelogin-response>")
        case "/global-protect/prelogin.esp", "/ssl-vpn/prelogin.esp":
            return ok("<prelogin-response><status>Success</status><username-label>Username</username-label><password-label>Password</password-label></prelogin-response>")
        case "/global-protect/getconfig.esp":
            guard f["passwd"] == password else { return HTTPResponse(status: 512, body: "") }
            return ok(#"<policy><version>6.2.8</version><gateways><external><list><entry name="gw.test"><description>GW</description></entry></list></external></gateways><hip-collection><hip-report-interval>1800</hip-report-interval></hip-collection></policy>"#)
        case "/ssl-vpn/login.esp":
            if let input = f["inputStr"] {
                guard challenges.remove(input) != nil, f["passwd"] == challengeAnswer else { return HTTPResponse(status: 512, body: "") }
            } else {
                guard f["passwd"] == password else { return HTTPResponse(status: 512, body: "") }
                if challengeAnswer != nil {
                    let token = "ch\(challenges.count)"
                    challenges.insert(token)
                    return ok("<challenge><user>test</user><inputstr>\(token)</inputstr><respmsg>Approve the push</respmsg></challenge>")
                }
            }
            issued += 1
            let args = ["(null)", "cookie\(issued)", "PC", "fake-portal", f["user"] ?? "", "Fake", "vsys1", "fake-domain",
                        "(null)", "", "", "", "tunnel", "-1", "4100", ip, "", "", ""]
            return ok("<jnlp><application-desc>" + args.map { "<argument>\($0)</argument>" }.joined() + "</application-desc></jnlp>")
        case "/ssl-vpn/getconfig.esp":
            if rejectCookies { return badCookie }
            return ok("<response><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><lifetime>86400</lifetime><ip-address>\(ip)</ip-address><netmask>255.255.255.255</netmask><access-routes><member>10.99.0.0/24</member></access-routes><dns><member>10.99.0.53</member></dns><dns-suffix><member>fake.test</member></dns-suffix></response>")
        case "/ssl-vpn/hipreportcheck.esp":
            if rejectCookies { return badCookie }
            let needed = hipNeeded && !_hipReports.contains { $0.contains(f["md5"] ?? "?") }
            return ok("<response status=\"success\"><hip-report-needed>\(needed ? "yes" : "no")</hip-report-needed></response>")
        case "/ssl-vpn/hipreport.esp":
            _hipReports.append(f["report"] ?? "")
            return ok(#"<response status="success"/>"#)
        case "/ssl-vpn/logout.esp":
            _loggedOut.append(f["authcookie"] ?? "")
            return ok(#"<response status="success"/>"#)
        default:
            return HTTPResponse(status: 404, body: "")
        }
    }

    func openTunnel(to server: String) async throws -> any TunnelConnection {
        let t = FakeTunnel(gateway: self)
        lock.with { _tunnels.append(t) }
        return t
    }

    func cookieValid(_ c: String) -> Bool { lock.with { !rejectCookies && !_loggedOut.contains(c) } }

    /// Closes every open tunnel, as a network failure would.
    func dropTunnels() { for t in tunnels { t.serverClose() } }
}

/// One tunnel connection to the fake gateway. Echoes data packets back and
/// answers keepalives.
final class FakeTunnel: TunnelConnection, @unchecked Sendable {
    private let lock = Lock()
    private let gateway: FakeGateway
    private let (stream, cont) = AsyncStream<[UInt8]>.makeStream()
    private var iterator: AsyncStream<[UInt8]>.Iterator?
    private var started = false
    private var decoder = GPST.Decoder()
    private(set) var closed = false
    var silent = false
    private(set) var keepalives = 0
    private(set) var packets: [[UInt8]] = []

    init(gateway: FakeGateway) {
        self.gateway = gateway
        iterator = stream.makeAsyncIterator()
    }

    func write(_ bytes: [UInt8]) async throws {
        let replies: [[UInt8]] = try lock.with {
            if closed { throw GPError.server("closed") }
            if !started {
                started = true
                let req = String(decoding: bytes, as: UTF8.self)
                let cookie = Form.parse(String(req.split(separator: "?")[1].split(separator: " ")[0]))["authcookie"] ?? ""
                return gateway.cookieValid(cookie) ? [Array("START_TUNNEL".utf8)] : [Array("HTTP/1.1 502 Bad Gateway\r\n\r\n".utf8)]
            }
            decoder.append(bytes)
            var out: [[UInt8]] = []
            while let f = try decoder.next() {
                switch f {
                case .keepalive:
                    keepalives += 1
                    out.append(GPST.keepaliveFrame)
                case .packet(let p):
                    packets.append(p)
                    out.append(GPST.encode(packet: p))
                }
            }
            return out
        }
        if lock.with({ silent && started }) && !replies.isEmpty && String(decoding: replies[0].prefix(5), as: UTF8.self) != "START" { return }
        for r in replies { cont.yield(r) }
    }

    func read() async throws -> [UInt8]? {
        var it = lock.with { () -> AsyncStream<[UInt8]>.Iterator? in
            let i = iterator
            iterator = nil
            return i
        }
        let v = await it?.next()
        lock.with { iterator = it }
        return v
    }

    func close() {
        lock.with { closed = true }
        cont.finish()
    }

    func serverClose() { close() }
}

/// A plain lock for the test fakes.
final class Lock: Sendable {
    private let m = Synchronization.Mutex(())
    func with<T>(_ f: () throws -> T) rethrows -> T {
        try m.withLock { _ in try f() }
    }
}

/// Records what the session asks of the OS.
final class FakeHost: TunnelHost, @unchecked Sendable {
    private let lock = Lock()
    private var _settings: [TunnelSettings] = []
    private var _delivered: [[UInt8]] = []
    private var _states: [SessionState] = []
    private var _saved: [AuthCookie?] = []
    private var _logs: [String] = []
    var settings: [TunnelSettings] { lock.with { _settings } }
    var delivered: [[UInt8]] { lock.with { _delivered } }
    var saved: [AuthCookie?] { lock.with { _saved } }
    var report: String? = "<hip-report><md5-sum>MD5</md5-sum></hip-report>"
    var reauth: (@Sendable () async throws -> AuthCookie)?

    func apply(_ s: TunnelSettings) async throws { lock.with { _settings.append(s) } }
    func deliver(_ p: [[UInt8]]) { lock.with { _delivered += p } }
    func stateChanged(_ s: SessionState) { lock.with { _states.append(s) } }
    func hipReport(_ c: HIPContext) async throws -> String? {
        lock.with { report?.replacingMD5(c.md5) }
    }
    func reauthenticate() async throws -> AuthCookie {
        guard let r = lock.with({ reauth }) else { throw StoredCredentials.NeedsUser() }
        return try await r()
    }
    func saveCookie(_ c: AuthCookie?) { lock.with { _saved.append(c) } }
    func log(_ m: String) { lock.with { _logs.append(m) } }

    var lastState: SessionState? { lock.with { _states.last } }
    var deliveredCount: Int { lock.with { _delivered.count } }
}

extension String {
    func replacingMD5(_ md5: String) -> String {
        var out = ""
        var rest = Substring(self)
        while let r = rest.firstRange(of: "MD5") {
            out += rest[..<r.lowerBound] + md5
            rest = rest[r.upperBound...]
        }
        return out + rest
    }
}

/// Polls until `cond` holds or about five seconds pass.
func eventually(_ what: String, _ cond: () async -> Bool) async {
    for _ in 0..<1000 {
        if await cond() { return }
        try? await Task.sleep(for: .milliseconds(5))
    }
    Issue.record("timed out waiting for \(what)")
}

let creds = StoredCredentials(username: "test", password: "test", secondFactor: "1")
let testClient = ClientInfo(computer: "albi-test")

@Suite struct LoginTests {
    @Test func portalThenGatewayWithChallenge() async throws {
        let gw = FakeGateway()
        let r = try await Login(transport: gw, credentials: creds, client: testClient).run(.auto("portal.test"))
        #expect(r.gateway == "gw.test")
        #expect(r.cookie.authcookie == "cookie1")
        #expect(r.cookie.user == "test")
        #expect(r.portal?.version == "6.2.8")
        #expect(gw.requests == ["/global-protect/prelogin.esp", "/global-protect/getconfig.esp",
                                "/ssl-vpn/prelogin.esp", "/ssl-vpn/login.esp", "/ssl-vpn/login.esp"])
    }

    @Test func autoFallsBackToGateway() async throws {
        let gw = FakeGateway()
        gw.portal = false
        let r = try await Login(transport: gw, credentials: creds, client: testClient).run(.auto("gw.test"))
        #expect(r.gateway == "gw.test")
        #expect(r.portal == nil)
    }

    @Test func wrongChallengeAnswerAsksForPasswordAgain() async throws {
        let gw = FakeGateway()
        gw.challengeAnswer = "2"
        await #expect(throws: StoredCredentials.NeedsUser.self) {
            try await Login(transport: gw, credentials: creds, client: testClient).run(.gateway("gw.test"))
        }
    }

    @Test func interactiveRetry() async throws {
        actor Answers: CredentialProvider {
            var prompts: [CredentialPrompt] = []
            func answer(_ p: CredentialPrompt) async throws -> String {
                prompts.append(p)
                switch p {
                case .username: return "test"
                case .password(_, _, _, let retry): return retry ? "test" : "wrong"
                case .challenge: return "1"
                }
            }
        }
        let a = Answers()
        let gw = FakeGateway()
        gw.portal = false
        let r = try await Login(transport: gw, credentials: a, client: testClient).run(.auto("gw.test"))
        #expect(r.cookie.authcookie == "cookie1")
        let prompts = await a.prompts
        #expect(prompts.count == 4)
        #expect(prompts[2] == .password(label: "Password", message: nil, server: "gw.test", retry: true))
        #expect(prompts[3] == .challenge(message: "Approve the push"))
    }

    @Test func samlIsRefused() async {
        struct SAML: HTTPTransport {
            func send(_ r: HTTPRequest, to s: String) async throws -> HTTPResponse {
                HTTPResponse(status: 200, body: "<prelogin-response><status>Success</status><saml-auth-method>REDIRECT</saml-auth-method><saml-request>eA==</saml-request></prelogin-response>")
            }
        }
        await #expect(throws: GPError.self) {
            try await Login(transport: SAML(), credentials: creds, client: testClient).run(.gateway("gw"))
        }
    }
}

@Suite(.serialized) struct RunnerTests {
    func fastPolicy() -> SessionPolicy {
        var p = SessionPolicy()
        p.dpdInterval = 0.2
        p.reconnectInitialDelay = 0.01
        p.reconnectMaxDelay = 0.05
        p.hipRetryInitialDelay = 0.05
        return p
    }

    func connected(_ gw: FakeGateway, _ host: FakeHost, policy: SessionPolicy? = nil) async throws -> SessionRunner {
        let login = try await Login(transport: gw, credentials: creds, client: testClient).run(.gateway("gw.test"))
        let runner = SessionRunner(server: login.gateway, client: testClient,
                                   session: Session(cookie: login.cookie, policy: policy ?? fastPolicy()), io: gw, host: host)
        await runner.start()
        await eventually("connected") { await runner.state == .connected }
        return runner
    }

    let ping: [UInt8] = [0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 10, 99, 0, 2, 10, 99, 0, 1, 8, 0, 0, 0, 0, 1, 0, 1]

    @Test func trafficFlowsAndLogoutKillsCookie() async throws {
        let gw = FakeGateway(), host = FakeHost()
        let runner = try await connected(gw, host)
        #expect(host.settings.first?.includedIPv4.first?.address == "10.99.0.0")
        #expect(host.settings.first?.matchDomains == ["fake.test"])
        await runner.send(packets: [ping, ping])
        await eventually("echo") { host.deliveredCount == 2 }
        #expect(host.delivered.first == ping)
        // Keepalives are sent and answered; the tunnel stays up.
        try await Task.sleep(for: .milliseconds(900))
        #expect(await runner.state == .connected)
        #expect((gw.tunnels.last?.keepalives ?? 0) >= 2)
        await runner.stop(logout: true)
        #expect(gw.loggedOut == ["cookie1"])
        #expect(await runner.waitUntilFinished() == .stopped(reason: "disconnected"))
        #expect(gw.tunnels.allSatisfy { $0.closed })
    }

    @Test func droppedTunnelReconnectsWithSameCookie() async throws {
        let gw = FakeGateway(), host = FakeHost()
        let runner = try await connected(gw, host)
        gw.dropTunnels()
        await eventually("second tunnel") { let st = await runner.state; return gw.tunnels.count == 2 && st == .connected }
        #expect(gw.loggedOut.isEmpty)
        await runner.send(packets: [ping])
        await eventually("echo after reconnect") { host.deliveredCount == 1 }
        await runner.stop(logout: false)
        #expect(gw.loggedOut.isEmpty)
    }

    @Test func pathChangeReconnects() async throws {
        let gw = FakeGateway(), host = FakeHost()
        let runner = try await connected(gw, host)
        await runner.post(.pathChanged(usable: true))
        await eventually("reconnected") { let st = await runner.state; return gw.tunnels.count == 2 && st == .connected }
        #expect(gw.tunnels[0].closed)
        await runner.stop(logout: false)
    }

    @Test func hipReportSubmittedWhenAsked() async throws {
        let gw = FakeGateway(), host = FakeHost()
        gw.hipNeeded = true
        let runner = try await connected(gw, host)
        #expect(gw.hipReports.count == 1)
        let cookie = await runner.cookie
        #expect(gw.hipReports.first?.contains(cookie.hipToken) == true)
        await runner.stop(logout: false)
    }

    @Test func rejectedCookieNeedsLogin() async throws {
        let gw = FakeGateway(), host = FakeHost()
        let runner = try await connected(gw, host)
        gw.set { $0.rejectCookies = true }
        gw.dropTunnels()
        #expect(await runner.waitUntilFinished() == .needsLogin(reason: "Invalid authentication cookie"))
        #expect(host.saved.last == .some(nil))
    }

    @Test func rejectedCookieReauthenticates() async throws {
        let gw = FakeGateway(), host = FakeHost()
        var p = fastPolicy()
        p.canReauthenticate = true
        host.reauth = {
            try await Login(transport: gw, credentials: creds, client: testClient).run(.gateway("gw.test")).cookie
        }
        let runner = try await connected(gw, host, policy: p)
        // Kill the cookie on the gateway, then drop the tunnel.
        let old = await runner.cookie
        _ = try await gw.send(Requests.logout(old), to: "gw.test")
        gw.dropTunnels()
        await eventually("new cookie") { let c = await runner.cookie; let st = await runner.state; return c.authcookie == "cookie2" && st == .connected }
        #expect(host.saved.last??.authcookie == "cookie2")
        await runner.stop(logout: true)
    }

    @Test func deadPeerDetected() async throws {
        let gw = FakeGateway(), host = FakeHost()
        let runner = try await connected(gw, host)
        // Stop echoing: make the tunnel swallow writes by closing the read side only.
        let t = gw.tunnels[0]
        t.stopAnswering()
        await eventually("reconnect after dead peer") { let st = await runner.state; return gw.tunnels.count == 2 && st == .connected }
        await runner.stop(logout: false)
    }
}

extension FakeTunnel {
    /// Keeps the connection open but stops replying, like a dead path.
    func stopAnswering() { lock.with { silent = true } }
}
