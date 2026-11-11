import Foundation
import Synchronization
import Testing
import Diagnostics
import GPCapture
@testable import GPCore

/// A gateway with realistic-looking names and secrets, so the tests can check
/// that none of them reach an incident file.
final class SecretGateway: GatewayConnector, @unchecked Sendable {
    static let host = "vpn.acmewidgets.edu"
    static let user = "jdoe-secret"
    static let password = "Hunter2-correct-horse"
    static let cookie = "4f1c9a7e2b3d4c5e6f708192a3b4c5d6"
    static let computer = "jdoes-macbook"
    static let publicIP = "128.104.17.33"

    let m = Mutex(State())
    struct State {
        var tunnelStatus: Int?  // non-nil: refuse tunnels with this status
        var tunnels: [Tunnel] = []
        var getconfigs = 0
    }

    func send(_ req: HTTPRequest, to server: String) async throws -> HTTPResponse {
        let path = String(req.path.split(separator: "?")[0])
        func ok(_ s: String) -> HTTPResponse { HTTPResponse(status: 200, body: s) }
        switch path {
        case "/ssl-vpn/prelogin.esp":
            return ok("<prelogin-response><status>Success</status><authentication-message>Welcome to Acmewidgets VPN</authentication-message></prelogin-response>")
        case "/ssl-vpn/login.esp":
            guard req.body["passwd"] == Self.password else { return HTTPResponse(status: 512, body: "") }
            let args = ["(null)", Self.cookie, "PC", "acme-portal", Self.user, "Acme LDAP", "vsys1", "acme",
                        "(null)", "", "", "", "tunnel", "-1", "4100", "10.31.4.2", "", "", ""]
            return ok("<jnlp><application-desc>" + args.map { "<argument>\($0)</argument>" }.joined() + "</application-desc></jnlp>")
        case "/ssl-vpn/getconfig.esp":
            m.withLock { $0.getconfigs += 1 }
            return ok("<response><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><lifetime>86400</lifetime><disconnect-on-idle>10800</disconnect-on-idle><timeout>7200</timeout><gw-address>\(Self.publicIP)</gw-address><ip-address>10.31.4.2</ip-address><netmask>255.255.255.255</netmask><mtu>1400</mtu><access-routes><member>10.31.0.0/16</member></access-routes><dns><member>10.31.0.53</member></dns><dns-suffix><member>corp.acmewidgets.edu</member></dns-suffix></response>")
        case "/ssl-vpn/hipreportcheck.esp":
            return ok("<response status=\"success\"><hip-report-needed>no</hip-report-needed></response>")
        case "/ssl-vpn/logout.esp":
            return ok(#"<response status="success"/>"#)
        default:
            return HTTPResponse(status: 404, body: "")
        }
    }

    func openTunnel(to server: String) async throws -> any TunnelConnection {
        let t = Tunnel(refuse: m.withLock { $0.tunnelStatus })
        m.withLock { $0.tunnels.append(t) }
        return t
    }

    func dropTunnels() { for t in m.withLock({ $0.tunnels }) { t.close() } }

    final class Tunnel: TunnelConnection, @unchecked Sendable {
        let refuse: Int?
        let (stream, cont) = AsyncStream<[UInt8]>.makeStream()
        let lock = NSLock()
        var it: AsyncStream<[UInt8]>.Iterator?
        let started = Mutex(false)

        init(refuse: Int?) {
            self.refuse = refuse
            it = stream.makeAsyncIterator()
        }

        func write(_ bytes: [UInt8]) async throws {
            let first = started.withLock { s in defer { s = true }; return !s }
            if first {
                cont.yield(refuse.map { Array("HTTP/1.1 \($0) Service Unavailable\r\n\r\n".utf8) } ?? Array("START_TUNNEL".utf8))
                if refuse != nil { cont.finish() }
                return
            }
            var d = GPST.Decoder()
            d.append(bytes)
            while let f = try d.next() {
                if case .keepalive = f { cont.yield(GPST.keepaliveFrame) }
            }
        }

        func read() async throws -> [UInt8]? {
            var i = lock.withLock { () -> AsyncStream<[UInt8]>.Iterator? in defer { it = nil }; return it }
            let v = await i?.next()
            lock.withLock { it = i }
            return v
        }

        func close() { cont.finish() }
    }
}

final class QuietHost: TunnelHost, @unchecked Sendable {
    func apply(_ settings: TunnelSettings) async throws {}
    func deliver(_ packets: [[UInt8]]) {}
    func stateChanged(_ state: SessionState) {}
    func hipReport(_ context: HIPContext) async throws -> String? { nil }
    func reauthenticate() async throws -> AuthCookie { throw StoredCredentials.NeedsUser() }
    func saveCookie(_ cookie: AuthCookie?) {}
    func log(_ message: String) {}
}

func eventually(_ what: String, timeout: Double = 10, _ cond: () async -> Bool) async {
    let deadline = ContinuousClock.now + .seconds(timeout)
    while ContinuousClock.now < deadline {
        if await cond() { return }
        try? await Task.sleep(for: .milliseconds(20))
    }
    Issue.record("timed out waiting for \(what)")
}

@Suite(.serialized) struct DiagnosticsTests {
    let secrets = [SecretGateway.host, SecretGateway.user, SecretGateway.password, SecretGateway.cookie,
                   SecretGateway.computer, SecretGateway.publicIP, "acmewidgets", "Acme LDAP", "acme-portal"]

    func tempDir() -> URL {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("albi-diag-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    @Test func unrecoveredDropWritesARedactedIncidentAndItsAftermath() async throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let clock = ContinuousSessionClock()
        var rp = FlightRecorder.Policy()
        rp.grace = 0.5
        rp.aftermath = 60
        let written = Mutex<[String]>([])
        let diag = Diagnostics(settings: DiagnosticsSettings(enabled: true), directory: dir, clock: clock,
                               secrets: KnownSecrets(password: SecretGateway.password, computer: SecretGateway.computer),
                               policy: rp) { _, line in written.withLock { $0.append(line) } }
        diag.start(every: .milliseconds(50))
        defer { diag.stop() }

        let gw = SecretGateway()
        let io = RecordingConnector(gw, recorder: diag.recorder, clock: clock)
        let creds = StoredCredentials(username: SecretGateway.user, password: SecretGateway.password, secondFactor: nil)
        let client = ClientInfo(computer: SecretGateway.computer)
        let login = try await Login(transport: io, credentials: creds, client: client, username: SecretGateway.user)
            .run(.gateway(SecretGateway.host))
        diag.updateSecrets { $0.cookies.append(login.cookie) }

        var policy = SessionPolicy()
        policy.dpdInterval = 0.2
        policy.reconnectInitialDelay = 0.05
        policy.reconnectMaxDelay = 0.1
        let runner = SessionRunner(server: login.gateway, client: client, session: Session(cookie: login.cookie, policy: policy),
                                   io: io, host: QuietHost(), clock: clock, recorder: diag.recorder)
        await runner.start()
        await eventually("connected") { await runner.state == .connected }

        // The gateway starts refusing tunnels, then the open one drops.
        gw.m.withLock { $0.tunnelStatus = 503 }
        gw.dropTunnels()
        await eventually("an incident file") { diag.lastIncident != nil }
        let url = try #require(diag.lastIncident)

        let first = try String(contentsOf: url, encoding: .utf8)
        for s in secrets { #expect(!first.lowercased().contains(s.lowercased()), "\(s) leaked") }
        let file = try IncidentFile(data: Data(first.utf8))
        #expect(file.header["outcome"] == nil)
        #expect((file.header["reason"] as? String)?.contains("not connected") == true)
        #expect(file.events.contains { $0["kind"] as? String == "http" && ($0["path"] as? String)?.contains("login.esp") == true })
        let login1 = try #require(file.events.first { ($0["path"] as? String)?.hasPrefix("/ssl-vpn/login.esp") == true })
        #expect((login1["request"] as? String)?.contains("passwd=REDACTED") == true)

        // The scenario draft has the refused tunnel and the drop.
        let draft = ScenarioDraft.make(from: file)
        let rules = draft["rules"] as? [[String: Any]] ?? []
        #expect(rules.contains { ($0["respond"] as? [String: Any])?["status"] as? Int == 503 })
        #expect(rules.contains { $0["do"] as? String == "drop_tunnel" })
        let config = draft["config"] as? [String: Any] ?? [:]
        #expect(config["rekey"] as? Int == 7200)
        #expect(config["idle_timeout"] as? Int == 10800)

        // Replaying the events into Session does what the client did.
        let replay = file.replay()
        if let d = replay.divergence {
            Issue.record("replay differs at \(d): recorded \(replay.recorded[max(0, d - 3)...].prefix(8)) replayed \(replay.replayed[max(0, d - 3)...].prefix(8))")
        }

        // Recovery rewrites the same file with the outcome.
        gw.m.withLock { $0.tunnelStatus = nil }
        await eventually("connected again") { await runner.state == .connected }
        await eventually("the rewrite") {
            (try? IncidentFile(contentsOf: url))?.header["outcome"] as? String == "connected again"
        }
        let second = try String(contentsOf: url, encoding: .utf8)
        for s in secrets { #expect(!second.lowercased().contains(s.lowercased()), "\(s) leaked") }
        #expect(second.contains("\"after\":true"))
        #expect(written.withLock { $0.count } == 2)
        await runner.stop(logout: true)
    }

    @Test func saveNowWritesWhileConnected() async throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let clock = ContinuousSessionClock()
        let diag = Diagnostics(settings: DiagnosticsSettings(enabled: true), directory: dir, clock: clock)
        diag.recorder.record(.event(.start), at: clock.now())
        diag.recorder.record(.state(.connected), at: clock.now())
        let url = try #require(diag.saveNow())
        let f = try IncidentFile(contentsOf: url)
        #expect(f.header["reason"] as? String == "saved by the user")
    }

    @Test func settingsRoundTripThroughProviderConfiguration() {
        var s = DiagnosticsSettings(enabled: true, windowMinutes: 45)
        var config: [String: Any] = [:]
        s.store(in: &config)
        let back = DiagnosticsSettings(providerConfiguration: config)
        #expect(back == s)
        #expect(back?.recorderPolicy.window == 1800)
        s.windowMinutes = 1
        #expect(s.recorderPolicy.window == 120)
    }

    @Test func requestKinds() {
        #expect(IncidentFile.requestKind("/ssl-vpn/getconfig.esp") == "getconfig")
        #expect(IncidentFile.requestKind("/global-protect/prelogin.esp?tmp=tmp") == "portal-prelogin")
    }
}
