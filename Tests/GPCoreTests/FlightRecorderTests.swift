import Testing
@testable import GPCore

@Suite struct IncidentRulesTests {
    typealias Signal = FlightRecorder.Signal

    struct Run {
        var rules = IncidentRules()
        var signals: [(Double, Signal)] = []

        init(grace: Double = 60, aftermath: Double = 600) {
            rules.grace = grace
            rules.aftermath = aftermath
        }

        mutating func at(_ t: Double, _ trace: FlightRecorder.Trace) {
            for s in rules.observe(trace, at: t) { signals.append((t, s)) }
        }

        mutating func tick(_ t: Double) {
            for s in rules.tick(now: t) { signals.append((t, s)) }
        }

        var dumps: [Double] { signals.compactMap { if case .dump = $0.1 { $0.0 } else { nil } } }
        var closes: [String] { signals.compactMap { if case .closed(_, let o) = $0.1 { o } else { nil } } }
    }

    func connected() -> Run {
        var r = Run()
        r.at(0, .event(.start))
        r.at(0, .state(.connecting(.config)))
        r.at(1, .state(.connected))
        return r
    }

    @Test func quickRecoveryIsNotAnIncident() {
        var r = connected()
        r.at(100, .event(.tunnelClosed(.transient("read: reset"))))
        r.at(100, .state(.reconnecting(attempt: 1, reason: "read: reset")))
        r.at(130, .state(.connected))
        r.tick(500)
        #expect(r.signals.isEmpty)
    }

    @Test func outageLongerThanGraceDumpsThenClosesOnReconnect() {
        var r = connected()
        r.at(100, .state(.reconnecting(attempt: 1, reason: "dead peer")))
        r.tick(159)
        #expect(r.dumps.isEmpty)
        r.tick(160)
        #expect(r.dumps == [160])
        r.tick(170)
        #expect(r.dumps == [160])
        r.at(200, .state(.connected))
        #expect(r.closes == ["connected again"])
    }

    @Test func sleepAndNoNetworkDontCount() {
        var r = connected()
        r.at(100, .event(.sleep))
        r.at(100, .state(.connecting(.config)))
        r.tick(5000)
        #expect(r.dumps.isEmpty)
        r.at(5000, .event(.wake))
        r.at(5030, .event(.pathChanged(usable: false)))
        r.tick(9000)
        #expect(r.dumps.isEmpty)
        r.at(9000, .event(.pathChanged(usable: true)))
        r.tick(9029)
        #expect(r.dumps.isEmpty)
        // 30 s before losing the network plus 30 s after it came back.
        r.tick(9030)
        #expect(r.dumps == [9030])
    }

    @Test func failingFirstConnectCounts() {
        var r = Run()
        r.at(0, .event(.start))
        r.at(0, .state(.connecting(.config)))
        r.at(1, .state(.reconnecting(attempt: 1, reason: "http(503)")))
        r.tick(61)
        #expect(r.dumps == [61])
    }

    @Test func earlyNeedsLoginDumpsAtOnce() {
        var r = connected()
        r.at(1, .event(.configFetched(try! config(lifetime: 3600))))
        r.at(500, .state(.needsLogin(reason: "Invalid authentication cookie")))
        #expect(r.dumps == [500])
        #expect(r.closes.count == 1)
    }

    @Test func needsLoginAtLifetimeIsExpected() {
        var r = connected()
        r.at(1, .event(.configFetched(try! config(lifetime: 3600))))
        r.at(3601, .state(.needsLogin(reason: "cookie lifetime ended")))
        #expect(r.signals.isEmpty)
    }

    @Test func userStopIsNotAnIncident() {
        var r = connected()
        r.at(100, .event(.stop(logout: true)))
        r.at(100, .state(.stopped(reason: "disconnected")))
        r.tick(1000)
        #expect(r.signals.isEmpty)
    }

    @Test func longOutageClosesAfterAftermathAndStaysQuiet() {
        var r = Run(grace: 60, aftermath: 600)
        r.at(0, .event(.start))
        r.at(1, .state(.connected))
        r.at(10, .state(.reconnecting(attempt: 1, reason: "x")))
        r.tick(70)
        r.tick(670)
        #expect(r.dumps == [70])
        #expect(r.closes.count == 1)
        r.tick(5000)
        #expect(r.dumps == [70])
        // A later outage, after recovering, is a new incident.
        r.at(6000, .state(.connected))
        r.at(6100, .state(.reconnecting(attempt: 1, reason: "y")))
        r.tick(6160)
        #expect(r.dumps == [70, 6160])
    }

    func config(lifetime: Int) throws -> GatewayConfig {
        try GatewayConfig(XMLElement.parse("<response><ip-address>10.99.0.2</ip-address><lifetime>\(lifetime)</lifetime></response>")!)
    }
}

@Suite struct FlightRecorderTests {
    @Test func windowDropsOldEntriesButKeepsSetupAndEvents() {
        var p = FlightRecorder.Policy()
        p.window = 60
        let r = FlightRecorder(policy: p)
        let login = HTTPRequest(path: "/ssl-vpn/login.esp", body: ["user": "u", "passwd": "hunter2"])
        r.recordHTTP(server: "gw", request: login, response: HTTPResponse(status: 200, body: "<jnlp/>"), error: nil, start: 0, end: 1)
        r.record(.event(.start), at: 1)
        r.record(.state(.connected), at: 1)
        r.record(.log("early"), at: 2)
        r.record(.log("late"), at: 100)
        let s = r.snapshot(now: 100)
        #expect(s.entries.map(\.trace) == [.log("late")])
        guard s.pinned.count == 2 else { Issue.record("pinned: \(s.pinned)"); return }
        guard case .http(let h) = s.pinned[0].trace else { Issue.record("no pinned login"); return }
        #expect(h.request["passwd"] == "(password)")
        #expect(!h.request.encoded.contains("hunter2"))
        #expect(s.pinned[1].trace == .event(.start))
        #expect(s.dropped == 4)
    }

    @Test func hipReportBodyIsNotKept() {
        let r = FlightRecorder()
        let req = HTTPRequest(path: "/ssl-vpn/hipreport.esp", body: ["report": "<hip-report>secret</hip-report>"])
        r.recordHTTP(server: "gw", request: req, response: HTTPResponse(status: 200, body: ""), error: nil, start: 0, end: 0)
        guard case .http(let h) = r.snapshot(now: 0).entries[0].trace else { Issue.record("no entry"); return }
        #expect(h.request["report"] == "(31 bytes)")
    }

    @Test func trafficIsFoldedPerSecond() {
        let r = FlightRecorder()
        for i in 0..<20 { r.count(at: Double(i) * 0.1, packetsIn: 1, bytesIn: 100) }
        r.count(at: 2.5, keepalivesOut: 1)
        r.record(.log("x"), at: 3)
        let t = r.snapshot(now: 3).entries.compactMap { e -> FlightRecorder.Traffic? in
            if case .traffic(let t) = e.trace { t } else { nil }
        }
        #expect(t.count == 3)
        #expect(t.map(\.packetsIn).reduce(0, +) == 20)
        #expect(t.last?.keepalivesOut == 1)
    }

    @Test func byteCapDropsOldest() {
        var p = FlightRecorder.Policy()
        p.maxBytes = 2000
        let r = FlightRecorder(policy: p)
        for i in 0..<100 { r.record(.log(String(repeating: "x", count: 100) + "\(i)"), at: Double(i)) }
        let s = r.snapshot(now: 100)
        #expect(s.entries.count < 20)
        #expect(s.entries.last?.trace == .log(String(repeating: "x", count: 100) + "99"))
    }

    @Test func notifiesDumpAndClose() {
        var p = FlightRecorder.Policy()
        p.grace = 5
        let got = Lock()
        nonisolated(unsafe) var signals: [FlightRecorder.Signal] = []
        let r = FlightRecorder(policy: p) { s in got.with { signals.append(s) } }
        r.record(.event(.start), at: 0)
        r.record(.state(.connected), at: 1)
        r.record(.state(.reconnecting(attempt: 1, reason: "x")), at: 2)
        r.poll(now: 8)
        r.record(.state(.connected), at: 9)
        #expect(got.with { signals } == [.dump(id: 1, reason: "not connected for 6 s with a usable network (last: x)"),
                                         .closed(id: 1, outcome: "connected again")])
        let marks = r.snapshot(now: 9).entries.filter { if case .incident = $0.trace { true } else { false } }
        #expect(marks.count == 2)
    }
}
