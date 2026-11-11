import Testing
@testable import GPCore

/// Drives a Session on a fake clock and records what it asks for.
struct Harness {
    var s: Session
    var now: Double = 0
    var log: [Session.Action] = []

    init(policy: SessionPolicy = SessionPolicy(), hipInterval: Double? = nil) {
        s = Session(cookie: cookieA, policy: policy, hipInterval: hipInterval)
    }

    @discardableResult
    mutating func send(_ e: Session.Event) -> [Session.Action] {
        let a = s.handle(e, now: now)
        log += a
        return a
    }

    /// Advances time, running timers as they come due.
    @discardableResult
    mutating func advance(to t: Double) -> [Session.Action] {
        var out: [Session.Action] = []
        while let d = s.nextDeadline, d <= t {
            now = max(now, d)
            out += s.tick(now: now)
        }
        now = t
        log += out
        return out
    }

    /// Advances time with a healthy tunnel: every keepalive is answered.
    @discardableResult
    mutating func alive(until t: Double) -> [Session.Action] {
        var out: [Session.Action] = []
        while now < t {
            out += advance(to: min(t, now + 10))
            send(.received)
        }
        return out
    }

    @discardableResult
    mutating func advance(by dt: Double) -> [Session.Action] { advance(to: now + dt) }

    /// Starts the session and answers every step with success.
    mutating func connect(_ config: GatewayConfig = cfg()) {
        send(.start)
        finishReconnect(config)
    }

    /// Answers the step the session is waiting on with success, running
    /// timers as needed, until it is connected.
    mutating func finishReconnect(_ config: GatewayConfig = cfg()) {
        for _ in 0..<20 {
            switch s.state {
            case .connected: return
            case .connecting(.config): send(.configFetched(config))
            case .connecting(.hip): send(.hipDone)
            case .connecting(.tunnel): send(.tunnelOpened)
            default:
                guard let d = s.nextDeadline else { preconditionFailure("stuck in \(s.state)") }
                advance(to: d)
            }
        }
        preconditionFailure("stuck in \(s.state)")
    }

    func count(where f: (Session.Action) -> Bool) -> Int { log.filter(f).count }
}

let cookieA = AuthCookie(authcookie: "A", portal: "p", user: "u", domain: "d", computer: "c")
let cookieB = AuthCookie(authcookie: "B", portal: "p", user: "u", domain: "d", computer: "c")

func cfg(ip: String = "10.0.0.2", lifetime: Int? = 86400, rekey: Int? = nil) -> GatewayConfig {
    var x = "<response><ip-address>\(ip)</ip-address>"
    if let lifetime { x += "<lifetime>\(lifetime)</lifetime>" }
    if let rekey { x += "<timeout>\(rekey)</timeout>" }
    x += "</response>"
    return try! GatewayConfig(XMLElement.parse(x)!)
}

func isFetch(_ a: Session.Action) -> Bool { if case .fetchConfig = a { true } else { false } }
func isOpen(_ a: Session.Action) -> Bool { if case .openTunnel = a { true } else { false } }
func isHIP(_ a: Session.Action) -> Bool { if case .checkHIP = a { true } else { false } }

@Suite struct SessionTests {
    @Test func connectSequence() {
        var h = Harness()
        let a1 = h.send(.start)
        #expect(a1 == [.stateChanged(.connecting(.config)), .fetchConfig(cookieA, previousIPv4: nil, previousIPv6: nil)])
        let a2 = h.send(.configFetched(cfg()))
        #expect(a2 == [.applySettings(cfg()), .stateChanged(.connecting(.hip)), .checkHIP(cookieA, clientIPv4: "10.0.0.2", clientIPv6: nil)])
        let a3 = h.send(.hipDone)
        #expect(a3 == [.stateChanged(.connecting(.tunnel)), .openTunnel(cookieA, path: "/ssl-tunnel-connect.sslvpn")])
        #expect(h.send(.tunnelOpened) == [.stateChanged(.connected)])
        #expect(h.s.expiresAt == 86400)
    }

    @Test func keepalivesAndDeadPeer() {
        var h = Harness()
        h.connect()
        // Gateway answers keepalives: they keep going every 10 s.
        for _ in 0..<5 {
            #expect(h.advance(by: 10) == [.sendKeepalive])
            h.send(.received)
        }
        // Gateway goes silent: after more than 20 s, reconnect at once.
        h.advance(by: 10)
        h.advance(by: 10)
        let a = h.advance(by: 10)
        #expect(a.contains(.closeTunnel))
        #expect(a.contains { isFetch($0) })
        #expect(h.s.state == .connecting(.config))
    }

    @Test func tunnelDropReconnectsWithBackoffAndNoCap() {
        var h = Harness()
        h.connect()
        // First failure: immediate retry.
        h.send(.tunnelClosed(.transient("reset")))
        #expect(h.s.state == .reconnecting(attempt: 1, reason: "reset"))
        #expect(h.s.nextDeadline == h.now)
        // Every retry fails at getconfig; delays double to the cap and keep going.
        var delays: [Double] = []
        for _ in 0..<12 {
            let t0 = h.now
            guard let d = h.s.nextDeadline else { Issue.record("no retry scheduled"); return }
            let acts = h.advance(to: d)
            #expect(acts.contains { isFetch($0) })
            delays.append(d - t0)
            h.send(.configFailed(.transient("timeout")))
        }
        #expect(delays == [0, 1, 2, 4, 8, 16, 30, 30, 30, 30, 30, 30])
        // Success resets the backoff.
        h.finishReconnect()
        h.send(.tunnelClosed(nil))
        #expect(h.s.nextDeadline == h.now)
    }

    @Test func reconnectReusesAddress() {
        var h = Harness()
        h.connect()
        h.send(.tunnelClosed(nil))
        let a = h.advance(by: 0)
        #expect(a.contains(.fetchConfig(cookieA, previousIPv4: "10.0.0.2", previousIPv6: nil)))
    }

    @Test func newAddressReappliesSettings() {
        var h = Harness()
        h.connect()
        h.send(.tunnelClosed(nil))
        h.advance(by: 0)
        let a = h.send(.configFetched(cfg(ip: "10.0.0.3")))
        #expect(a.first == .applySettings(cfg(ip: "10.0.0.3")))
        // Same config again: nothing to re-apply.
        h.send(.hipDone)
        h.send(.tunnelOpened)
        h.send(.tunnelClosed(nil))
        h.advance(by: 0)
        #expect(!h.send(.configFetched(cfg(ip: "10.0.0.3"))).contains { if case .applySettings = $0 { true } else { false } })
    }

    @Test func cookieRejectedWithoutReauthNeedsLogin() {
        var h = Harness()
        h.connect()
        h.send(.tunnelClosed(nil))
        h.advance(by: 0)
        let a = h.send(.configFailed(.cookieRejected("Invalid authentication cookie")))
        #expect(a.contains(.saveCookie(nil)))
        #expect(h.s.state == .needsLogin(reason: "Invalid authentication cookie"))
        #expect(h.s.nextDeadline == nil)
    }

    @Test func tunnel502IsRejection() {
        var h = Harness()
        h.send(.start)
        h.send(.configFetched(cfg()))
        h.send(.hipDone)
        h.send(.tunnelFailed(.cookieRejected("502")))
        #expect(h.s.state == .needsLogin(reason: "502"))
    }

    @Test func cookieRejectedWithReauthLogsInAgain() {
        var p = SessionPolicy()
        p.canReauthenticate = true
        var h = Harness(policy: p)
        h.connect()
        h.send(.tunnelClosed(nil))
        h.advance(by: 0)
        let a = h.send(.configFailed(.cookieRejected("expired")))
        #expect(a.contains(.reauthenticate))
        #expect(h.s.state == .reauthenticating)
        let b = h.send(.reauthenticated(cookieB))
        #expect(b.contains(.saveCookie(cookieB)))
        // The old cookie is already dead: no logout for it.
        #expect(!b.contains(.logout(cookieA)))
        #expect(b.contains(.fetchConfig(cookieB, previousIPv4: "10.0.0.2", previousIPv6: nil)))
    }

    @Test func reauthNeedingUserStops() {
        var p = SessionPolicy()
        p.canReauthenticate = true
        var h = Harness(policy: p)
        h.connect()
        h.send(.tunnelFailed(.cookieRejected("x")))   // ignored: no tunnel pending
        h.send(.tunnelClosed(.cookieRejected("gone")))
        h.send(.reauthFailed(.transient("password rejected"), needsUser: true))
        #expect(h.s.state == .needsLogin(reason: "login needed: password rejected"))
    }

    @Test func earlyReauthBeforeLifetimeEnds() {
        var p = SessionPolicy()
        p.canReauthenticate = true
        var h = Harness(policy: p)
        h.connect(cfg(lifetime: 3600))
        // Keep the tunnel alive while time passes.
        var reauthAt: Double?
        while h.now < 3600 {
            let a = h.advance(by: 10)
            h.send(.received)
            if a.contains(.reauthenticate) { reauthAt = h.now; break }
        }
        #expect(reauthAt == 3300)
        #expect(h.s.state == .connected)
        let b = h.send(.reauthenticated(cookieB))
        #expect(b.contains(.closeTunnel))
        #expect(b.contains(.logout(cookieA)))
        #expect(b.contains(.fetchConfig(cookieB, previousIPv4: "10.0.0.2", previousIPv6: nil)))
        h.finishReconnect(cfg(lifetime: 3600))
        #expect(h.s.cookie == cookieB)
        #expect(h.s.expiresAt == 6900.0)
    }

    @Test func earlyReauthNeedingUserKeepsTunnel() {
        var p = SessionPolicy()
        p.canReauthenticate = true
        var h = Harness(policy: p)
        h.connect(cfg(lifetime: 600))
        h.alive(until: 300)
        #expect(h.log.contains(.reauthenticate))
        h.send(.reauthFailed(.transient("push denied"), needsUser: true))
        #expect(h.s.state == .connected)
    }

    @Test func earlyReauthTransientFailureRetries() {
        var p = SessionPolicy()
        p.canReauthenticate = true
        var h = Harness(policy: p)
        h.connect(cfg(lifetime: 3600))
        h.alive(until: 3300)
        h.send(.reauthFailed(.transient("timeout"), needsUser: false))
        #expect(h.s.state == .connected)
        let before = h.count { $0 == .reauthenticate }
        h.alive(until: 3360)
        #expect(h.count { $0 == .reauthenticate } == before + 1)
    }

    @Test func noReauthTimerWithoutSavedCredentials() {
        var h = Harness()
        h.connect(cfg(lifetime: 600))
        for _ in 0..<70 {
            h.advance(by: 10)
            h.send(.received)
        }
        #expect(!h.log.contains(.reauthenticate))
    }

    @Test func hipRecheckRunsBesideTunnel() {
        var h = Harness(hipInterval: 3600)
        h.connect()
        var hipAt: Double?
        while h.now < 4000 {
            let a = h.advance(by: 10)
            h.send(.received)
            if a.contains(where: isHIP) { hipAt = h.now; break }
        }
        #expect(hipAt == 3540)
        #expect(!h.log.contains(.closeTunnel))
        h.send(.hipDone)
        #expect(h.s.state == .connected)
    }

    @Test func hipFailureRetriesAndNeverDrops() {
        var h = Harness(hipInterval: 3600)
        h.connect()
        h.alive(until: 3540)
        var retryTimes: [Double] = []
        for _ in 0..<6 {
            h.send(.hipFailed(.transient("HTTP 500")))
            #expect(h.s.state == .connected)
            let start = h.now
            while true {
                let a = h.advance(by: 10)
                h.send(.received)
                if a.contains(where: isHIP) { break }
            }
            retryTimes.append(h.now - start)
        }
        #expect(retryTimes == [30, 60, 120, 240, 300, 300])
        #expect(!h.log.contains(.closeTunnel))
        // Success goes back to the normal interval.
        h.send(.hipDone)
        let t = h.now
        while true {
            let a = h.advance(by: 10)
            h.send(.received)
            if a.contains(where: isHIP) { break }
        }
        #expect(h.now - t == 3540)
    }

    @Test func hipFailureDuringConnectStillOpensTunnel() {
        var h = Harness()
        h.send(.start)
        h.send(.configFetched(cfg()))
        let a = h.send(.hipFailed(.transient("HTTP 500")))
        #expect(a.contains { isOpen($0) })
        h.send(.tunnelOpened)
        #expect(h.s.state == .connected)
        #expect(h.s.nextDeadline != nil)
    }

    @Test func hipCookieRejection() {
        var h = Harness()
        h.connect()
        h.alive(until: 3540)
        h.send(.hipFailed(.cookieRejected("Invalid authentication cookie")))
        #expect(h.s.state == .needsLogin(reason: "Invalid authentication cookie"))
        #expect(h.log.contains(.closeTunnel))
    }

    @Test func rekeyReconnectsEarly() {
        var h = Harness()
        h.connect(cfg(rekey: 600))
        var at: Double?
        while h.now < 700 {
            let a = h.advance(by: 10)
            h.send(.received)
            if a.contains(.closeTunnel) { at = h.now; break }
        }
        #expect(at == 540)
        #expect(h.log.contains { isFetch($0) && h.s.state == .connecting(.config) })
    }

    @Test func pathChangeReconnectsImmediately() {
        var h = Harness()
        h.connect()
        h.advance(by: 3)
        let a = h.send(.pathChanged(usable: true))
        #expect(a.contains(.closeTunnel))
        #expect(h.advance(by: 0).contains { isFetch($0) })
    }

    @Test func networkLossWaitsThenReconnects() {
        var h = Harness()
        h.connect()
        h.send(.pathChanged(usable: false))
        #expect(h.s.state == .waitingForNetwork)
        #expect(h.s.nextDeadline == nil || !(h.advance(by: 600).contains { isFetch($0) }))
        h.send(.pathChanged(usable: true))
        #expect(h.advance(by: 0).contains { isFetch($0) })
    }

    @Test func failureWhileOfflineWaits() {
        var h = Harness()
        h.connect()
        h.send(.tunnelClosed(nil))
        h.send(.pathChanged(usable: false))
        h.advance(by: 100)
        #expect(h.s.state == .waitingForNetwork)
    }

    @Test func sleepAndWake() {
        var h = Harness()
        h.connect()
        let a = h.send(.sleep)
        #expect(a == [.closeTunnel])
        // Asleep for two hours: no keepalives, no reconnects.
        let during = h.advance(by: 7200)
        #expect(!during.contains(.sendKeepalive))
        #expect(!during.contains { isFetch($0) })
        h.send(.wake)
        #expect(h.s.state == .reconnecting(attempt: 0, reason: "woke from sleep"))
        h.finishReconnect()
        #expect(h.s.cookie == cookieA)
    }

    @Test func wakeAfterLifetimeEnded() {
        var p = SessionPolicy()
        p.canReauthenticate = true
        var h = Harness(policy: p)
        h.connect(cfg(lifetime: 3600))
        h.send(.sleep)
        h.now = 4000
        let a = h.send(.wake)
        #expect(a.contains(.reauthenticate))
    }

    @Test func retriesStopAtLifetime() {
        var h = Harness()
        h.connect(cfg(lifetime: 100))
        h.send(.tunnelClosed(nil))
        while h.s.state != .needsLogin(reason: "cookie lifetime ended") {
            guard let d = h.s.nextDeadline, d < 1000 else { Issue.record("no stop: \(h.s.state)"); return }
            let a = h.advance(to: d)
            if a.contains(where: isFetch) { h.send(.configFailed(.transient("down"))) }
        }
        #expect(h.now >= 100)
    }

    @Test func stopWithLogout() {
        var h = Harness()
        h.connect()
        let a = h.send(.stop(logout: true))
        #expect(a == [.closeTunnel, .logout(cookieA), .saveCookie(nil), .stateChanged(.stopped(reason: "disconnected"))])
        #expect(h.s.nextDeadline == nil)
        #expect(h.send(.tunnelClosed(nil)).isEmpty)
    }

    @Test func stopWithoutLogoutKeepsCookie() {
        var h = Harness()
        h.connect()
        let a = h.send(.stop(logout: false))
        #expect(!a.contains(.logout(cookieA)))
        #expect(!a.contains(.saveCookie(nil)))
    }

    @Test func staleResultsIgnored() {
        var h = Harness()
        h.connect()
        #expect(h.send(.configFetched(cfg(ip: "10.0.0.9"))).isEmpty)
        #expect(h.send(.hipDone).isEmpty)
        #expect(h.send(.tunnelOpened).isEmpty)
    }

    @Test func backoffMath() {
        #expect(backoff(0, 1, 30) == 1)
        #expect(backoff(4, 1, 30) == 16)
        #expect(backoff(100, 1, 30) == 30)
    }
}
