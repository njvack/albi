/// Timing rules for a session. Seconds throughout.
public struct SessionPolicy: Equatable, Sendable {
    /// Keepalive (DPD) interval. The peer is dead after twice this with
    /// nothing received. openconnect and the Windows client use 10.
    public var dpdInterval: Double = 10
    /// Reconnect backoff: the first retry is immediate, then this doubles up
    /// to `reconnectMaxDelay`. There is no cap on attempts.
    public var reconnectInitialDelay: Double = 1
    public var reconnectMaxDelay: Double = 30
    /// Retry backoff for a failed HIP check or report, which does not touch
    /// the tunnel.
    public var hipRetryInitialDelay: Double = 30
    public var hipRetryMaxDelay: Double = 300
    /// HIP recheck interval when the portal gives none.
    public var defaultHIPInterval: Double = 3600
    /// Re-authenticate this long before the cookie's lifetime ends. Capped at
    /// half the lifetime.
    public var reauthLeadTime: Double = 300
    /// Retry backoff when an early re-auth fails while the old cookie works.
    public var reauthRetryDelay: Double = 60
    /// Whether the session may log in again by itself (saved password and a
    /// fixed second-factor answer). Without it, a rejected cookie ends the
    /// session in `needsLogin`.
    public var canReauthenticate = false

    public init() {}

    /// The policy as name and value pairs, for diagnostics; `init(fields:)`
    /// reads them back.
    public var fields: [(String, String)] {
        [("dpd-interval", "\(dpdInterval)"), ("reconnect-initial-delay", "\(reconnectInitialDelay)"),
         ("reconnect-max-delay", "\(reconnectMaxDelay)"), ("hip-retry-initial-delay", "\(hipRetryInitialDelay)"),
         ("hip-retry-max-delay", "\(hipRetryMaxDelay)"), ("default-hip-interval", "\(defaultHIPInterval)"),
         ("reauth-lead-time", "\(reauthLeadTime)"), ("reauth-retry-delay", "\(reauthRetryDelay)"),
         ("can-reauthenticate", "\(canReauthenticate)")]
    }

    public init(fields: [String: String]) {
        func d(_ k: String, _ v: inout Double) { if let x = fields[k].flatMap({ Double($0) }) { v = x } }
        d("dpd-interval", &dpdInterval)
        d("reconnect-initial-delay", &reconnectInitialDelay)
        d("reconnect-max-delay", &reconnectMaxDelay)
        d("hip-retry-initial-delay", &hipRetryInitialDelay)
        d("hip-retry-max-delay", &hipRetryMaxDelay)
        d("default-hip-interval", &defaultHIPInterval)
        d("reauth-lead-time", &reauthLeadTime)
        d("reauth-retry-delay", &reauthRetryDelay)
        canReauthenticate = fields["can-reauthenticate"] == "true"
    }
}

/// What the session is doing, for the UI and for logs.
public enum SessionState: Equatable, Sendable {
    case idle
    case connecting(Phase)
    case connected
    /// Waiting to retry; `attempt` counts consecutive failures.
    case reconnecting(attempt: Int, reason: String)
    /// Waiting for the network to come back.
    case waitingForNetwork
    case reauthenticating
    /// The cookie is gone and we cannot log in unattended.
    case needsLogin(reason: String)
    case stopped(reason: String)

    public enum Phase: Equatable, Sendable {
        case config, hip, tunnel
    }
}

/// The session state machine. It does no I/O: feed it events with the current
/// time, carry out the actions it returns, and call `tick` at `nextDeadline`.
/// Time is seconds on a clock that keeps running during sleep.
public struct Session: Sendable {
    public enum Failure: Equatable, Sendable {
        /// The gateway rejected the cookie.
        case cookieRejected(String)
        /// Anything else: network errors, timeouts, unexpected answers.
        case transient(String)

        public init(_ error: any Error) {
            if case GPError.cookieRejected(let m)? = error as? GPError {
                self = .cookieRejected(m)
            } else {
                self = .transient(String(describing: error))
            }
        }
    }

    public enum Event: Equatable, Sendable {
        case start
        case configFetched(GatewayConfig)
        case configFailed(Failure)
        case hipDone
        case hipFailed(Failure)
        case tunnelOpened
        case tunnelFailed(Failure)
        /// The open tunnel ended. nil: closed with no error.
        case tunnelClosed(Failure?)
        /// Any frame arrived on the tunnel, keepalive or data.
        case received
        /// The network path changed. `usable` false means no route out.
        case pathChanged(usable: Bool)
        case sleep
        case wake
        case reauthenticated(AuthCookie)
        /// `needsUser` true: saved credentials are not enough.
        case reauthFailed(Failure, needsUser: Bool)
        /// Stop. `logout` true kills the cookie on the gateway.
        case stop(logout: Bool)
    }

    public enum Action: Equatable, Sendable {
        case fetchConfig(AuthCookie, previousIPv4: String?, previousIPv6: String?)
        /// hipreportcheck, and hipreport if the gateway asks for one.
        case checkHIP(AuthCookie, clientIPv4: String?, clientIPv6: String?)
        case openTunnel(AuthCookie, path: String)
        case closeTunnel
        case sendKeepalive
        case applySettings(GatewayConfig)
        case reauthenticate
        case logout(AuthCookie)
        /// The cookie changed; save it so a restarted extension can reuse it.
        case saveCookie(AuthCookie?)
        case stateChanged(SessionState)
    }

    public private(set) var state: SessionState = .idle
    public private(set) var cookie: AuthCookie
    public private(set) var config: GatewayConfig?
    /// When the cookie expires, if the gateway said.
    public private(set) var expiresAt: Double?
    public let policy: SessionPolicy
    public var hipInterval: Double

    enum Timer: Hashable, Sendable {
        case reconnect, keepalive, hipRecheck, rekey, reauth
    }

    private(set) var deadlines: [Timer: Double] = [:]
    private var tunnelUp = false
    private var tunnelPending = false
    private var lastRx: Double = 0
    private var reconnectAttempt = 0
    private var hipRetryAttempt = 0
    private var hipInFlight = false
    private var configInFlight = false
    private var networkUsable = true
    private var asleep = false
    private var reauthInFlight = false
    /// A reconnect is wanted as soon as the in-flight steps allow.
    private var pendingReason: String?

    public init(cookie: AuthCookie, policy: SessionPolicy = SessionPolicy(), hipInterval: Double? = nil) {
        self.cookie = cookie
        self.policy = policy
        self.hipInterval = hipInterval ?? policy.defaultHIPInterval
    }

    /// The earliest time `tick` needs to run, if any.
    public var nextDeadline: Double? { deadlines.values.min() }

    public var isTunnelUp: Bool { tunnelUp }

    // MARK: Events

    public mutating func handle(_ event: Event, now: Double) -> [Action] {
        var out: [Action] = []
        switch event {
        case .start:
            guard state == .idle else { break }
            beginConnect(now: now, out: &out)

        case .configFetched(let c):
            guard configInFlight else { break }
            configInFlight = false
            let changed = config != c
            config = c
            if let l = c.lifetime, l > 0 {
                expiresAt = now + Double(l)
                let lead = min(policy.reauthLeadTime, Double(l) / 2)
                deadlines[.reauth] = policy.canReauthenticate ? now + Double(l) - lead : nil
            }
            if let r = c.rekeyTimeout {
                // openconnect rekeys a minute early.
                deadlines[.rekey] = now + max(Double(r) - 60, Double(r) / 2)
            } else {
                deadlines[.rekey] = nil
            }
            if changed { out.append(.applySettings(c)) }
            if isStopped { break }
            set(.connecting(.hip), &out)
            hipInFlight = true
            out.append(.checkHIP(cookie, clientIPv4: c.ipv4, clientIPv6: c.ipv6))

        case .configFailed(let f):
            guard configInFlight else { break }
            configInFlight = false
            fail(f, now: now, out: &out)

        case .hipDone:
            guard hipInFlight else { break }
            hipInFlight = false
            hipRetryAttempt = 0
            // A minute early, like openconnect, unless the interval is very short.
            deadlines[.hipRecheck] = now + (hipInterval > 120 ? hipInterval - 60 : max(hipInterval, 1))
            if state == .connecting(.hip) { openTunnel(&out) }

        case .hipFailed(let f):
            guard hipInFlight else { break }
            hipInFlight = false
            if case .cookieRejected = f {
                cookieRejected(f, now: now, out: &out)
                break
            }
            // Retry on its own timer. A failed HIP check never ends the
            // session, and during connect it doesn't hold up the tunnel.
            deadlines[.hipRecheck] = now + backoff(hipRetryAttempt, policy.hipRetryInitialDelay, policy.hipRetryMaxDelay)
            hipRetryAttempt += 1
            if state == .connecting(.hip) { openTunnel(&out) }

        case .tunnelOpened:
            guard tunnelPending else { break }
            tunnelPending = false
            tunnelUp = true
            lastRx = now
            reconnectAttempt = 0
            deadlines[.keepalive] = now + policy.dpdInterval
            set(.connected, &out)

        case .tunnelFailed(let f):
            guard tunnelPending else { break }
            tunnelPending = false
            fail(f, now: now, out: &out)

        case .tunnelClosed(let f):
            guard tunnelUp else { break }
            tunnelUp = false
            deadlines[.keepalive] = nil
            if isStopped || asleep { break }
            fail(f ?? .transient("tunnel closed"), now: now, out: &out)

        case .received:
            lastRx = now

        case .pathChanged(let usable):
            networkUsable = usable
            guard !isStopped, !asleep, state != .idle else { break }
            if usable {
                // Same cookie, right away: the old TCP connection is likely
                // bound to an interface that's gone.
                reconnectAttempt = 0
                reconnect(now: now, reason: "network changed", out: &out)
            } else {
                closeTunnelIfUp(&out)
                deadlines[.reconnect] = nil
                deadlines[.keepalive] = nil
                if !configInFlight && !tunnelPending && !hipInFlight && !reauthInFlight {
                    set(.waitingForNetwork, &out)
                }
            }

        case .sleep:
            guard !isStopped, state != .idle else { break }
            asleep = true
            closeTunnelIfUp(&out)
            deadlines[.keepalive] = nil
            deadlines[.reconnect] = nil

        case .wake:
            guard asleep else { break }
            asleep = false
            if let e = expiresAt, now >= e {
                cookieRejected(.cookieRejected("cookie lifetime ended during sleep"), now: now, out: &out)
                break
            }
            // Timers that came due during sleep fire on the next tick.
            reconnectAttempt = 0
            reconnect(now: now, reason: "woke from sleep", out: &out)

        case .reauthenticated(let c):
            guard reauthInFlight else { break }
            reauthInFlight = false
            let old = cookie
            cookie = c
            out.append(.saveCookie(c))
            if c.authcookie != old.authcookie && state != .reauthenticating {
                out.append(.logout(old))
            }
            reconnectAttempt = 0
            closeTunnelIfUp(&out)
            beginConnect(now: now, out: &out)

        case .reauthFailed(let f, let needsUser):
            guard reauthInFlight else { break }
            reauthInFlight = false
            if needsUser {
                if state == .reauthenticating {
                    needsLogin("login needed: \(describe(f))", out: &out)
                }
                // Early re-auth while the old cookie still works: keep going
                // until the gateway rejects it.
                break
            }
            if state == .reauthenticating {
                // Login itself failed transiently; retry with backoff.
                deadlines[.reauth] = now + backoff(reconnectAttempt, policy.reconnectInitialDelay, policy.reconnectMaxDelay)
                reconnectAttempt += 1
            } else if let e = expiresAt, now + policy.reauthRetryDelay < e {
                deadlines[.reauth] = now + policy.reauthRetryDelay
            }

        case .stop(let logout):
            guard !isStopped else { break }
            closeTunnelIfUp(&out)
            deadlines.removeAll()
            configInFlight = false
            hipInFlight = false
            tunnelPending = false
            reauthInFlight = false
            if logout {
                out.append(.logout(cookie))
                out.append(.saveCookie(nil))
            }
            set(.stopped(reason: logout ? "disconnected" : "stopped"), &out)
        }
        return out
    }

    /// Runs every timer that is due at `now`.
    public mutating func tick(now: Double) -> [Action] {
        var out: [Action] = []
        for t in [Timer.reauth, .rekey, .reconnect, .hipRecheck, .keepalive] {
            guard let d = deadlines[t], d <= now else { continue }
            deadlines[t] = nil
            fire(t, now: now, out: &out)
        }
        return out
    }

    // MARK: Internals

    private var isStopped: Bool {
        switch state {
        case .stopped, .needsLogin: true
        default: false
        }
    }

    private mutating func fire(_ t: Timer, now: Double, out: inout [Action]) {
        if isStopped { return }
        switch t {
        case .keepalive:
            guard tunnelUp else { return }
            if now - lastRx > 2 * policy.dpdInterval {
                closeTunnelIfUp(&out)
                reconnectAttempt = 0
                reconnect(now: now, reason: "dead peer", out: &out)
            } else {
                out.append(.sendKeepalive)
                deadlines[.keepalive] = now + policy.dpdInterval
            }
        case .reconnect:
            if asleep { return }
            if let e = expiresAt, now >= e {
                cookieRejected(.cookieRejected("cookie lifetime ended"), now: now, out: &out)
                return
            }
            if !networkUsable {
                set(.waitingForNetwork, &out)
                return
            }
            beginConnect(now: now, out: &out)
        case .hipRecheck:
            guard !hipInFlight, !asleep else {
                deadlines[.hipRecheck] = now + 60
                return
            }
            // Rechecks run beside the tunnel; it stays up.
            if config == nil || state != .connected {
                // A connect in progress runs its own HIP check.
                deadlines[.hipRecheck] = now + 60
                return
            }
            hipInFlight = true
            out.append(.checkHIP(cookie, clientIPv4: config?.ipv4, clientIPv6: config?.ipv6))
        case .rekey:
            closeTunnelIfUp(&out)
            reconnectAttempt = 0
            reconnect(now: now, reason: "rekey", out: &out)
        case .reauth:
            guard !reauthInFlight else { return }
            reauthInFlight = true
            out.append(.reauthenticate)
        }
    }

    private mutating func beginConnect(now: Double, out: inout [Action]) {
        guard !configInFlight, !tunnelPending, !reauthInFlight else { return }
        deadlines[.reconnect] = nil
        configInFlight = true
        hipInFlight = false
        set(.connecting(.config), &out)
        out.append(.fetchConfig(cookie, previousIPv4: config?.ipv4, previousIPv6: config?.ipv6))
    }

    private mutating func openTunnel(_ out: inout [Action]) {
        guard let c = config else { return }
        set(.connecting(.tunnel), &out)
        tunnelPending = true
        out.append(.openTunnel(cookie, path: c.tunnelPath))
    }

    private mutating func closeTunnelIfUp(_ out: inout [Action]) {
        if tunnelUp || tunnelPending {
            tunnelUp = false
            tunnelPending = false
            out.append(.closeTunnel)
        }
    }

    /// A step of connecting failed, or the tunnel died.
    private mutating func fail(_ f: Failure, now: Double, out: inout [Action]) {
        switch f {
        case .cookieRejected:
            cookieRejected(f, now: now, out: &out)
        case .transient(let why):
            closeTunnelIfUp(&out)
            hipInFlight = false
            scheduleReconnect(now: now, reason: why, out: &out)
        }
    }

    /// Reconnect now if nothing is in flight, else as soon as possible.
    private mutating func reconnect(now: Double, reason: String, out: inout [Action]) {
        closeTunnelIfUp(&out)
        if configInFlight {
            // The answer to the in-flight getconfig is still useful; the
            // tunnel step that follows will use the new path.
            return
        }
        if !networkUsable {
            set(.waitingForNetwork, &out)
            return
        }
        deadlines[.reconnect] = now
        set(.reconnecting(attempt: reconnectAttempt, reason: reason), &out)
    }

    private mutating func scheduleReconnect(now: Double, reason: String, out: inout [Action]) {
        let delay = reconnectAttempt == 0 ? 0 : backoff(reconnectAttempt - 1, policy.reconnectInitialDelay, policy.reconnectMaxDelay)
        reconnectAttempt += 1
        if !networkUsable {
            set(.waitingForNetwork, &out)
            return
        }
        deadlines[.reconnect] = now + delay
        set(.reconnecting(attempt: reconnectAttempt, reason: reason), &out)
    }

    private mutating func cookieRejected(_ f: Failure, now: Double, out: inout [Action]) {
        closeTunnelIfUp(&out)
        configInFlight = false
        tunnelPending = false
        hipInFlight = false
        deadlines.removeAll()
        out.append(.saveCookie(nil))
        if policy.canReauthenticate {
            set(.reauthenticating, &out)
            if !reauthInFlight {
                reauthInFlight = true
                out.append(.reauthenticate)
            }
        } else {
            needsLogin(describe(f), out: &out)
        }
    }

    private mutating func needsLogin(_ reason: String, out: inout [Action]) {
        closeTunnelIfUp(&out)
        deadlines.removeAll()
        set(.needsLogin(reason: reason), &out)
    }

    private func describe(_ f: Failure) -> String {
        switch f {
        case .cookieRejected(let m), .transient(let m): m
        }
    }

    private mutating func set(_ s: SessionState, _ out: inout [Action]) {
        if state != s {
            state = s
            out.append(.stateChanged(s))
        }
    }
}

func backoff(_ attempt: Int, _ initial: Double, _ max: Double) -> Double {
    var d = initial
    for _ in 0..<min(attempt, 30) { d *= 2 }
    return Swift.min(d, max)
}
