/// A TLS byte stream to the gateway, used for the tunnel.
public protocol TunnelConnection: Sendable {
    /// Writes in call order. Callers must not overlap calls.
    func write(_ bytes: [UInt8]) async throws
    /// Returns the next bytes, or nil at end of stream.
    func read() async throws -> [UInt8]?
    func close()
}

/// The network side: HTTPS requests plus a raw TLS connection for the tunnel.
public protocol GatewayConnector: HTTPTransport {
    func openTunnel(to server: String) async throws -> any TunnelConnection
}

/// What the HIP reporter needs; the same values openconnect passes to
/// a --csd-wrapper script.
public struct HIPContext: Equatable, Sendable {
    public var cookie: AuthCookie
    public var clientIPv4: String?
    public var clientIPv6: String?
    public var md5: String
    public var clientOS: String
    public var appVersion: String
}

/// The OS side of a session: packets, settings, secrets and HIP.
public protocol TunnelHost: Sendable {
    /// Applies network settings. Called again whenever getconfig changes.
    func apply(_ settings: TunnelSettings) async throws
    /// Packets from the gateway, to hand to the OS.
    func deliver(_ packets: [[UInt8]])
    func stateChanged(_ state: SessionState)
    /// The HIP report XML, or nil to skip submitting one.
    func hipReport(_ context: HIPContext) async throws -> String?
    /// Logs in again with saved credentials. Throw `StoredCredentials.NeedsUser`
    /// (or `GPError.badCredentials`) when the user has to step in.
    func reauthenticate() async throws -> AuthCookie
    func saveCookie(_ cookie: AuthCookie?)
    func log(_ message: String)
}

/// A clock that keeps counting during sleep, in seconds.
public protocol SessionClock: Sendable {
    func now() -> Double
    func sleep(until deadline: Double) async throws
}

public struct ContinuousSessionClock: SessionClock {
    private let origin = ContinuousClock.now

    public init() {}

    public func now() -> Double {
        let d = ContinuousClock.now - origin
        return Double(d.components.seconds) + Double(d.components.attoseconds) / 1e18
    }

    public func sleep(until deadline: Double) async throws {
        let delay = deadline - now()
        if delay > 0 {
            // Whole milliseconds, rounded up (no libm needed).
            try await Task.sleep(for: .milliseconds(Int64(delay * 1000) + 1))
        }
    }
}

/// Runs a `Session` against real (or fake) I/O. All protocol work happens
/// here; the OS-specific parts come in through `GatewayConnector` and
/// `TunnelHost`.
public actor SessionRunner {
    public let server: String
    public let client: ClientInfo
    private var session: Session
    private let io: any GatewayConnector
    private let host: any TunnelHost
    private let clock: any SessionClock

    private var tunnel: (any TunnelConnection)?
    private var writer: AsyncStream<[UInt8]>.Continuation?
    private var tunnelGen = 0
    private var configGen = 0
    private var hipGen = 0
    private var reauthGen = 0
    private var timerTask: Task<Void, Never>?
    private var timerDeadline: Double?
    private var pending: [Task<Void, Never>] = []
    private var waiters: [CheckedContinuation<SessionState, Never>] = []

    public init(server: String, client: ClientInfo, session: Session, io: any GatewayConnector,
                host: any TunnelHost, clock: any SessionClock = ContinuousSessionClock()) {
        self.server = server
        self.client = client
        self.session = session
        self.io = io
        self.host = host
        self.clock = clock
    }

    public var state: SessionState { session.state }
    public var cookie: AuthCookie { session.cookie }
    public var config: GatewayConfig? { session.config }

    public func start() { post(.start) }

    /// Feeds an event from outside: path changes, sleep and wake.
    public func post(_ event: Session.Event) {
        run(session.handle(event, now: clock.now()))
    }

    /// Stops the session and waits for the logout request, if any, to finish.
    public func stop(logout: Bool) async {
        post(.stop(logout: logout))
        let tasks = pending
        pending = []
        for t in tasks { await t.value }
    }

    /// Returns once the session is stopped or needs a login.
    public func waitUntilFinished() async -> SessionState {
        if isFinal(session.state) { return session.state }
        return await withCheckedContinuation { waiters.append($0) }
    }

    /// Packets from the OS to send through the tunnel. Dropped while the
    /// tunnel is down, as a real link would.
    public func send(packets: [[UInt8]]) {
        guard let w = writer, session.isTunnelUp else { return }
        var buf: [UInt8] = []
        for p in packets where !p.isEmpty { buf += GPST.encode(packet: p) }
        if !buf.isEmpty { w.yield(buf) }
    }

    // MARK: Actions

    private func run(_ actions: [Session.Action]) {
        for a in actions { perform(a) }
        rescheduleTimer()
    }

    private func perform(_ action: Session.Action) {
        switch action {
        case .stateChanged(let s):
            host.log("state: \(s)")
            host.stateChanged(s)
            if isFinal(s) {
                timerTask?.cancel()
                let ws = waiters
                waiters = []
                for w in ws { w.resume(returning: s) }
            }
        case .fetchConfig(let cookie, let v4, let v6):
            configGen += 1
            let gen = configGen
            spawn { [io, server, client] in
                let ev: Session.Event
                do {
                    let resp = try await io.send(Requests.getConfig(cookie, client: client, previousIPv4: v4, previousIPv6: v6), to: server)
                    if resp.body.trimmingXMLWhitespace() == "errors getting SSL/VPN config" {
                        throw GPError.cookieRejected("errors getting SSL/VPN config")
                    }
                    ev = .configFetched(try GatewayConfig(Reply.document(status: resp.status, body: resp.body)))
                } catch {
                    ev = .configFailed(Session.Failure(error))
                }
                await self.result(ev, gen: gen, of: .config)
            }
        case .applySettings(let c):
            // gw-address is the gateway's own IP; NE wants an address here.
            let settings = TunnelSettings(config: c, remoteAddress: c.gatewayAddress ?? hostOnly(server))
            if !settings.ignoredRoutes.isEmpty { host.log("ignored routes: \(settings.ignoredRoutes)") }
            spawn { [host] in
                do { try await host.apply(settings) } catch { host.log("applying settings failed: \(error)") }
            }
        case .checkHIP(let cookie, let v4, let v6):
            hipGen += 1
            let gen = hipGen
            let ctx = HIPContext(cookie: cookie, clientIPv4: v4, clientIPv6: v6, md5: cookie.hipToken,
                                 clientOS: client.clientOS, appVersion: client.appVersion)
            spawn { [io, server, host] in
                let ev: Session.Event
                do {
                    let resp = try await io.send(Requests.hipReportCheck(cookie, clientIPv4: v4, clientIPv6: v6), to: server)
                    let needed = try Requests.hipReportNeeded(Reply.document(status: resp.status, body: resp.body))
                    if needed {
                        if let report = try await host.hipReport(ctx) {
                            let r = try await io.send(Requests.hipReport(cookie, clientIPv4: v4, clientIPv6: v6, report: report), to: server)
                            _ = try Reply.document(status: r.status, body: r.body)
                            host.log("HIP report submitted (\(report.utf8.count) bytes)")
                        } else {
                            host.log("gateway asked for a HIP report, but none is available")
                        }
                    }
                    ev = .hipDone
                } catch {
                    host.log("HIP check failed: \(error)")
                    ev = .hipFailed(Session.Failure(error))
                }
                await self.result(ev, gen: gen, of: .hip)
            }
        case .openTunnel(let cookie, let path):
            tunnelGen += 1
            let gen = tunnelGen
            spawn { [io, server] in
                do {
                    let conn = try await io.openTunnel(to: server)
                    do {
                        try await conn.write(GPST.tunnelRequest(path: path, cookie: cookie))
                        var hs = GPST.Handshake()
                        var leftover: [UInt8]?
                        while leftover == nil {
                            guard let bytes = try await conn.read() else { throw hs.closed() }
                            switch hs.feed(bytes) {
                            case .started(let rest): leftover = rest
                            case .rejected(let e): throw e
                            case nil: continue
                            }
                        }
                        await self.tunnelStarted(conn, leftover: leftover!, gen: gen)
                    } catch {
                        conn.close()
                        throw error
                    }
                } catch {
                    await self.result(.tunnelFailed(Session.Failure(error)), gen: gen, of: .tunnel)
                }
            }
        case .closeTunnel:
            tunnelGen += 1
            closeCurrentTunnel()
        case .sendKeepalive:
            writer?.yield(GPST.keepaliveFrame)
        case .reauthenticate:
            reauthGen += 1
            let gen = reauthGen
            spawn { [host] in
                let ev: Session.Event
                do {
                    ev = .reauthenticated(try await host.reauthenticate())
                } catch is StoredCredentials.NeedsUser {
                    ev = .reauthFailed(.transient("saved credentials are not enough"), needsUser: true)
                } catch GPError.badCredentials(let m) {
                    ev = .reauthFailed(.transient(m), needsUser: true)
                } catch GPError.cancelled {
                    ev = .reauthFailed(.transient("cancelled"), needsUser: true)
                } catch {
                    ev = .reauthFailed(Session.Failure(error), needsUser: false)
                }
                await self.result(ev, gen: gen, of: .reauth)
            }
        case .logout(let cookie):
            spawn { [io, server, host] in
                do {
                    let r = try await io.send(Requests.logout(cookie), to: server)
                    _ = try Reply.document(status: r.status, body: r.body)
                    host.log("logged out")
                } catch {
                    host.log("logout failed: \(error)")
                }
            }
        case .saveCookie(let c):
            host.saveCookie(c)
        }
    }

    private func spawn(_ body: @escaping @Sendable () async -> Void) {
        pending.removeAll { $0.isCancelled }
        let t = Task { await body() }
        pending.append(t)
        // Drop finished tasks now and then so the list doesn't grow.
        if pending.count > 64 {
            pending = Array(pending.suffix(16))
        }
    }

    private enum Op { case config, hip, tunnel, reauth }

    /// Posts a result unless a newer request of the same kind replaced it.
    private func result(_ event: Session.Event, gen: Int, of op: Op) {
        let current = switch op {
        case .config: configGen
        case .hip: hipGen
        case .tunnel: tunnelGen
        case .reauth: reauthGen
        }
        guard current == gen else { return }
        post(event)
    }

    private func tunnelStarted(_ conn: any TunnelConnection, leftover: [UInt8], gen: Int) {
        guard gen == tunnelGen else {
            conn.close()
            return
        }
        closeCurrentTunnel()
        tunnel = conn
        let (stream, cont) = AsyncStream<[UInt8]>.makeStream()
        writer = cont
        post(.tunnelOpened)
        Task { [weak self] in
            do {
                for await chunk in stream { try await conn.write(chunk) }
            } catch {
                await self?.tunnelEnded(gen: gen, failure: .transient("write: \(error)"))
            }
        }
        Task { [weak self] in
            var dec = GPST.Decoder()
            dec.append(leftover)
            do {
                while true {
                    var packets: [[UInt8]] = []
                    var any = false
                    while let f = try dec.next() {
                        any = true
                        if case .packet(let p) = f { packets.append(p) }
                    }
                    if any { await self?.received(packets, gen: gen) }
                    guard let bytes = try await conn.read() else {
                        await self?.tunnelEnded(gen: gen, failure: nil)
                        return
                    }
                    dec.append(bytes)
                }
            } catch {
                await self?.tunnelEnded(gen: gen, failure: .transient("read: \(error)"))
            }
        }
    }

    private func received(_ packets: [[UInt8]], gen: Int) {
        guard gen == tunnelGen else { return }
        if !packets.isEmpty { host.deliver(packets) }
        post(.received)
    }

    private func tunnelEnded(gen: Int, failure: Session.Failure?) {
        guard gen == tunnelGen else { return }
        closeCurrentTunnel()
        post(.tunnelClosed(failure))
    }

    private func closeCurrentTunnel() {
        writer?.finish()
        writer = nil
        tunnel?.close()
        tunnel = nil
    }

    private func rescheduleTimer() {
        let next = isFinal(session.state) ? nil : session.nextDeadline
        guard next != timerDeadline else { return }
        timerTask?.cancel()
        timerDeadline = next
        guard let d = next else { return }
        timerTask = Task { [clock, weak self] in
            do { try await clock.sleep(until: d) } catch { return }
            await self?.timerFired(d)
        }
    }

    private func timerFired(_ d: Double) {
        guard timerDeadline == d else { return }
        timerDeadline = nil
        run(session.tick(now: clock.now()))
    }

    private func isFinal(_ s: SessionState) -> Bool {
        switch s {
        case .stopped, .needsLogin: true
        default: false
        }
    }
}

/// `host:port` → `host`; handles bracketed IPv6.
func hostOnly(_ server: String) -> String {
    if server.hasPrefix("["), let end = server.firstIndex(of: "]") {
        return String(server[server.index(after: server.startIndex)..<end])
    }
    let parts = server.split(separator: ":")
    return parts.count == 2 ? String(parts[0]) : server
}
