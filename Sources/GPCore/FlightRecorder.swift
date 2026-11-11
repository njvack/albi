import Synchronization

/// What diagnostics mode keeps: a rolling window of the session's inputs,
/// outputs and HTTPS exchanges, and the incident rules that decide when the
/// window is worth saving. It holds raw values; redaction happens when a dump
/// is written (see the Diagnostics target), never here, except that
/// passwords and HIP report bodies are never stored at all.
///
/// Times are seconds on the session's clock.
public final class FlightRecorder: Sendable {
    public struct Policy: Equatable, Sendable {
        /// How much history to keep.
        public var window: Double = 600
        /// Rough upper bound on what the buffer holds, in bytes of text.
        public var maxBytes = 8 << 20
        /// How long the session may be out of `connected`, while awake with a
        /// usable network, before the outage counts as an incident.
        public var grace: Double = 60
        /// How long after a dump an incident still open is closed anyway.
        public var aftermath: Double = 600
        /// Response bodies longer than this are cut.
        public var maxBody = 64 << 10

        public init() {}
    }

    /// One HTTPS request and its outcome.
    public struct HTTP: Equatable, Sendable {
        public var server: String
        public var method: String
        public var path: String
        /// The request form, with the password replaced.
        public var request: Form
        public var status: Int?
        public var body: String?
        /// The response body was longer than this many bytes and was cut.
        public var truncatedFrom: Int?
        public var error: String?
        public var duration: Double
    }

    /// Traffic through the tunnel over one interval. Contents are never kept.
    public struct Traffic: Equatable, Sendable {
        public var start: Double
        public var end: Double
        public var packetsIn = 0, bytesIn = 0, packetsOut = 0, bytesOut = 0
        public var keepalivesIn = 0, keepalivesOut = 0

        var isEmpty: Bool { packetsIn + packetsOut + keepalivesIn + keepalivesOut == 0 }
    }

    public enum Trace: Equatable, Sendable {
        /// An input to the session state machine.
        case event(Session.Event)
        /// An output of it, other than `stateChanged`.
        case action(Session.Action)
        case state(SessionState)
        case http(HTTP)
        case traffic(Traffic)
        case log(String)
        /// The incident rules fired (open, dump, close).
        case incident(String)
    }

    public struct Entry: Equatable, Sendable {
        public var seq: Int
        public var time: Double
        public var trace: Trace
    }

    /// What the recorder tells its owner.
    public enum Signal: Equatable, Sendable {
        /// Write a dump now. `reason` is one line.
        case dump(id: Int, reason: String)
        /// The incident `id` ended; rewrite its dump with what followed.
        case closed(id: Int, outcome: String)
    }

    /// The window plus the pinned setup exchanges, as of `time`.
    public struct Snapshot: Equatable, Sendable {
        public var time: Double
        /// Setup exchanges and session events older than the window, oldest first.
        public var pinned: [Entry]
        public var entries: [Entry]
        public var info: [String: String]
        /// Entries dropped from the front of the window since recording began.
        public var dropped: Int
    }

    public let policy: Policy
    private let state: Mutex<State>
    private let notify: @Sendable (Signal) -> Void

    /// `notify` is called with the lock released, on whatever thread recorded
    /// the entry that fired the rule.
    public init(policy: Policy = Policy(), notify: @escaping @Sendable (Signal) -> Void = { _ in }) {
        self.policy = policy
        self.notify = notify
        state = Mutex(State(policy: policy))
    }

    // MARK: Recording

    public func record(_ trace: Trace, at time: Double) {
        let signals = state.withLock { $0.append(trace, at: time) }
        for s in signals { notify(s) }
    }

    /// Records one HTTPS exchange. Drops the password and HIP report fields
    /// and cuts long bodies.
    public func recordHTTP(server: String, request: HTTPRequest, response: HTTPResponse?, error: (any Error)?,
                           start: Double, end: Double) {
        var form = Form()
        for (name, value) in request.body.fields {
            switch name.lowercased() {
            case "passwd", "password": form.append(name, value.isEmpty ? "" : "(password)")
            case "report": form.append(name, "(\(value.utf8.count) bytes)")
            default: form.append(name, value)
            }
        }
        var body = response?.body
        var cut: Int?
        if let b = body, b.utf8.count > policy.maxBody {
            cut = b.utf8.count
            body = String(decoding: b.utf8.prefix(policy.maxBody), as: UTF8.self)
        }
        let h = HTTP(server: server, method: request.method, path: request.path, request: form,
                     status: response?.status, body: body, truncatedFrom: cut,
                     error: error.map { String(describing: $0) }, duration: end - start)
        record(.http(h), at: end)
    }

    /// Counts tunnel traffic; folded into one entry per second.
    public func count(at time: Double, packetsIn: Int = 0, bytesIn: Int = 0, packetsOut: Int = 0, bytesOut: Int = 0,
                      keepalivesIn: Int = 0, keepalivesOut: Int = 0) {
        state.withLock {
            $0.count(at: time, packetsIn, bytesIn, packetsOut, bytesOut, keepalivesIn, keepalivesOut)
        }
    }

    /// Free-form facts for the dump header: versions, server, transport.
    public func setInfo(_ key: String, _ value: String?) {
        state.withLock { $0.info[key] = value }
    }

    /// Runs the time-based incident rules. Call every few seconds.
    public func poll(now: Double) {
        let signals = state.withLock { $0.poll(now: now) }
        for s in signals { notify(s) }
    }

    /// Asks for a dump now, whatever the session is doing ("Save diagnostics
    /// now"). Returns the incident id the dump belongs to.
    @discardableResult
    public func requestDump(reason: String, now: Double) -> Int {
        let (id, signals) = state.withLock { $0.manual(reason: reason, now: now) }
        for s in signals { notify(s) }
        return id
    }

    public func snapshot(now: Double) -> Snapshot {
        state.withLock { $0.snapshot(now: now) }
    }

    /// Entries recorded after `seq`, for the aftermath of an incident.
    public func entries(after seq: Int) -> [Entry] {
        state.withLock { s in s.entries.filter { $0.seq > seq } }
    }

    // MARK: State

    struct State {
        let policy: Policy
        var entries: [Entry] = []
        var bytes = 0
        var dropped = 0
        var seq = 0
        var pinned: [String: Entry] = [:]
        /// Every session event since recording began (they are rare: no
        /// `.received`), so a dump can replay the session from its start.
        var spine: [Entry] = []
        var info: [String: String] = [:]
        var traffic: Traffic?
        var rules = IncidentRules()

        init(policy: Policy) {
            self.policy = policy
            rules.grace = policy.grace
            rules.aftermath = policy.aftermath
        }

        mutating func append(_ trace: Trace, at time: Double) -> [Signal] {
            flushTraffic(before: time, force: true)
            let e = add(trace, at: time)
            if case .http(let h) = trace, let key = Self.pinKey(h.path) { pinned[key] = e }
            if case .event = trace {
                spine.append(e)
                if spine.count > 5000 { spine.removeFirst(1000) }
            }
            var out: [Signal] = []
            for s in rules.observe(trace, at: time) {
                out.append(s)
                note(s, at: time)
            }
            trim(now: time)
            return out
        }

        @discardableResult
        mutating func add(_ trace: Trace, at time: Double) -> Entry {
            seq += 1
            let e = Entry(seq: seq, time: time, trace: trace)
            entries.append(e)
            bytes += Self.size(trace)
            return e
        }

        mutating func note(_ s: Signal, at time: Double) {
            switch s {
            case .dump(let id, let reason): add(.incident("dump #\(id): \(reason)"), at: time)
            case .closed(let id, let outcome): add(.incident("closed #\(id): \(outcome)"), at: time)
            }
        }

        mutating func count(at time: Double, _ pi: Int, _ bi: Int, _ po: Int, _ bo: Int, _ ki: Int, _ ko: Int) {
            flushTraffic(before: time, force: false)
            var t = traffic ?? Traffic(start: time, end: time)
            t.end = time
            t.packetsIn += pi; t.bytesIn += bi; t.packetsOut += po; t.bytesOut += bo
            t.keepalivesIn += ki; t.keepalivesOut += ko
            traffic = t
        }

        /// Closes the open traffic interval if it is a second old, or always
        /// when another entry is about to be added, so entries stay in order.
        mutating func flushTraffic(before time: Double, force: Bool) {
            guard let t = traffic, force || time - t.start >= 1 else { return }
            traffic = nil
            if !t.isEmpty { add(.traffic(t), at: t.end) }
        }

        mutating func poll(now: Double) -> [Signal] {
            flushTraffic(before: now, force: false)
            var out: [Signal] = []
            for s in rules.tick(now: now) {
                out.append(s)
                note(s, at: now)
            }
            trim(now: now)
            return out
        }

        mutating func manual(reason: String, now: Double) -> (Int, [Signal]) {
            flushTraffic(before: now, force: true)
            let (id, signals) = rules.manual(reason: reason, now: now)
            for s in signals { note(s, at: now) }
            return (id, signals)
        }

        mutating func trim(now: Double) {
            // While an incident is open, keep everything since it began, so
            // its aftermath can still be written.
            let floor = rules.openSince.map { min($0, now - policy.window) } ?? (now - policy.window)
            var n = 0
            var freed = 0
            while n < entries.count, entries[n].time < floor || bytes - freed > policy.maxBytes {
                freed += Self.size(entries[n].trace)
                n += 1
            }
            if n > 0 {
                entries.removeFirst(n)
                bytes -= freed
                dropped += n
            }
        }

        func snapshot(now: Double) -> Snapshot {
            var all = entries
            if let t = traffic, !t.isEmpty { all.append(Entry(seq: seq, time: t.end, trace: .traffic(t))) }
            let first = all.first?.seq ?? Int.max
            let old = (Array(pinned.values) + spine).filter { $0.seq < first }.sorted { $0.seq < $1.seq }
            return Snapshot(time: now, pinned: old, entries: all, info: info, dropped: dropped)
        }

        /// The setup exchanges worth keeping beyond the window: the latest of
        /// each kind.
        static func pinKey(_ path: String) -> String? {
            let p = String(path.split(separator: "?", maxSplits: 1).first ?? "")
            switch p {
            case "/global-protect/prelogin.esp", "/global-protect/getconfig.esp",
                 "/ssl-vpn/prelogin.esp", "/ssl-vpn/login.esp", "/ssl-vpn/getconfig.esp":
                return p
            default:
                return nil
            }
        }

        static func size(_ t: Trace) -> Int {
            switch t {
            case .http(let h): 200 + h.path.utf8.count + h.request.encoded.utf8.count + (h.body?.utf8.count ?? 0)
            case .log(let s), .incident(let s): 64 + s.utf8.count
            default: 160
            }
        }
    }
}

/// When an outage becomes an incident. Pure logic, fed in time order.
///
/// The session is "out" whenever it has started and is not connected. Time
/// out only counts while awake with a usable network, so sleep and a dead
/// Wi-Fi don't fire it, but a failure to come back after wake does. Out for
/// longer than `grace` of counted time is an incident and gets a dump. So
/// does reaching `needsLogin` while the cookie should still be valid. The
/// incident closes on the next `connected`, a stop, or `aftermath` after the
/// dump.
struct IncidentRules: Sendable {
    var grace: Double = 60
    var aftermath: Double = 600

    private(set) var openSince: Double?
    private var counted: Double = 0
    private var countingSince: Double?
    private var awake = true
    private var usable = true
    private var connected = false
    private var started = false
    private var expiresAt: Double?
    private var lastReason = "not connected"
    private var nextID = 1
    /// The incident that has had its dump.
    private var dumped: (id: Int, at: Double)?
    /// An incident closed by `aftermath` while still out: no new dump until
    /// the session connects or stops.
    private var quiet = false

    mutating func observe(_ t: FlightRecorder.Trace, at now: Double) -> [FlightRecorder.Signal] {
        var out: [FlightRecorder.Signal] = []
        switch t {
        case .event(let e):
            switch e {
            case .start:
                started = true
                goOut(now: now)
            case .sleep:
                pause(now: now)
                awake = false
            case .wake:
                awake = true
                resume(now: now)
            case .pathChanged(let u):
                if u {
                    usable = true
                    resume(now: now)
                } else {
                    pause(now: now)
                    usable = false
                }
            case .configFetched(let c):
                if let l = c.lifetime, l > 0 { expiresAt = now + Double(l) }
            case .stop:
                out += close(now: now, outcome: "stopped")
                started = false
                quiet = false
            default:
                break
            }
        case .state(let s):
            switch s {
            case .connected:
                connected = true
                quiet = false
                out += close(now: now, outcome: "connected again")
            case .reconnecting(_, let reason):
                lastReason = reason
                if connected { connected = false; goOut(now: now) }
            case .connecting, .waitingForNetwork, .reauthenticating:
                if connected { connected = false; goOut(now: now) }
            case .needsLogin(let reason):
                connected = false
                if started, expiresAt.map({ now < $0 - 30 }) ?? true {
                    if openSince == nil { goOut(now: now) }
                    quiet = false
                    out += dump(now: now, reason: "login needed before the cookie's lifetime ended: \(reason)")
                }
                out += close(now: now, outcome: "login needed: \(reason)")
                started = false
            case .stopped:
                out += close(now: now, outcome: "stopped")
                started = false
            case .idle:
                break
            }
        default:
            break
        }
        out += tick(now: now)
        return out
    }

    mutating func tick(now: Double) -> [FlightRecorder.Signal] {
        if let d = dumped, now - d.at >= aftermath {
            let out = close(now: now, outcome: "still not connected \(Int(now - d.at)) s after the dump")
            if started && !connected { quiet = true }
            return out
        }
        guard openSince != nil, dumped == nil, !quiet else { return [] }
        let total = counted + (countingSince.map { now - $0 } ?? 0)
        guard total >= grace else { return [] }
        return dump(now: now, reason: "not connected for \(Int(total.rounded(.up))) s with a usable network (last: \(lastReason))")
    }

    mutating func manual(reason: String, now: Double) -> (Int, [FlightRecorder.Signal]) {
        if let d = dumped { return (d.id, []) }
        if openSince == nil { openSince = now }
        let s = dump(now: now, reason: reason)
        return (dumped?.id ?? 0, s)
    }

    private mutating func goOut(now: Double) {
        guard openSince == nil else { return }
        openSince = now
        counted = 0
        countingSince = awake && usable ? now : nil
    }

    private mutating func pause(now: Double) {
        if let s = countingSince { counted += now - s }
        countingSince = nil
    }

    private mutating func resume(now: Double) {
        if openSince != nil, countingSince == nil, awake, usable { countingSince = now }
    }

    private mutating func dump(now: Double, reason: String) -> [FlightRecorder.Signal] {
        guard dumped == nil else { return [] }
        let id = nextID
        nextID += 1
        dumped = (id, now)
        return [.dump(id: id, reason: reason)]
    }

    private mutating func close(now: Double, outcome: String) -> [FlightRecorder.Signal] {
        defer {
            openSince = nil
            counted = 0
            countingSince = nil
            dumped = nil
        }
        guard let d = dumped else { return [] }
        return [.closed(id: d.id, outcome: outcome)]
    }
}

/// Records every HTTPS exchange that passes through it. Wrap the connector
/// before login so the recorder sees the login too; `SessionRunner` wraps one
/// itself if it was given a recorder and an unwrapped connector.
public struct RecordingConnector: GatewayConnector {
    public let base: any GatewayConnector
    public let recorder: FlightRecorder
    public let clock: any SessionClock

    public init(_ base: any GatewayConnector, recorder: FlightRecorder, clock: any SessionClock) {
        self.base = base
        self.recorder = recorder
        self.clock = clock
    }

    public func send(_ request: HTTPRequest, to server: String) async throws -> HTTPResponse {
        let start = clock.now()
        do {
            let r = try await base.send(request, to: server)
            recorder.recordHTTP(server: server, request: request, response: r, error: nil, start: start, end: clock.now())
            return r
        } catch {
            recorder.recordHTTP(server: server, request: request, response: nil, error: error, start: start, end: clock.now())
            throw error
        }
    }

    public func openTunnel(to server: String) async throws -> any TunnelConnection {
        try await base.openTunnel(to: server)
    }
}

/// Forwards to a host and records its log lines.
struct RecordingHost: TunnelHost {
    let base: any TunnelHost
    let recorder: FlightRecorder
    let clock: any SessionClock

    func apply(_ settings: TunnelSettings) async throws { try await base.apply(settings) }
    func deliver(_ packets: [[UInt8]]) { base.deliver(packets) }
    func stateChanged(_ state: SessionState) { base.stateChanged(state) }
    func hipReport(_ context: HIPContext) async throws -> String? { try await base.hipReport(context) }
    func reauthenticate() async throws -> AuthCookie { try await base.reauthenticate() }
    func saveCookie(_ cookie: AuthCookie?) { base.saveCookie(cookie) }
    func log(_ message: String) {
        // State changes are recorded as such.
        if !message.hasPrefix("state: ") { recorder.record(.log(message), at: clock.now()) }
        base.log(message)
    }
}
