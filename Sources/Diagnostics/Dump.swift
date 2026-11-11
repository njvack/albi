import Foundation
import GPCapture
import GPCore

/// What the redactor should know beyond what the recorded exchanges teach it:
/// values the client holds that may never appear in a recorded request.
public struct KnownSecrets: Sendable {
    public var password: String?
    public var cookies: [AuthCookie] = []
    public var servers: [String] = []
    public var computer: String?
    public var localAccount: String?
    /// Words to scrub everywhere, such as the organization's name.
    public var words: [String] = []

    public init(password: String? = nil, cookies: [AuthCookie] = [], servers: [String] = [],
                computer: String? = nil, localAccount: String? = nil, words: [String] = []) {
        self.password = password
        self.cookies = cookies
        self.servers = servers
        self.computer = computer
        self.localAccount = localAccount
        self.words = words
    }
}

/// Turns recorder entries into the incident file: redacted JSON with one
/// event per line.
public struct DumpWriter {
    public static let format = "albi-incident/1"

    public struct Incident: Sendable {
        public var id: Int
        public var reason: String
        /// How it ended, once it has.
        public var outcome: String?
        public var written: Date
        public var snapshot: FlightRecorder.Snapshot
        /// Entries after the snapshot, for a rewrite once the incident closes.
        public var aftermath: [FlightRecorder.Entry] = []
        public var recorderPolicy: FlightRecorder.Policy

        public init(id: Int, reason: String, outcome: String? = nil, written: Date = Date(),
                    snapshot: FlightRecorder.Snapshot, aftermath: [FlightRecorder.Entry] = [],
                    recorderPolicy: FlightRecorder.Policy) {
            self.id = id
            self.reason = reason
            self.outcome = outcome
            self.written = written
            self.snapshot = snapshot
            self.aftermath = aftermath
            self.recorderPolicy = recorderPolicy
        }
    }

    public struct Result: Sendable {
        public var text: String
        /// Values still holding something the redactor had learned, replaced
        /// whole by a placeholder.
        public var withheld: Int
        /// How many values the redactor learned to hide.
        public var learned: Int
    }

    public static func write(_ incident: Incident, secrets: KnownSecrets) -> Result {
        let s = incident.snapshot
        let all = s.pinned.map { ($0, true) } + s.entries.map { ($0, false) } + incident.aftermath.map { ($0, false) }
        var r = makeRedactor(entries: all.map(\.0), info: s.info, secrets: secrets)
        var withheld = 0
        func red(_ v: String) -> String {
            let out = r.redact(v)
            if !r.leaks(in: out).isEmpty {
                withheld += 1
                return "(withheld: still held a value the redactor learned)"
            }
            return out
        }
        func redForm(_ v: String) -> String {
            let out = r.redactForm(v)
            if !r.leaks(in: out).isEmpty {
                withheld += 1
                return "(withheld: still held a value the redactor learned)"
            }
            return out
        }
        func redTarget(_ v: String) -> String {
            let out = r.redactTarget(v)
            if !r.leaks(in: out).isEmpty {
                withheld += 1
                return "(withheld)"
            }
            return out
        }
        let red3 = Redactors(text: red, form: redForm, target: redTarget)

        var lines: [String] = []
        let afterSeq = incident.aftermath.first?.seq
        for (e, pinned) in all {
            var o = encode(e, red3)
            if pinned { o["pinned"] = true }
            if let a = afterSeq, e.seq >= a { o["after"] = true }
            lines.append(json(o, pretty: false))
        }

        var info: [String: String] = [:]
        for (k, v) in s.info { info[k] = red(v) }
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime]
        var header: [String: Any] = [
            "id": incident.id,
            "reason": red(incident.reason),
            "written": iso.string(from: incident.written),
            "clock": s.time,
            "window_seconds": incident.recorderPolicy.window,
            "grace_seconds": incident.recorderPolicy.grace,
            "dropped_before_window": s.dropped,
            "info": info,
            "redaction": [
                "learned": r.learnedCount,
                "withheld": withheld,
                "note": "Read this file before sharing it: free text the redactor doesn't recognise is only covered by its pattern sweeps.",
            ] as [String: Any],
            "system": [
                "os": ProcessInfo.processInfo.operatingSystemVersionString,
                "albi": Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev",
            ],
        ]
        if let o = incident.outcome { header["outcome"] = red(o) }

        var text = "{\n\"format\": \"\(format)\",\n\"header\": " + json(header, pretty: true) + ",\n\"events\": [\n"
        text += lines.joined(separator: ",\n")
        text += "\n]\n}\n"
        return Result(text: text, withheld: withheld, learned: r.learnedCount)
    }

    struct Redactors {
        var text: (String) -> String
        var form: (String) -> String
        var target: (String) -> String
    }

    static func makeRedactor(entries: [FlightRecorder.Entry], info: [String: String], secrets: KnownSecrets) -> Redactor {
        var r = Redactor(password: secrets.password, words: secrets.words)
        r.learnLocal(account: secrets.localAccount, hostNames: secrets.computer.map { [$0] } ?? [])
        for c in secrets.cookies {
            for (name, value) in c.form.fields { r.learn(field: name, value: value) }
        }
        var exchanges: [Exchange] = []
        for e in entries {
            switch e.trace {
            case .http(let h):
                exchanges.append(Exchange(
                    method: h.method, target: h.path,
                    requestHeaders: [HTTPHeader(name: "Host", value: h.server),
                                     HTTPHeader(name: "Content-Type", value: HTTPRequest.contentType)],
                    requestBody: h.request.encoded, statusLine: h.status.map { "HTTP/1.1 \($0)" },
                    responseBody: h.body))
            case .event(.reauthenticated(let c)):
                for (name, value) in c.form.fields { r.learn(field: name, value: value) }
            default:
                break
            }
        }
        r.learn(CaptureLog(exchanges: exchanges))
        for s in secrets.servers + [info["server"]].compactMap({ $0 }) { r.learnHost(s) }
        return r
    }

    // MARK: Encoding

    static func encode(_ e: FlightRecorder.Entry, _ red: Redactors) -> [String: Any] {
        var o: [String: Any] = ["seq": e.seq, "t": round3(e.time)]
        switch e.trace {
        case .event(let ev):
            o["kind"] = "event"
            o.merge(encode(ev, red)) { a, _ in a }
        case .action(let a):
            o["kind"] = "action"
            o.merge(encode(a, red)) { a, _ in a }
        case .state(let st):
            o["kind"] = "state"
            o["state"] = red.text(label(st))
        case .http(let h):
            o["kind"] = "http"
            o["server"] = red.text(h.server)
            o["method"] = h.method
            o["path"] = red.target(h.path)
            if !h.request.fields.isEmpty { o["request"] = red.form(h.request.encoded) }
            if let s = h.status { o["status"] = s }
            if let b = h.body { o["body"] = red.text(b) }
            if let n = h.truncatedFrom { o["truncated_from"] = n }
            if let err = h.error { o["error"] = red.text(err) }
            o["duration"] = round3(h.duration)
        case .traffic(let t):
            o["kind"] = "traffic"
            o["seconds"] = round3(t.end - t.start)
            if t.packetsIn > 0 { o["packets_in"] = t.packetsIn; o["bytes_in"] = t.bytesIn }
            if t.packetsOut > 0 { o["packets_out"] = t.packetsOut; o["bytes_out"] = t.bytesOut }
            if t.keepalivesIn > 0 { o["keepalives_in"] = t.keepalivesIn }
            if t.keepalivesOut > 0 { o["keepalives_out"] = t.keepalivesOut }
        case .log(let m):
            o["kind"] = "log"
            o["message"] = red.text(m)
        case .incident(let m):
            o["kind"] = "incident"
            o["message"] = red.text(m)
        }
        return o
    }

    static func encode(_ f: Session.Failure, _ red: Redactors) -> [String: Any] {
        switch f {
        case .cookieRejected(let m): ["cookie_rejected": red.text(m)]
        case .transient(let m): ["transient": red.text(m)]
        }
    }

    static func encode(_ e: Session.Event, _ red: Redactors) -> [String: Any] {
        switch e {
        case .start: return ["event": "start"]
        case .configFetched(let c):
            var o: [String: Any] = ["event": "configFetched"]
            if let l = c.lifetime { o["lifetime"] = l }
            if let i = c.idleTimeout { o["idle_timeout"] = i }
            if let r = c.rekeyTimeout { o["rekey"] = r }
            if let m = c.mtu { o["mtu"] = m }
            if let v4 = c.ipv4 { o["ipv4"] = red.text(v4) }
            o["esp_offered"] = c.esp != nil
            return o
        case .configFailed(let f): return ["event": "configFailed", "failure": encode(f, red)]
        case .hipDone: return ["event": "hipDone"]
        case .hipFailed(let f): return ["event": "hipFailed", "failure": encode(f, red)]
        case .tunnelOpened: return ["event": "tunnelOpened"]
        case .tunnelFailed(let f): return ["event": "tunnelFailed", "failure": encode(f, red)]
        case .tunnelClosed(let f):
            var o: [String: Any] = ["event": "tunnelClosed"]
            if let f { o["failure"] = encode(f, red) }
            return o
        case .received: return ["event": "received"]
        case .pathChanged(let u): return ["event": "pathChanged", "usable": u]
        case .sleep: return ["event": "sleep"]
        case .wake: return ["event": "wake"]
        case .reauthenticated(let c): return ["event": "reauthenticated", "cookie": red.text(c.authcookie)]
        case .reauthFailed(let f, let needsUser):
            return ["event": "reauthFailed", "failure": encode(f, red), "needs_user": needsUser]
        case .stop(let logout): return ["event": "stop", "logout": logout]
        }
    }

    static func encode(_ a: Session.Action, _ red: Redactors) -> [String: Any] {
        switch a {
        case .fetchConfig: return ["action": "fetchConfig"]
        case .checkHIP: return ["action": "checkHIP"]
        case .openTunnel(_, let path): return ["action": "openTunnel", "path": red.target(path)]
        case .closeTunnel: return ["action": "closeTunnel"]
        case .sendKeepalive: return ["action": "sendKeepalive"]
        case .applySettings: return ["action": "applySettings"]
        case .reauthenticate: return ["action": "reauthenticate"]
        case .logout: return ["action": "logout"]
        case .saveCookie(let c): return ["action": "saveCookie", "cleared": c == nil]
        case .stateChanged(let s): return ["action": "stateChanged", "state": red.text(label(s))]
        }
    }

    /// `connecting(config)`, `reconnecting(2, dead peer)`, `needsLogin(...)`.
    public static func label(_ s: SessionState) -> String {
        switch s {
        case .idle: "idle"
        case .connecting(let p): "connecting(\(p))"
        case .connected: "connected"
        case .reconnecting(let a, let r): "reconnecting(\(a), \(r))"
        case .waitingForNetwork: "waitingForNetwork"
        case .reauthenticating: "reauthenticating"
        case .needsLogin(let r): "needsLogin(\(r))"
        case .stopped(let r): "stopped(\(r))"
        }
    }

    static func round3(_ d: Double) -> Double { (d * 1000).rounded() / 1000 }

    static func json(_ o: Any, pretty: Bool) -> String {
        var opts: JSONSerialization.WritingOptions = [.sortedKeys, .withoutEscapingSlashes]
        if pretty { opts.insert(.prettyPrinted) }
        guard let d = try? JSONSerialization.data(withJSONObject: o, options: opts) else { return "{}" }
        return String(decoding: d, as: UTF8.self)
    }
}
