import Foundation
import GPCore

/// An incident file read back: the header and its events as JSON objects.
public struct IncidentFile {
    public var header: [String: Any]
    public var events: [[String: Any]]

    public init(data: Data) throws {
        guard let o = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              o["format"] as? String == DumpWriter.format,
              let h = o["header"] as? [String: Any], let ev = o["events"] as? [[String: Any]] else {
            throw GPError.malformed("not an \(DumpWriter.format) file")
        }
        header = h
        events = ev.sorted { ($0["seq"] as? Int ?? 0) < ($1["seq"] as? Int ?? 0) }
    }

    public init(contentsOf url: URL) throws {
        try self.init(data: Data(contentsOf: url))
    }

    public var info: [String: String] { header["info"] as? [String: String] ?? [:] }

    /// Time of the first entry inside the window (pinned entries come before it).
    public var windowStart: Double? {
        events.first { $0["pinned"] as? Bool != true }.flatMap { $0["t"] as? Double }
    }

    /// The protocol's name for an HTTP path: `getconfig`, `portal-getconfig`, ...
    public static func requestKind(_ path: String) -> String {
        let p = String(path.split(separator: "?", maxSplits: 1).first ?? "")
        let name = String((p.split(separator: "/").last ?? "").split(separator: ".").first ?? "")
        if p.hasPrefix("/global-protect/") { return "portal-" + name }
        return name
    }

    // MARK: Replay

    public struct Replay {
        public var actions: [(time: Double, action: String)] = []
        public var finalState: SessionState
        /// Recorded and replayed action names inside the window, and the
        /// first index where both have one and they differ.
        public var recorded: [String]
        public var replayed: [String]
        public var divergence: Int?
        public var notes: [String] = []
    }

    /// Feeds the recorded session events into a fresh `Session` on a fake
    /// clock, firing its timers at their deadlines in between, and compares
    /// what it does with what the client did.
    public func replay() -> Replay {
        var info: [String: String] = [:]
        for (k, v) in self.info where k.hasPrefix("policy.") { info[String(k.dropFirst(7))] = v }
        let policy = SessionPolicy(fields: info)
        let cookie = AuthCookie(authcookie: "replay", portal: nil, user: "user", domain: nil, computer: "computer")
        var session = Session(cookie: cookie, policy: policy, hipInterval: self.info["hip-interval"].flatMap { Double($0) })
        var out: [(Double, String)] = []
        var notes: [String] = []

        func run(_ actions: [Session.Action], at t: Double) {
            for a in actions { out.append((t, Self.name(a))) }
        }
        func advance(to t: Double) {
            while let d = session.nextDeadline, d <= t {
                run(session.tick(now: d), at: d)
            }
        }

        var lastConfig: GatewayConfig?
        var anyConfig: GatewayConfig?
        for e in events where e["kind"] as? String == "http" && Self.requestKind(e["path"] as? String ?? "") == "getconfig" {
            if let c = Self.config(e) { anyConfig = c }
        }
        var end = 0.0
        for e in events {
            let t = e["t"] as? Double ?? 0
            end = max(end, t)
            if e["kind"] as? String == "http", Self.requestKind(e["path"] as? String ?? "") == "getconfig",
               let c = Self.config(e) {
                lastConfig = c
            }
            guard e["kind"] as? String == "event" else { continue }
            advance(to: t)
            guard let ev = event(e, config: lastConfig ?? anyConfig, notes: &notes) else { continue }
            run(session.handle(ev, now: t), at: t)
        }
        advance(to: end)

        let start = windowStart ?? 0
        let recorded = events.filter { ($0["t"] as? Double ?? 0) >= start && $0["pinned"] as? Bool != true }
            .compactMap { e -> String? in
                switch e["kind"] as? String {
                case "action": e["action"] as? String
                case "state": "stateChanged"
                default: nil
                }
            }
        // Keepalives are counted, not listed, in the recording.
        let replayed = out.filter { $0.0 >= start && $0.1 != "sendKeepalive" }.map(\.1)
        let rec = recorded.filter { $0 != "sendKeepalive" }
        var div: Int?
        // The recording can stop just before or after a timer fired, so only
        // a difference where both have an action counts.
        for i in 0..<min(rec.count, replayed.count) where rec[i] != replayed[i] {
            div = i
            break
        }
        var r = Replay(finalState: session.state, recorded: rec, replayed: replayed, divergence: div, notes: notes)
        r.actions = out
        return r
    }

    static func config(_ e: [String: Any]) -> GatewayConfig? {
        guard let s = e["status"] as? Int, let b = e["body"] as? String,
              let doc = try? Reply.document(status: s, body: b) else { return nil }
        return try? GatewayConfig(doc)
    }

    static func failure(_ o: Any?) -> Session.Failure {
        let d = o as? [String: Any] ?? [:]
        if let m = d["cookie_rejected"] as? String { return .cookieRejected(m) }
        return .transient(d["transient"] as? String ?? "")
    }

    func event(_ e: [String: Any], config: GatewayConfig?, notes: inout [String]) -> Session.Event? {
        switch e["event"] as? String {
        case "start": return .start
        case "configFetched":
            guard let config else {
                notes.append("configFetched at \(e["t"] ?? "?") has no getconfig response to replay; skipped")
                return nil
            }
            return .configFetched(config)
        case "configFailed": return .configFailed(Self.failure(e["failure"]))
        case "hipDone": return .hipDone
        case "hipFailed": return .hipFailed(Self.failure(e["failure"]))
        case "tunnelOpened": return .tunnelOpened
        case "tunnelFailed": return .tunnelFailed(Self.failure(e["failure"]))
        case "tunnelClosed": return .tunnelClosed(e["failure"] == nil ? nil : Self.failure(e["failure"]))
        case "received": return .received
        case "pathChanged": return .pathChanged(usable: e["usable"] as? Bool ?? true)
        case "sleep": return .sleep
        case "wake": return .wake
        case "reauthenticated":
            return .reauthenticated(AuthCookie(authcookie: e["cookie"] as? String ?? "replay2", portal: nil, user: "user",
                                               domain: nil, computer: "computer"))
        case "reauthFailed":
            return .reauthFailed(Self.failure(e["failure"]), needsUser: e["needs_user"] as? Bool ?? false)
        case "stop": return .stop(logout: e["logout"] as? Bool ?? false)
        default: return nil
        }
    }

    static func name(_ a: Session.Action) -> String {
        switch a {
        case .fetchConfig: "fetchConfig"
        case .checkHIP: "checkHIP"
        case .openTunnel: "openTunnel"
        case .closeTunnel: "closeTunnel"
        case .sendKeepalive: "sendKeepalive"
        case .applySettings: "applySettings"
        case .reauthenticate: "reauthenticate"
        case .logout: "logout"
        case .saveCookie: "saveCookie"
        case .stateChanged: "stateChanged"
        }
    }
}
