import Foundation
import GPCore

/// Drafts a gp-fake-gateway scenario from an incident file: the gateway's
/// timers, plus one rule per thing the gateway did that a healthy gateway
/// wouldn't (an error status, a closed or silent tunnel, a refused tunnel).
/// The draft is a starting point: trim it to the smallest set of rules that
/// still makes the client fail, then commit it under `scenarios/`.
///
/// Request counts (`nth`) are counted from the start of the file, which
/// starts at the session's setup (pinned) entries, so they line up with a
/// fake gateway that has just started. They are approximate when the dump
/// dropped exchanges from the middle of a long session.
public enum ScenarioDraft {
    public static func make(from f: IncidentFile, name: String? = nil) -> [String: Any] {
        var rules: [[String: Any]] = []
        var counts: [String: Int] = [:]
        var tunnelAttempt = 0
        var tunnelOpenedAt: Double?
        var lastKeepaliveIn: Double?
        var hipNeeded = false
        var config: [String: Any] = [:]

        for e in f.events {
            let t = e["t"] as? Double ?? 0
            switch e["kind"] as? String {
            case "http":
                let kind = IncidentFile.requestKind(e["path"] as? String ?? "")
                counts[kind, default: 0] += 1
                let n = counts[kind]!
                let status = e["status"] as? Int
                let body = e["body"] as? String ?? ""
                if kind == "getconfig", let c = IncidentFile.config(e) {
                    if let l = c.lifetime { config["lifetime"] = l }
                    if let i = c.idleTimeout { config["idle_timeout"] = i }
                    if let r = c.rekeyTimeout { config["rekey"] = r }
                    if let m = c.mtu { config["mtu"] = m }
                }
                if kind == "hipreportcheck", body.contains("<hip-report-needed>yes") { hipNeeded = true }
                var rule: [String: Any] = ["when": ["request": kind, "nth": n],
                                           "_seen": "t=\(t) in the dump"]
                if let err = e["error"] as? String {
                    let lower = err.lowercased()
                    if lower.contains("timed out") || lower.contains("timeout") {
                        rule["delay"] = 60
                    } else {
                        rule["do"] = "close"
                    }
                    rule["_error"] = err
                    rules.append(rule)
                } else if let s = status, s != 200 || isErrorBody(kind: kind, body) {
                    rule["respond"] = ["status": s, "body": body]
                    rules.append(rule)
                }
                if let d = e["duration"] as? Double, d >= 10, e["error"] == nil {
                    var slow: [String: Any] = ["when": ["request": kind, "nth": n], "delay": Int(d.rounded())]
                    slow["_seen"] = "answered after \(d) s"
                    rules.append(slow)
                }
            case "action" where e["action"] as? String == "openTunnel":
                tunnelAttempt += 1
                tunnelOpenedAt = nil
                lastKeepaliveIn = nil
            case "event":
                switch e["event"] as? String {
                case "tunnelOpened":
                    tunnelOpenedAt = t
                case "tunnelFailed":
                    let msg = ((e["failure"] as? [String: Any])?.values.first as? String) ?? ""
                    var rule: [String: Any] = ["when": ["request": "tunnel", "nth": tunnelAttempt], "_error": msg]
                    if let s = statusCode(in: msg) {
                        rule["respond"] = ["status": s]
                    } else {
                        rule["do"] = "close"
                    }
                    rules.append(rule)
                case "tunnelClosed":
                    // Closed by the gateway (EOF) or by the network (a read error).
                    if let open = tunnelOpenedAt {
                        let after = max(0, Int((t - open).rounded()))
                        rules.append(["when": ["request": "tunnel", "nth": tunnelAttempt], "after": after,
                                      "do": "drop_tunnel", "_seen": "tunnel \(tunnelAttempt) closed after \(after) s"])
                    }
                    tunnelOpenedAt = nil
                default:
                    break
                }
            case "traffic":
                if (e["keepalives_in"] as? Int ?? 0) > 0 { lastKeepaliveIn = t }
            case "state":
                let s = e["state"] as? String ?? ""
                if s.contains("dead peer"), let open = tunnelOpenedAt {
                    let silent = lastKeepaliveIn ?? open
                    let after = max(0, Int((silent - open).rounded()))
                    rules.append(["when": ["request": "tunnel", "nth": tunnelAttempt], "after": after,
                                  "do": "ignore_keepalive", "_seen": "no keepalive answers after \(after) s"])
                    tunnelOpenedAt = nil
                }
            default:
                break
            }
        }

        rules = mergeRuns(rules)
        if let i = f.info["hip-interval"].flatMap({ Double($0) }) { config["hip_interval"] = Int(i) }
        if hipNeeded { config["hip_needed"] = true }
        let grace = f.header["grace_seconds"] as? Double ?? 60
        var out: [String: Any] = [
            "name": name ?? (f.header["reason"] as? String ?? "incident"),
            "profile": "default",
            "transport": f.info["transport"] ?? "https",
            "config": config,
            "rules": rules,
            "expect": ["connected_within": max(30, Int(grace.rounded(.up)))],
            "_source": [
                "written": f.header["written"] ?? "",
                "reason": f.header["reason"] ?? "",
                "outcome": f.header["outcome"] ?? "",
            ],
        ]
        if let v = f.info["portal-version"] { out["_gateway_version"] = v }
        return out
    }

    /// Folds rules that differ only in consecutive `nth` into one
    /// `from`/`to` rule: eight refused tunnels in a row become one rule.
    static func mergeRuns(_ rules: [[String: Any]]) -> [[String: Any]] {
        func key(_ r: [String: Any]) -> String {
            var r = r
            var w = r["when"] as? [String: Any] ?? [:]
            w["nth"] = nil
            r["when"] = w
            r["_seen"] = nil
            r["_error"] = nil
            return json(r)
        }
        var out: [[String: Any]] = []
        var runKey: String?
        var runEnd = 0
        for r in rules {
            let w = r["when"] as? [String: Any] ?? [:]
            guard let n = w["nth"] as? Int else {
                out.append(r)
                runKey = nil
                continue
            }
            let k = key(r)
            if k == runKey, n == runEnd + 1, var last = out.popLast() {
                var lw = last["when"] as? [String: Any] ?? [:]
                if lw["from"] == nil { lw["from"] = lw["nth"]; lw["nth"] = nil }
                lw["to"] = n
                last["when"] = lw
                out.append(last)
                runEnd = n
                continue
            }
            out.append(r)
            runKey = k
            runEnd = n
        }
        return out
    }

    static func isErrorBody(kind: String, _ body: String) -> Bool {
        let b = body.trimmingCharacters(in: .whitespacesAndNewlines)
        if b == "errors getting SSL/VPN config" { return true }
        return b.contains("status=\"error\"") || b.contains("<status>Error</status>")
    }

    /// `http(502)`, `HTTP/1.1 502`, `status 502` → 502.
    static func statusCode(in s: String) -> Int? {
        let digits = s.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) }
        return digits.first { (300...599).contains($0) }
    }

    public static func json(_ o: [String: Any]) -> String {
        guard let d = try? JSONSerialization.data(withJSONObject: o, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        else { return "{}" }
        return String(decoding: d, as: UTF8.self) + "\n"
    }
}
