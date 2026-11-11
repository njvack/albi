import Foundation
import GPCore

/// What a capture says about the gateway, with nothing identifying in it:
/// timers, tunnel mode, HIP behaviour and counts.
public struct Summary {
    public var lines: [String] = []

    public init(_ log: CaptureLog) {
        func add(_ s: String) { lines.append(s) }
        func duration(_ s: Int?) -> String {
            guard let s else { return "not sent" }
            if s <= 0 { return "\(s)" }
            var parts: [String] = []
            if s >= 3600 { parts.append("\(s / 3600) h") }
            if s % 3600 >= 60 { parts.append("\(s % 3600 / 60) min") }
            if s % 60 != 0 { parts.append("\(s % 60) s") }
            return "\(s) s (\(parts.joined(separator: " ")))"
        }
        let xs = log.exchanges
        func docs(_ label: String) -> [(Exchange, XMLElement)] {
            xs.filter { $0.label == label && $0.status == 200 }.compactMap { x in
                x.responseBody.flatMap(XMLElement.parse).map { (x, $0) }
            }
        }

        if let v = log.events.first(where: { $0.text.hasPrefix("OpenConnect version") }) { add(v.text) }
        if let first = log.exchanges.first?.time ?? log.events.first?.time,
           let last = log.events.last?.time ?? log.exchanges.last?.time,
           let d = Self.seconds(from: first, to: last) {
            add("Captured \(d) s of traffic")
        }

        add("")
        add("Portal")
        if let (_, pre) = docs("portal-prelogin").first {
            let p = Prelogin(pre)
            add("  prelogin: \(p.samlMethod.map { "SAML (\($0))" } ?? "username and password")")
            if let v = pre.value("panos-version") { add("  panos-version: \(v)") }
        } else {
            add("  no portal prelogin answer (connected straight to a gateway?)")
        }
        if let (_, doc) = docs("portal-getconfig").first, let pc = try? PortalConfig(doc) {
            add("  version: \(pc.version ?? "not sent")")
            add("  gateways offered: \(pc.gateways.count)")
            add("  HIP report interval: \(duration(pc.hipReportInterval))")
            add("  config elements: \(Self.elementNames(doc))")
        }

        add("")
        add("Gateway login")
        let logins = xs.filter { $0.label == "gateway-login" }
        let challenges = logins.filter { $0.responseBody?.contains("<challenge") == true || $0.responseBody?.contains("Challenge") == true }
        add("  login requests: \(logins.count), second-factor challenges: \(challenges.count)")
        if let (_, jnlp) = docs("gateway-login").first(where: { $0.1.name == "jnlp" }) {
            let args = jnlp.child("application-desc")?.children("argument").map(\.trimmedText) ?? []
            add("  jnlp arguments: \(args.count)")
            if args.count > 13 { add("  password expires in (days): \(args[13])") }
        }

        add("")
        add("Gateway config (getconfig.esp)")
        let configs = docs("gateway-getconfig")
        add("  getconfig answers: \(configs.count)")
        if let (_, doc) = configs.first {
            if let gc = try? GatewayConfig(doc) {
                add("  lifetime: \(duration(gc.lifetime))")
                add("  disconnect-on-idle: \(duration(gc.idleTimeout))")
                add("  timeout (rekey): \(duration(doc.value("timeout").flatMap { Int($0) }))")
                add("  mtu: \(doc.value("mtu") ?? "not sent")")
                add("  IPv4 address: \(gc.ipv4 == nil ? "no" : "yes"), netmask \(gc.netmask ?? "none")")
                add("  IPv6 address: \(gc.ipv6 == nil ? "no" : "yes")")
                add("  access routes: \(gc.accessRoutes.count) (\(gc.accessRoutes.filter { $0.contains(":") }.count) IPv6)\(gc.accessRoutes.contains { $0.hasPrefix("0.0.0.0/0") } ? ", includes a default route" : "")")
                add("  exclude routes: \(gc.excludeRoutes.count)")
                add("  DNS servers: \(gc.dns.count), DNS suffixes: \(gc.dnsSuffixes.count)")
                add("  quarantine: \(gc.quarantine ? "yes" : "no")")
                if let esp = gc.esp {
                    add("  ESP offered: yes, \(esp.encAlgo ?? "?") / \(esp.hmacAlgo ?? "?"), UDP port \(esp.udpPort.map(String.init) ?? "?")")
                } else {
                    add("  ESP offered: no")
                }
            } else {
                add("  (GPCore could not parse it)")
            }
            add("  elements: \(Self.elementNames(doc))")
        }

        add("")
        add("Tunnel")
        let ev = log.events.map(\.text)
        func has(_ s: String) -> Bool { ev.contains { $0.contains(s) } }
        if has("ESP session established") {
            add("  ESP: established")
        } else if has("Failed to connect ESP tunnel") || has("using HTTPS instead") {
            add("  ESP: offered but failed; openconnect fell back to HTTPS")
        } else if has("tunnel will be TLS only") || has("ESP disabled") {
            add("  ESP: not used (not offered or disabled)")
        } else {
            add("  ESP: no result in the log")
        }
        if let c = ev.first(where: { $0.hasPrefix("Configured as ") }) {
            add("  " + c.replacingOccurrences(of: #"Configured as [^,]+,"#, with: "Configured,", options: .regularExpression))
        }
        add("  tunnel connects: \(xs.filter { $0.label == "tunnel-connect" }.count)")
        let keepalives = ev.filter { $0.contains("DPD/keepalive request") }.count
        if keepalives > 0 { add("  keepalives sent: \(keepalives)") }
        for key in ["Tunnel timeout", "Rekey", "rekey", "reconnect", "Reconnect", "dead peer", "DPD", "Idle timeout"] {
            let n = ev.filter { $0.contains(key) && !$0.contains("DPD/keepalive") }.count
            if n > 0 { add("  log lines mentioning \"\(key)\": \(n)") }
        }

        add("")
        add("HIP")
        let checks = docs("gateway-hipreportcheck")
        add("  hipreportcheck calls: \(xs.filter { $0.label == "gateway-hipreportcheck" }.count)")
        for (_, d) in checks { add("  hip-report-needed: \(d.value("hip-report-needed") ?? "?")") }
        let reports = xs.filter { $0.label == "gateway-hipreport" }
        add("  hipreport submissions: \(reports.count), accepted: \(reports.filter { $0.responseBody?.contains("success") == true }.count)")
        if let t = ev.first(where: { $0.contains("HIP report interval") || $0.contains("HIP report") && $0.contains("minutes") }) {
            add("  openconnect: \(t)")
        }

        let odd = xs.filter { $0.status != nil && $0.status != 200 }
        if !odd.isEmpty {
            add("")
            add("Non-200 answers")
            for x in odd { add("  \(x.label): \(x.statusLine ?? "?")") }
        }
        if let end = log.events.last(where: { !$0.text.isEmpty }) {
            add("")
            add("Last log line: \(end.text)")
        }
    }

    public var text: String { lines.joined(separator: "\n") + "\n" }

    /// The distinct element names in a document, in order of first use.
    static func elementNames(_ x: XMLElement) -> String {
        var seen: [String] = []
        func walk(_ e: XMLElement) {
            for c in e.elements {
                if !seen.contains(c.name) { seen.append(c.name) }
                walk(c)
            }
        }
        walk(x)
        return seen.joined(separator: " ")
    }

    static func seconds(from a: String, to b: String) -> Int? {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        guard let x = f.date(from: a), let y = f.date(from: b) else { return nil }
        return Int(y.timeIntervalSince(x))
    }
}
