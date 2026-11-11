import Foundation

/// The GlobalProtect version we claim to be. Keep it in step with the
/// client version Albi sends at login.
public let defaultClientVersion = "6.2.8-1045"

/// What the VPN client tells the reporter, plus our own options.
public struct Request: Sendable {
    public var md5 = ""
    public var cookie = ""
    public var clientIP = ""
    public var clientIPv6 = ""
    public var clientOS = ""
    public var clientVersion = ""
    /// Used when the cookie has none.
    public var userName = ""
    /// Interface whose MAC is the host-id; default en0.
    public var hostIDDevice = ""

    public init() {}
}

/// One hardware network port.
public struct Interface: Sendable, Codable, Equatable {
    public var device: String
    public var mac: String
    public var ipv4: [String]
    public var ipv6: [String]
}

/// Everything collected for one report. Encoded as JSON, this is the
/// per-check summary the app shows.
public struct Facts: Sendable, Codable {
    public var userName: String
    public var domain: String
    public var computer: String
    public var hostName: String
    public var hostID: String
    public var clientIP: String
    public var clientIPv6: String
    public var clientVersion: String
    public var osVersion: String
    public var md5: String
    public var generated: Date
    public var timeZoneOffset: Int
    public var trusted: Bool
    public var interfaces: [Interface]
    public var products: [Product]

    enum CodingKeys: String, CodingKey {
        case userName = "user_name", domain, computer, hostName = "host_name", hostID = "host_id"
        case clientIP = "client_ip", clientIPv6 = "client_ipv6", clientVersion = "client_version"
        case osVersion = "os_version", md5, generated, timeZoneOffset = "time_zone_offset", trusted
        case interfaces, products
    }

    var zone: TimeZone { TimeZone(secondsFromGMT: timeZoneOffset) ?? .current }
}

/// Runs every check and gathers host facts.
public func collect(_ env: Env, _ set: CheckSet, _ req: Request) -> Facts {
    let cookie = parseCookie(req.cookie)
    let short = String(env.sys.hostname().split(separator: ".", maxSplits: 1).first ?? "")
    let now = env.sys.now()
    var f = Facts(
        userName: cookie["user"] ?? "", domain: cookie["domain"] ?? "", computer: cookie["computer"] ?? "",
        hostName: short, hostID: "", clientIP: req.clientIP, clientIPv6: req.clientIPv6,
        clientVersion: req.clientVersion.isEmpty ? defaultClientVersion : req.clientVersion,
        osVersion: env.osVersion(), md5: req.md5, generated: now,
        timeZoneOffset: env.sys.timeZone().secondsFromGMT(for: now),
        trusted: set.trusted, interfaces: [], products: [])
    // These must match what the client sent at login, so the cookie wins.
    if f.userName.isEmpty { f.userName = req.userName }
    if f.computer.isEmpty { f.computer = short }
    // Hardware ports only: GP skips lo0, utun*, awdl0 and similar. MACs are
    // the burned-in ones, not Wi-Fi's private per-network address, as GP does.
    f.interfaces = env.sys.networkInterfaces()
    let idDev = req.hostIDDevice.isEmpty ? "en0" : req.hostIDDevice
    f.hostID = f.interfaces.first { $0.device == idDev }?.mac ?? ""
    f.products = set.checks.compactMap(env.evaluate)
    return f
}

/// Decodes the URL-encoded login cookie (user=...&domain=...). Only the
/// first value of each field counts.
func parseCookie(_ s: String) -> [String: String] {
    var m: [String: String] = [:]
    for pair in s.split(separator: "&", omittingEmptySubsequences: true) {
        let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        let k = String(parts[0])
        if k.isEmpty || m[k] != nil { continue }
        m[k] = urlDecode(parts.count > 1 ? String(parts[1]) : "")
    }
    return m
}

func urlDecode(_ s: String) -> String {
    let bytes = Array(s.utf8)
    var out: [UInt8] = []
    var i = 0
    while i < bytes.count {
        let b = bytes[i]
        if b == UInt8(ascii: "+") {
            out.append(UInt8(ascii: " "))
        } else if b == UInt8(ascii: "%"), i + 2 < bytes.count,
                  let n = UInt8(String(decoding: bytes[i + 1...i + 2], as: UTF8.self), radix: 16) {
            out.append(n)
            i += 2
        } else {
            out.append(b)
        }
        i += 1
    }
    return String(decoding: out, as: UTF8.self)
}

// MARK: - Host

// MARK: - XML

extension Facts {
    /// The HIP report.
    public var xml: Node {
        let root = Node("hip-report", [
            .text("md5-sum", md5),
            .text("user-name", userName),
            .text("domain", domain),
            .text("host-name", computer),
            .text("host-id", hostID),
            .text("ip-address", clientIP),
            .text("ipv6-address", clientIPv6),
            .text("generate-time", format(generated, "MM/dd/yyyy HH:mm:ss")),
            .text("hip-report-version", "4"),
        ])
        let cats = Node("categories", [hostInfo])
        for def in categories { cats.add(category(def)) }
        root.add(cats, customChecks)
        return root
    }

    private func format(_ d: Date, _ pattern: String) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = zone
        f.dateFormat = pattern
        return f.string(from: d)
    }

    private var hostInfo: Node {
        let nics = Node("network-interface")
        for i in interfaces {
            let e = Node.entry(i.device, [.text("description", i.device), .text("mac-address", i.mac)])
            if !i.ipv4.isEmpty { e.add(addressList("ip-address", i.ipv4)) }
            if !i.ipv6.isEmpty { e.add(addressList("ipv6-address", i.ipv6)) }
            nics.add(e)
        }
        return .entry("host-info", [
            .text("client-version", clientVersion),
            .text("os", "Apple Mac OS X " + osVersion),
            .text("os-vendor", "Apple"),
            .text("domain", domain),
            .text("host-name", hostName),
            .text("host-id", hostID),
            nics,
        ])
    }

    private func addressList(_ tag: String, _ addrs: [String]) -> Node {
        Node(tag, addrs.map { Node("entry", attrs: [("name", $0)]) })
    }

    private func category(_ def: CategoryDef) -> Node {
        let list = Node("list")
        for p in products where p.category == def.name {
            list.add(Node("entry", [Node("ProductInfo", productInfo(def, p))]))
        }
        let e = Node.entry(def.name, [list])
        if def.name == "patch-management" {
            // Pending updates aren't checked, so this always claims none.
            e.add(Node("missing-patches"))
        }
        return e
    }

    /// The children of <ProductInfo>: a <Prod> whose attributes carry vendor,
    /// name and version (and, for anti-malware, the definition version and
    /// date), then one element per remaining field.
    private func productInfo(_ def: CategoryDef, _ p: Product) -> [Node] {
        func val(_ n: String) -> String { p.fields[n]?.value ?? "" }
        var attrs = [("vendor", p.vendor), ("name", p.name), ("version", val("version"))]
        var rest: [Node] = []
        switch def.name {
        case "anti-malware":
            let (mon, day, year) = dateParts(val("updated"))
            attrs += [("defver", val("defver")), ("engver", val("engver")),
                      ("datemon", mon), ("dateday", day), ("dateyear", year),
                      ("prodType", "3"), ("osType", "4")]
            rest = [.text("real-time-protection", val("real-time-protection")),
                    .text("last-full-scan-time", val("last-full-scan-time"))]
        case "disk-encryption":
            rest = [Node("drives", (p.fields["drives"]?.drives ?? []).map {
                Node("entry", [.text("drive-name", $0.name), .text("enc-state", $0.state)])
            })]
        default:
            rest = def.fields.filter { $0.name != "version" }.map { .text($0.name, val($0.name)) }
        }
        return [Node("Prod", attrs: attrs)] + rest
    }

    /// The unpadded month, day and year of a Unix time, in the report's zone.
    private func dateParts(_ epoch: String) -> (String, String, String) {
        guard let n = Int64(epoch) else { return ("", "", "") }
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = zone
        let c = cal.dateComponents([.year, .month, .day], from: Date(timeIntervalSince1970: TimeInterval(n)))
        return (String(c.month ?? 0), String(c.day ?? 0), String(c.year ?? 0))
    }

    private var customChecks: Node {
        let pl = Node("plist")
        for p in products {
            guard let r = p.plist else { continue }
            let prefs = Node("preference-value", r.keys.map {
                .entry($0.key, [.text("exist", yesNo($0.exists)), .text("value", $0.value)])
            })
            pl.add(.entry(r.path, [.text("exist", yesNo(r.exists)), .text("value", ""), prefs]))
        }
        return Node("custom-checks", [pl])
    }
}
