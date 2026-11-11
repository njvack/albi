/// What prelogin.esp says about the login form.
public struct Prelogin: Equatable, Sendable {
    public var message: String?
    public var usernameLabel: String
    public var passwordLabel: String
    /// The gateway wants SAML, which Albi does not support.
    public var samlMethod: String?
    public var region: String?

    public init(_ x: XMLElement) {
        message = x.value("authentication-message").flatMap { $0.isEmpty ? nil : $0 }
        usernameLabel = x.value("username-label").flatMap { $0.isEmpty ? nil : $0 } ?? "Username"
        passwordLabel = x.value("password-label").flatMap { $0.isEmpty ? nil : $0 } ?? "Password"
        samlMethod = x.value("saml-auth-method").flatMap { $0.isEmpty ? nil : $0 }
        region = x.value("region")
    }
}

/// The parts of a portal's getconfig.esp policy a client needs.
public struct PortalConfig: Equatable, Sendable {
    public struct Gateway: Equatable, Sendable {
        /// Host (and optional port) to connect to.
        public var address: String
        public var description: String?
        public var priority: Int?
    }

    public var gateways: [Gateway]
    /// Seconds between HIP reports, from hip-collection.
    public var hipReportInterval: Int?
    /// The portal's GlobalProtect version, which we report back as our own.
    public var version: String?
    public var userAuthCookie: String?
    public var prelogonUserAuthCookie: String?

    public init(_ x: XMLElement) throws(GPError) {
        guard x.name == "policy" else { throw .malformed("portal config is <\(x.name)>, not <policy>") }
        func cookie(_ name: String) -> String? {
            guard let v = x.child(name)?.text, !v.isEmpty, v != "empty" else { return nil }
            return v
        }
        userAuthCookie = cookie("portal-userauthcookie")
        prelogonUserAuthCookie = cookie("portal-prelogonuserauthcookie")
        version = x.value("version")
        hipReportInterval = x.child("hip-collection")?.value("hip-report-interval").flatMap { Int($0) }
        let list = x.child("gateways")?.child("external")?.child("list")
        gateways = (list?.children("entry") ?? []).compactMap { e in
            guard let name = e.attributes["name"], !name.isEmpty else { return nil }
            let prio = e.child("priority-rule")?.child("entry")?.value("priority").flatMap { Int($0) }
                ?? e.value("priority").flatMap { Int($0) }
            return Gateway(address: name, description: e.value("description"), priority: prio)
        }
        if gateways.isEmpty { throw .malformed("portal config lists no gateways") }
    }
}

/// The session identity login.esp returns. openconnect calls the encoded
/// form of this its "cookie"; every later request carries these fields.
public struct AuthCookie: Codable, Equatable, Sendable {
    public var authcookie: String
    public var portal: String?
    public var user: String
    public var domain: String?
    public var preferredIP: String?
    public var preferredIPv6: String?
    public var computer: String

    public init(authcookie: String, portal: String?, user: String, domain: String?,
                preferredIP: String? = nil, preferredIPv6: String? = nil, computer: String) {
        self.authcookie = authcookie
        self.portal = portal
        self.user = user
        self.domain = domain
        self.preferredIP = preferredIP
        self.preferredIPv6 = preferredIPv6
        self.computer = computer
    }

    /// Parses login.esp's `<jnlp><application-desc><argument>…` list.
    public init(jnlp x: XMLElement, computer: String) throws(GPError) {
        guard x.name == "jnlp", let desc = x.child("application-desc") else {
            throw .malformed("login response is not a <jnlp> document")
        }
        let args: [String?] = desc.children("argument").map { a in
            let v = a.text
            return v.isEmpty || v == "(null)" || v == "-1" ? nil : v
        }
        func arg(_ i: Int) -> String? { i < args.count ? args[i] : nil }
        guard let cookie = arg(1), let user = arg(4).map(Form.unescape) else {
            throw .malformed("login response has no authcookie or user")
        }
        if let ct = arg(12), ct != "tunnel" {
            throw .malformed("login response connection-type is \(ct), not tunnel")
        }
        self.init(authcookie: Form.unescape(cookie), portal: arg(3).map(Form.unescape), user: user,
                  domain: arg(7).map(Form.unescape), preferredIP: arg(15).map(Form.unescape),
                  preferredIPv6: arg(18).map(Form.unescape), computer: computer)
    }

    /// The fields in openconnect's order, as sent with getconfig, HIP and logout.
    public var form: Form {
        var f = Form()
        f.append("authcookie", authcookie)
        f.append("portal", portal)
        f.append("user", user)
        f.append("domain", domain)
        f.append("preferred-ip", preferredIP)
        f.append("preferred-ipv6", preferredIPv6)
        f.append("computer", computer)
        return f
    }

    /// The HIP "md5" token: an identifier for this user and host on this
    /// gateway that does not change when the authcookie or IP does. Same
    /// computation as openconnect's `build_csd_token`.
    public var hipToken: String {
        MD5.hex(form.removing(["authcookie", "preferred-ip", "preferred-ipv6"]).encoded)
    }
}

/// A gateway's getconfig.esp answer.
public struct GatewayConfig: Equatable, Sendable {
    public var ipv4: String?
    public var netmask: String?
    public var ipv6: String?
    public var mtu: Int?
    /// Seconds the cookie remains valid, counted from this response.
    public var lifetime: Int?
    /// Seconds the gateway keeps an idle session.
    public var idleTimeout: Int?
    /// Seconds until the tunnel must be rekeyed (reconnected).
    public var rekeyTimeout: Int?
    public var tunnelPath: String
    public var dns: [String]
    public var dnsSuffixes: [String]
    public var accessRoutes: [String]
    public var excludeRoutes: [String]
    public var gatewayAddress: String?
    public var quarantine: Bool
    public var esp: ESPConfig?

    public init(_ x: XMLElement) throws(GPError) {
        guard x.name == "response" else { throw .malformed("getconfig answer is <\(x.name)>, not <response>") }
        func int(_ n: String) -> Int? { x.value(n).flatMap { Int($0) } }
        func nonEmpty(_ n: String) -> String? { x.value(n).flatMap { $0.isEmpty ? nil : $0 } }
        ipv4 = nonEmpty("ip-address")
        netmask = nonEmpty("netmask")
        ipv6 = nonEmpty("ip-address-v6")
        mtu = int("mtu").flatMap { $0 > 0 ? $0 : nil }
        lifetime = int("lifetime")
        idleTimeout = int("disconnect-on-idle")
        rekeyTimeout = int("timeout").flatMap { $0 > 0 ? $0 : nil }
        tunnelPath = nonEmpty("ssl-tunnel-url") ?? "/ssl-tunnel-connect.sslvpn"
        var servers: [String] = []
        for s in x.members("dns") + x.members("dns-v6") where !servers.contains(s) {
            servers.append(s)
        }
        dns = servers
        dnsSuffixes = x.members("dns-suffix")
        accessRoutes = x.members("access-routes") + x.members("access-routes-v6")
        excludeRoutes = x.members("exclude-access-routes") + x.members("exclude-access-routes-v6")
        gatewayAddress = nonEmpty("gw-address")
        quarantine = (x.value("quarantine") ?? "no") != "no"
        esp = x.child("ipsec").flatMap(ESPConfig.init)
        if ipv4 == nil && ipv6 == nil { throw .malformed("getconfig gave no client address") }
    }
}

/// ESP parameters from getconfig's `<ipsec>`. Parsed so we can see whether a
/// gateway offers ESP; the HTTPS tunnel is used either way for now.
public struct ESPConfig: Equatable, Sendable {
    public var udpPort: Int?
    public var encAlgo: String?
    public var hmacAlgo: String?
    public var c2sSPI: UInt32?
    public var s2cSPI: UInt32?
    public var c2sEncKey: [UInt8]
    public var s2cEncKey: [UInt8]
    public var c2sAuthKey: [UInt8]
    public var s2cAuthKey: [UInt8]

    init?(_ x: XMLElement) {
        udpPort = x.value("udp-port").flatMap { Int($0) }
        encAlgo = x.value("enc-algo")
        hmacAlgo = x.value("hmac-algo")
        c2sSPI = x.value("c2s-spi").flatMap { UInt32($0.hasPrefix("0x") ? String($0.dropFirst(2)) : $0, radix: 16) }
        s2cSPI = x.value("s2c-spi").flatMap { UInt32($0.hasPrefix("0x") ? String($0.dropFirst(2)) : $0, radix: 16) }
        func key(_ n: String) -> [UInt8] {
            // <ekey-c2s><bits>128</bits><val>hex</val></ekey-c2s>
            guard let k = x.child(n), let hex = k.value("val") else { return [] }
            var out: [UInt8] = []
            var it = hex.makeIterator()
            while let h = it.next(), let l = it.next() {
                guard let b = UInt8(String([h, l]), radix: 16) else { return [] }
                out.append(b)
            }
            return out
        }
        c2sEncKey = key("ekey-c2s")
        s2cEncKey = key("ekey-s2c")
        c2sAuthKey = key("akey-c2s")
        s2cAuthKey = key("akey-s2c")
        if encAlgo == nil && c2sSPI == nil { return nil }
    }
}
