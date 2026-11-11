/// An HTTPS request to a portal or gateway, relative to its host.
public struct HTTPRequest: Equatable, Sendable {
    public var method: String
    /// Path and query, starting with `/`.
    public var path: String
    public var body: Form

    public init(method: String = "POST", path: String, body: Form) {
        self.method = method
        self.path = path
        self.body = body
    }

    public static let contentType = "application/x-www-form-urlencoded"
    /// What openconnect sends; some gateways check it.
    public static let userAgent = "PAN GlobalProtect"
}

public struct HTTPResponse: Equatable, Sendable {
    public var status: Int
    public var body: String

    public init(status: Int, body: String) {
        self.status = status
        self.body = body
    }
}

/// How this client describes itself to the gateway. Defaults match what
/// openconnect sends from a Mac, since that is known to be accepted.
public struct ClientInfo: Equatable, Sendable {
    public var clientOS = "Mac"
    /// openconnect sends its platform name here.
    public var osVersion = "mac-intel"
    /// The host name the gateway records for this session.
    public var computer: String
    /// Sent as app-version; replaced by the portal's version when there is one.
    public var appVersion = "6.3.0-33"
    public var ipv6Support = true

    public init(computer: String) {
        self.computer = computer
    }
}

/// Builds the requests of the GlobalProtect protocol.
public enum Requests {
    public enum Interface: String, Sendable {
        case portal = "global-protect"
        case gateway = "ssl-vpn"
    }

    public static func prelogin(_ iface: Interface, client: ClientInfo) -> HTTPRequest {
        HTTPRequest(path: "/\(iface.rawValue)/prelogin.esp?tmp=tmp&clientVer=4100&clientos=\(Form.escape(client.clientOS))",
                    body: Form())
    }

    /// Portal getconfig.esp or gateway login.esp, which take the same fields.
    public static func login(_ iface: Interface, client: ClientInfo, server: String, user: String, password: String,
                             inputStr: String? = nil, portalCookies: PortalConfig? = nil) -> HTTPRequest {
        var f: Form = [
            "jnlpReady": "jnlpReady", "ok": "Login", "direct": "yes", "clientVer": "4100",
            "prot": "https:", "internal": "no",
        ]
        f.append("ipv6-support", client.ipv6Support ? "yes" : "no")
        f.append("clientos", client.clientOS)
        f.append("os-version", client.osVersion)
        f.append("server", server)
        f.append("computer", client.computer)
        f.append("portal-userauthcookie", portalCookies?.userAuthCookie)
        f.append("portal-prelogonuserauthcookie", portalCookies?.prelogonUserAuthCookie)
        f.append("inputStr", inputStr)
        f.append("user", user)
        f.append("passwd", password)
        let path = iface == .portal ? "/global-protect/getconfig.esp" : "/ssl-vpn/login.esp"
        return HTTPRequest(path: path, body: f)
    }

    /// getconfig.esp on the gateway. Pass the addresses we had before to ask
    /// for them again on a reconnect.
    public static func getConfig(_ cookie: AuthCookie, client: ClientInfo, previousIPv4: String? = nil,
                                 previousIPv6: String? = nil) -> HTTPRequest {
        var f: Form = ["client-type": "1", "protocol-version": "p1", "internal": "no"]
        f.append("app-version", client.appVersion)
        f.append("ipv6-support", client.ipv6Support ? "yes" : "no")
        f.append("clientos", client.clientOS)
        f.append("os-version", client.osVersion)
        f.append("hmac-algo", "sha1,md5,sha256")
        f.append("enc-algo", "aes-128-cbc,aes-256-cbc")
        if previousIPv4 != nil || previousIPv6 != nil {
            f.append("preferred-ip", previousIPv4)
            f.append("preferred-ipv6", previousIPv6)
            f.append(contentsOf: cookie.form.removing(["preferred-ip", "preferred-ipv6"]))
        } else {
            f.append(contentsOf: cookie.form)
        }
        return HTTPRequest(path: "/ssl-vpn/getconfig.esp", body: f)
    }

    public static func hipReportCheck(_ cookie: AuthCookie, clientIPv4: String?, clientIPv6: String?) -> HTTPRequest {
        var f: Form = ["client-role": "global-protect-full"]
        f.append(contentsOf: cookie.form)
        f.append("client-ip", clientIPv4)
        f.append("client-ipv6", clientIPv6)
        f.append("md5", cookie.hipToken)
        return HTTPRequest(path: "/ssl-vpn/hipreportcheck.esp", body: f)
    }

    public static func hipReport(_ cookie: AuthCookie, clientIPv4: String?, clientIPv6: String?, report: String) -> HTTPRequest {
        var f: Form = ["client-role": "global-protect-full"]
        f.append(contentsOf: cookie.form)
        f.append("client-ip", clientIPv4)
        f.append("client-ipv6", clientIPv6)
        f.append("report", report)
        return HTTPRequest(path: "/ssl-vpn/hipreport.esp", body: f)
    }

    public static func logout(_ cookie: AuthCookie) -> HTTPRequest {
        HTTPRequest(path: "/ssl-vpn/logout.esp", body: cookie.form)
    }

    /// Whether hipreportcheck.esp's answer asks for a report.
    public static func hipReportNeeded(_ x: XMLElement) throws(GPError) -> Bool {
        switch x.value("hip-report-needed") {
        case "yes": return true
        case "no": return false
        default: throw .malformed("hipreportcheck answer has no hip-report-needed")
        }
    }
}
