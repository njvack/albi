/// Sends HTTPS requests to a portal or gateway. The macOS layer implements it
/// with URLSession; tests use a fake.
public protocol HTTPTransport: Sendable {
    /// `server` is `host` or `host:port`.
    func send(_ request: HTTPRequest, to server: String) async throws -> HTTPResponse
}

/// Something the login flow needs from the user or from saved settings.
public enum CredentialPrompt: Equatable, Sendable {
    case username(label: String, message: String?)
    /// `retry` is true when the previous password was rejected.
    case password(label: String, message: String?, server: String, retry: Bool)
    /// The second factor. For a push, the answer is usually "1".
    case challenge(message: String)
}

public protocol CredentialProvider: Sendable {
    /// Returns the answer, or throws (for example `GPError.cancelled`).
    func answer(_ prompt: CredentialPrompt) async throws -> String
}

/// Saved credentials, for unattended login and re-auth. Throws
/// `needsUser` for anything it cannot answer, including a rejected password.
public struct StoredCredentials: CredentialProvider {
    public struct NeedsUser: Error, Equatable {
        public init() {}
    }

    public var username: String
    public var password: String
    /// Fixed answer to the second-factor challenge, or nil to ask the user.
    public var secondFactor: String?

    public init(username: String, password: String, secondFactor: String?) {
        self.username = username
        self.password = password
        self.secondFactor = secondFactor
    }

    public func answer(_ prompt: CredentialPrompt) async throws -> String {
        switch prompt {
        case .username: return username
        case .password(_, _, _, false): return password
        case .challenge where secondFactor != nil: return secondFactor!
        default: throw NeedsUser()
        }
    }
}

public struct LoginResult: Equatable, Sendable {
    public var cookie: AuthCookie
    /// The gateway the cookie is for: `host` or `host:port`.
    public var gateway: String
    /// The portal's config, if we logged in through a portal.
    public var portal: PortalConfig?
}

/// The login flow: portal (if any), then gateway, answering the second-factor
/// challenge. It follows openconnect's `gpst_obtain_cookie`.
public struct Login: Sendable {
    public enum Target: Equatable, Sendable {
        /// Try the server as a portal, then as a gateway.
        case auto(String)
        case portal(String)
        case gateway(String)
    }

    public var transport: any HTTPTransport
    public var credentials: any CredentialProvider
    public var client: ClientInfo
    /// Picks a gateway from the portal's list. Defaults to the lowest
    /// priority number, then list order.
    public var chooseGateway: @Sendable ([PortalConfig.Gateway]) -> PortalConfig.Gateway
    /// The username to use without asking, if known.
    public var username: String?
    /// How many times to ask again after a rejected password.
    public var maxPasswordRetries = 2

    public init(transport: any HTTPTransport, credentials: any CredentialProvider, client: ClientInfo,
                username: String? = nil,
                chooseGateway: @escaping @Sendable ([PortalConfig.Gateway]) -> PortalConfig.Gateway = Login.defaultGateway) {
        self.transport = transport
        self.credentials = credentials
        self.client = client
        self.username = username
        self.chooseGateway = chooseGateway
    }

    public static func defaultGateway(_ gws: [PortalConfig.Gateway]) -> PortalConfig.Gateway {
        gws.enumerated().min { a, b in
            (a.element.priority ?? Int.max, a.offset) < (b.element.priority ?? Int.max, b.offset)
        }!.element
    }

    public func run(_ target: Target) async throws -> LoginResult {
        var state = FlowState(username: username)
        switch target {
        case .gateway(let s):
            return try await gatewayLogin(s, portal: nil, state: &state)
        case .portal(let s):
            return try await portalLogin(s, state: &state)
        case .auto(let s):
            do {
                return try await portalLogin(s, state: &state)
            } catch GPError.notFound {
                return try await gatewayLogin(s, portal: nil, state: &state)
            }
        }
    }

    struct FlowState {
        var username: String?
        var password: String?
    }

    func portalLogin(_ server: String, state: inout FlowState) async throws -> LoginResult {
        let doc = try await authenticate(.portal, server: server, portal: nil, state: &state)
        let portal = try PortalConfig(doc)
        let gw = chooseGateway(portal.gateways)
        return try await gatewayLogin(gw.address, portal: portal, state: &state)
    }

    func gatewayLogin(_ server: String, portal: PortalConfig?, state: inout FlowState) async throws -> LoginResult {
        let doc = try await authenticate(.gateway, server: server, portal: portal, state: &state)
        let cookie = try AuthCookie(jnlp: doc, computer: client.computer)
        return LoginResult(cookie: cookie, gateway: server, portal: portal)
    }

    /// prelogin, then the login form, answering challenges, until the server
    /// returns a document.
    func authenticate(_ iface: Requests.Interface, server: String, portal: PortalConfig?,
                      state: inout FlowState) async throws -> XMLElement {
        let pre = try await send(Requests.prelogin(iface, client: client), to: server)
        let form = try Prelogin(Reply.document(status: pre.status, body: pre.body))
        if let saml = form.samlMethod {
            throw GPError.server("\(iface == .portal ? "portal" : "gateway") wants SAML (\(saml)), which is not supported")
        }
        if state.username == nil {
            state.username = try await credentials.answer(.username(label: form.usernameLabel, message: form.message))
        }
        let user = state.username!
        var retries = 0
        var retry = false
        while true {
            if state.password == nil || retry {
                state.password = try await credentials.answer(
                    .password(label: form.passwordLabel, message: form.message, server: server, retry: retry))
            }
            var req = Requests.login(iface, client: client, server: server, user: user, password: state.password!,
                                     portalCookies: portal)
            do {
                while true {
                    let resp = try await send(req, to: server)
                    switch try Reply.classify(status: resp.status, body: resp.body) {
                    case .document(let d):
                        return d
                    case .challenge(let prompt, let inputStr):
                        let answer = try await credentials.answer(.challenge(message: prompt))
                        req = Requests.login(iface, client: client, server: server, user: user, password: answer,
                                             inputStr: inputStr, portalCookies: portal)
                    }
                }
            } catch GPError.badCredentials(let msg) {
                guard retries < maxPasswordRetries else { throw GPError.badCredentials(msg) }
                retries += 1
                retry = true
            }
        }
    }

    func send(_ req: HTTPRequest, to server: String) async throws -> HTTPResponse {
        try await transport.send(req, to: server)
    }
}
