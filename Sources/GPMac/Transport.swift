#if canImport(Network)
import Foundation
import GPCore
import Network
import Security

/// HTTPS requests to the portal and gateway over URLSession.
public final class URLSessionTransport: NSObject, HTTPTransport, URLSessionDelegate, @unchecked Sendable {
    public let trust: TrustPolicy
    private var session: URLSession!

    public init(trust: TrustPolicy, timeout: TimeInterval = 30) {
        self.trust = trust
        super.init()
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = timeout
        cfg.timeoutIntervalForResource = timeout * 2
        cfg.httpShouldSetCookies = false
        cfg.httpCookieAcceptPolicy = .never
        cfg.urlCache = nil
        cfg.waitsForConnectivity = false
        session = URLSession(configuration: cfg, delegate: self, delegateQueue: nil)
    }

    /// Breaks URLSession's strong reference to its delegate.
    public func invalidate() { session.invalidateAndCancel() }

    public func send(_ r: HTTPRequest, to server: String) async throws -> HTTPResponse {
        guard let url = URL(string: "https://\(server)\(r.path)") else { throw GPError.malformed("bad URL for \(server)") }
        var req = URLRequest(url: url)
        req.httpMethod = r.method
        req.setValue(HTTPRequest.userAgent, forHTTPHeaderField: "User-Agent")
        if r.method == "POST" {
            req.setValue(HTTPRequest.contentType, forHTTPHeaderField: "Content-Type")
            req.httpBody = Data(r.body.encoded.utf8)
        }
        let (data, resp) = try await session.data(for: req)
        let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
        return HTTPResponse(status: status, body: String(decoding: data, as: UTF8.self))
    }

    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge)
        async -> (URLSession.AuthChallengeDisposition, URLCredential?)
    {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let t = challenge.protectionSpace.serverTrust else { return (.performDefaultHandling, nil) }
        if trust.evaluate(t, host: challenge.protectionSpace.host) {
            return (.useCredential, URLCredential(trust: t))
        }
        return (.cancelAuthenticationChallenge, nil)
    }
}

/// The gateway over Network.framework: URLSession for requests, an
/// NWConnection with TLS for the tunnel.
public final class NWGatewayConnector: GatewayConnector, @unchecked Sendable {
    public let http: URLSessionTransport
    public let trust: TrustPolicy
    public let connectTimeout: Int

    public init(trust: TrustPolicy, connectTimeout: Int = 15) {
        self.trust = trust
        self.connectTimeout = connectTimeout
        http = URLSessionTransport(trust: trust, timeout: TimeInterval(connectTimeout * 2))
    }

    public func send(_ request: HTTPRequest, to server: String) async throws -> HTTPResponse {
        try await http.send(request, to: server)
    }

    public func openTunnel(to server: String) async throws -> any TunnelConnection {
        try await NWTunnelConnection.open(server: server, trust: trust, timeout: connectTimeout)
    }
}

/// A TLS connection to the gateway for the GPST tunnel.
public final class NWTunnelConnection: TunnelConnection, @unchecked Sendable {
    let connection: NWConnection
    private let queue = DispatchQueue(label: "albi.tunnel")

    init(_ c: NWConnection) { connection = c }

    public static func open(server: String, trust: TrustPolicy, timeout: Int) async throws -> NWTunnelConnection {
        let (host, port) = splitHostPort(server)
        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(sec, .TLSv12)
        let verifyQueue = DispatchQueue(label: "albi.tls-verify")
        sec_protocol_options_set_verify_block(sec, { _, secTrust, complete in
            let t = sec_trust_copy_ref(secTrust).takeRetainedValue()
            complete(trust.evaluate(t, host: host))
        }, verifyQueue)
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.connectionTimeout = timeout
        let params = NWParameters(tls: tls, tcp: tcp)
        let conn = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port) ?? 443, using: params)
        let tunnel = NWTunnelConnection(conn)
        try await tunnel.start()
        return tunnel
    }

    private func start() async throws {
        let once = Once()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                connection.stateUpdateHandler = { [connection] state in
                    switch state {
                    case .ready:
                        once.run { cont.resume() }
                    case .failed(let e), .waiting(let e):
                        // waiting means no route right now; let the session retry.
                        once.run {
                            connection.cancel()
                            cont.resume(throwing: e)
                        }
                    case .cancelled:
                        once.run { cont.resume(throwing: CancellationError()) }
                    default:
                        break
                    }
                }
                connection.start(queue: queue)
            }
        } onCancel: {
            connection.cancel()
        }
    }

    public func write(_ bytes: [UInt8]) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: Data(bytes), completion: .contentProcessed { error in
                if let error { cont.resume(throwing: error) } else { cont.resume() }
            })
        }
    }

    public func read() async throws -> [UInt8]? {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<[UInt8]?, Error>) in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
                if let data, !data.isEmpty {
                    cont.resume(returning: [UInt8](data))
                } else if let error {
                    cont.resume(throwing: error)
                } else if isComplete {
                    cont.resume(returning: nil)
                } else {
                    cont.resume(returning: [])
                }
            }
        }
    }

    public func close() { connection.cancel() }
}

/// Runs a closure at most once, from any thread.
final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func run(_ f: () -> Void) {
        lock.lock()
        let first = !done
        done = true
        lock.unlock()
        if first { f() }
    }
}

/// `host:port`, `[v6]:port` or `host` → (host, port), default port 443.
public func splitHostPort(_ server: String) -> (String, UInt16) {
    if server.hasPrefix("["), let end = server.firstIndex(of: "]") {
        let host = String(server[server.index(after: server.startIndex)..<end])
        let rest = server[server.index(after: end)...]
        return (host, rest.hasPrefix(":") ? UInt16(rest.dropFirst()) ?? 443 : 443)
    }
    let parts = server.split(separator: ":")
    if parts.count == 2, let p = UInt16(parts[1]) { return (String(parts[0]), p) }
    return (server, 443)
}

/// Watches the network path and reports changes that should trigger a
/// reconnect: the path becoming usable or unusable, a new primary
/// interface, or a new router. The tunnel's own utun interface is ignored.
public final class PathWatcher: @unchecked Sendable {
    private let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other, .loopback])
    private let queue = DispatchQueue(label: "albi.path")
    private var last: (usable: Bool, primary: String?, gateways: [String])?
    private let onChange: @Sendable (_ usable: Bool) -> Void

    public init(onChange: @escaping @Sendable (_ usable: Bool) -> Void) {
        self.onChange = onChange
    }

    public func start() {
        monitor.pathUpdateHandler = { [weak self] path in self?.update(path) }
        monitor.start(queue: queue)
    }

    public func stop() { monitor.cancel() }

    private func update(_ path: NWPath) {
        // The primary interface catches Wi-Fi to Ethernet; the router address
        // catches moving between Wi-Fi networks on the same interface.
        let now = (usable: path.status == .satisfied, primary: path.availableInterfaces.first?.name,
                   gateways: path.gateways.map { "\($0)" })
        defer { last = now }
        guard let prev = last else { return }
        if prev.usable != now.usable || (now.usable && (prev.primary != now.primary || prev.gateways != now.gateways)) {
            onChange(now.usable)
        }
    }
}
#endif
