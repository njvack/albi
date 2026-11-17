#if canImport(Network)
import Foundation
import GPCore
import Network
import Security
import SystemConfiguration

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
///
/// With `requiredInterface`, every connection to the gateway (requests too)
/// goes over NWConnection pinned to the interface it returns, so a full
/// tunnel's 0/1 and 128/1 can't capture the gateway's own traffic and no host
/// route is needed. The closure is asked on every connection, so it can
/// follow Wi-Fi changes; nil from it means "don't pin this one".
public final class NWGatewayConnector: GatewayConnector, @unchecked Sendable {
    public let http: URLSessionTransport
    public let trust: TrustPolicy
    public let connectTimeout: Int
    public let requestTimeout: TimeInterval
    public let requiredInterface: (@Sendable () -> NWInterface?)?

    /// `requestTimeout` is long because login.esp holds the answer to the
    /// second-factor challenge until the push is approved.
    public init(trust: TrustPolicy, connectTimeout: Int = 15, requestTimeout: TimeInterval = 90,
                requiredInterface: (@Sendable () -> NWInterface?)? = nil) {
        self.trust = trust
        self.connectTimeout = connectTimeout
        self.requestTimeout = requestTimeout
        self.requiredInterface = requiredInterface
        http = URLSessionTransport(trust: trust, timeout: requestTimeout)
    }

    public func send(_ request: HTTPRequest, to server: String) async throws -> HTTPResponse {
        guard let requiredInterface else { return try await http.send(request, to: server) }
        let conn = try await NWTunnelConnection.open(server: server, trust: trust, timeout: connectTimeout,
                                                     interface: requiredInterface())
        defer { conn.close() }
        return try await withTimeout(requestTimeout) {
            try await conn.write(HTTP1.encode(request, host: server))
            var parser = HTTP1.ResponseParser()
            while true {
                guard let bytes = try await conn.read() else { return try parser.finish() }
                if let r = try parser.feed(bytes) { return r }
            }
        } onTimeout: {
            conn.close()
        }
    }

    public func openTunnel(to server: String) async throws -> any TunnelConnection {
        try await NWTunnelConnection.open(server: server, trust: trust, timeout: connectTimeout,
                                          interface: requiredInterface?())
    }
}

struct RequestTimedOut: Error, CustomStringConvertible {
    var description: String { "request timed out" }
}

/// Runs `body`, calling `onTimeout` (which should make it finish) after `seconds`.
func withTimeout<T>(_ seconds: TimeInterval, _ body: () async throws -> T,
                    onTimeout: @escaping @Sendable () -> Void) async throws -> T {
    let fired = Flag()
    let timer = Task {
        try? await Task.sleep(for: .milliseconds(Int(seconds * 1000)))
        guard !Task.isCancelled else { return }
        fired.set()
        onTimeout()
    }
    defer { timer.cancel() }
    do {
        return try await body()
    } catch {
        if fired.isSet { throw RequestTimedOut() }
        throw error
    }
}

final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    func set() { lock.withLock { value = true } }
    var isSet: Bool { lock.withLock { value } }
}

/// A TLS connection to the gateway for the GPST tunnel.
public final class NWTunnelConnection: TunnelConnection, @unchecked Sendable {
    let connection: NWConnection
    private let queue = DispatchQueue(label: "albi.tunnel")

    init(_ c: NWConnection) { connection = c }

    public static func open(server: String, trust: TrustPolicy, timeout: Int,
                            interface: NWInterface? = nil) async throws -> NWTunnelConnection {
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
        if let interface { params.requiredInterface = interface }
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

/// Watches the physical network and reports changes that should trigger a
/// reconnect: it becoming usable or unusable, a new primary interface, or a
/// new router. Tunnels (type `.other`: our own utun, Tailscale) are left out.
///
/// The monitor itself is unrestricted: one that prohibits `.other` reports
/// the path unsatisfied as soon as a full tunnel's 0/1 and 128/1 go in,
/// since the best route is then the utun. What counts here is whether a
/// physical interface is still there.
public final class PathWatcher: @unchecked Sendable {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "albi.path")
    private let lock = NSLock()
    private var last: (usable: Bool, primary: String?, router: String?)?
    private var physical: [NWInterface] = []
    private var router: String?
    private var path: NWPath?
    private let onChange: @Sendable (_ usable: Bool) -> Void

    public init(onChange: @escaping @Sendable (_ usable: Bool) -> Void) {
        self.onChange = onChange
    }

    public func start() {
        monitor.pathUpdateHandler = { [weak self] path in self?.update(path) }
        monitor.start(queue: queue)
    }

    public func stop() { monitor.cancel() }

    /// The physical interface traffic would leave by, for pinning the
    /// gateway connection. nil until the first path arrives.
    public var primaryInterface: NWInterface? { lock.withLock { physical.first } }

    /// The IPv4 router of the primary physical interface, for excluded routes.
    public var ipv4Router: String? { lock.withLock { router } }

    /// The last path, for logs.
    public var summary: String {
        lock.withLock {
            guard let p = path else { return "no path yet" }
            return "physical=\(physical.map(\.name)) router=\(router ?? "-") status=\(p.status) interfaces=\(p.availableInterfaces.map(\.name))"
        }
    }

    private func update(_ path: NWPath) {
        var phys = path.availableInterfaces.filter { $0.type != .other && $0.type != .loopback }
        // The interface configd made primary (the real default route) goes
        // first. The monitor's own order can put another one, such as a
        // Thunderbolt bridge, ahead of it once a tunnel takes the best path.
        if let primary = Self.globalPrimaryInterface(), let i = phys.firstIndex(where: { $0.name == primary }) {
            phys.insert(phys.remove(at: i), at: 0)
        }
        let r = phys.first.flatMap { Self.router(for: $0.name) }
        lock.withLock {
            self.path = path
            physical = phys
            router = r
        }
        // The primary interface catches Wi-Fi to Ethernet; the router address
        // catches moving between Wi-Fi networks on the same interface.
        let now = (usable: !phys.isEmpty, primary: phys.first?.name, router: r)
        defer { last = now }
        guard let prev = last else { return }
        if prev.usable != now.usable || (now.usable && (prev.primary != now.primary || prev.router != now.router)) {
            onChange(now.usable)
        }
    }

    /// configd's primary IPv4 interface, unless it's a tunnel's.
    static func globalPrimaryInterface() -> String? {
        guard let store = SCDynamicStoreCreate(nil, "albi-path" as CFString, nil, nil),
              let d = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any],
              let name = d["PrimaryInterface"] as? String, !name.hasPrefix("utun") else { return nil }
        return name
    }

    /// The router of the network service on `ifname`, from configd's state
    /// (not the global state, which a tunnel can take over).
    static func router(for ifname: String) -> String? {
        guard let store = SCDynamicStoreCreate(nil, "albi-path" as CFString, nil, nil),
              let keys = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/[^/]+/IPv4" as CFString) as? [String]
        else { return nil }
        for k in keys {
            guard let d = SCDynamicStoreCopyValue(store, k as CFString) as? [String: Any],
                  d["InterfaceName"] as? String == ifname, let r = d["Router"] as? String else { continue }
            return r
        }
        return nil
    }
}
#endif
