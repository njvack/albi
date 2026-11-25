#if os(macOS)
    import AlbiConstants
    import Diagnostics
    import Foundation
    import GPCore

    /// The root helper's XPC interface. The helper changes the network for
    /// the session, which runs in the app as the user: it opens a utun and
    /// hands over the descriptor, then sets the utun's addresses, routes and
    /// DNS from settings it checks first, and takes them out again. Nothing
    /// else: no login, no credentials, no packets. Requests and replies are
    /// JSON (`HelperRequest`, `HelperReply`), so the protocol itself never
    /// changes shape as messages are added.
    @objc public protocol AlbiHelperXPC {
        func call(_ request: Data, reply: @escaping @Sendable (Data) -> Void)
        /// Opens a utun for this connection, closing any it had, and replies
        /// with its descriptor and a `HelperReply` naming it. With no
        /// descriptor, the reply's `error` says why. The utun and everything
        /// set on it go when the connection does.
        func openTunnel(reply: @escaping @Sendable (FileHandle?, Data) -> Void)
    }

    public enum AlbiHelper {
        /// The Mach service and launchd label.
        public static let label = AlbiIDs.helperLabel
        /// The launchd plist inside the app's Contents/Library/LaunchDaemons.
        public static let plistName = AlbiIDs.helperPlist
        /// Bumped when requests or replies change incompatibly.
        public static let protocolVersion = 2
        /// Gateway addresses one install may route around the tunnel.
        public static let maxGateways = 16

        public static func interface() -> NSXPCInterface { NSXPCInterface(with: AlbiHelperXPC.self) }

        /// Whether the helper may give `s` a host route around the tunnel: an
        /// IPv4 address in dotted-quad form that a gateway could have, so not
        /// in 0.0.0.0/8, loopback, link-local, multicast or reserved.
        public static func isGatewayAddress(_ s: String) -> Bool {
            guard let b = UtunHost.bytes(v4: s), s == b.map(String.init).joined(separator: ".") else { return false }
            return b[0] != 0 && b[0] != 127 && b[0] < 224 && !(b[0] == 169 && b[1] == 254)
        }
    }

    /// One saved VPN, as the app keeps it in profiles.json.
    public struct StoredProfile: Codable, Equatable, Sendable, Identifiable {
        public var id: UUID
        public var name: String
        public var profile: Profile

        public init(id: UUID, name: String, profile: Profile) {
            self.id = id
            self.name = name
            self.profile = profile
        }
    }

    /// profiles.json: the profiles and the diagnostics setting.
    public struct HelperProfiles: Codable, Equatable, Sendable {
        public var profiles: [StoredProfile] = []
        public var diagnostics = DiagnosticsSettings()

        public init(profiles: [StoredProfile] = [], diagnostics: DiagnosticsSettings = DiagnosticsSettings()) {
            self.profiles = profiles
            self.diagnostics = diagnostics
        }
    }

    /// What the app's session asks of the root helper. Each tunnel request
    /// acts on the utun this connection opened, and fails without one.
    public enum HelperRequest: Codable, Sendable {
        /// The helper's protocol version and build, for the setup check.
        case hello
        /// Sets the utun's addresses and MTU.
        case configureInterface(TunnelSettings)
        /// Routes and DNS for the settings. `router` must be the router of
        /// one of the Mac's own network services; `gateways` are IPv4
        /// addresses that get host routes via it.
        case installNetwork(TunnelSettings, router: String?, gateways: [String], dnsMode: NetConfig.DNSMode)
        /// Re-points gateway and excluded routes at a new router.
        case updateRouter(String?)
        /// Takes out routes and DNS; the utun stays.
        case removeNetwork
        /// Takes out everything and closes the helper's end of the utun.
        case closeTunnel
        /// What the helper has set up now, for `albi-helper status`.
        case status
    }

    public struct HelperReply: Codable, Sendable {
        public var error: String?
        public var version: Int?
        public var build: String?
        /// The utun `openTunnel` made.
        public var interface: String?
        /// What's installed, for logs and `albi-helper status`.
        public var summary: String?

        public init(
            error: String? = nil, version: Int? = nil, build: String? = nil, interface: String? = nil,
            summary: String? = nil
        ) {
            self.error = error
            self.version = version
            self.build = build
            self.interface = interface
            self.summary = summary
        }
    }

    /// The session's status as the helper build's session reports it, and as
    /// the packet tunnel extension reports it in `ProviderMessage.Status.tunnel`.
    /// The app maps it onto its own `TunnelStatus`.
    public struct HelperStatus: Codable, Equatable, Sendable {
        public enum State: Codable, Equatable, Sendable {
            case disconnected
            case authenticating
            case waitingForPush
            case needsSecondFactor(prompt: String)
            /// "config", "hip" or "tunnel".
            case connecting(phase: String)
            case connected
            case reconnecting(attempt: Int, reason: String)
            case waitingForNetwork
            case disconnecting
            case needsLogin(reason: String)
            case failed(reason: String)
        }

        public var profileID: UUID?
        public var state: State
        public var gateway: String?
        public var ipv4: String?
        public var connectedSince: Date?
        public var cookieExpiry: Date?
        /// Split-tunnel routes as CIDR strings; empty for a full tunnel.
        public var routes: [String]
        public var dnsDomains: [String]
        public var hipRequested: Bool
        public var hipLastSent: Date?
        public var lastIncident: String?

        public init(
            profileID: UUID? = nil, state: State = .disconnected, gateway: String? = nil, ipv4: String? = nil,
            connectedSince: Date? = nil, cookieExpiry: Date? = nil, routes: [String] = [], dnsDomains: [String] = [],
            hipRequested: Bool = false, hipLastSent: Date? = nil, lastIncident: String? = nil
        ) {
            self.profileID = profileID
            self.state = state
            self.gateway = gateway
            self.ipv4 = ipv4
            self.connectedSince = connectedSince
            self.cookieExpiry = cookieExpiry
            self.routes = routes
            self.dnsDomains = dnsDomains
            self.hipRequested = hipRequested
            self.hipLastSent = hipLastSent
            self.lastIncident = lastIncident
        }
    }

    extension HelperStatus {
        /// Follows one of TunnelController's events. Returns false for events
        /// that don't change what the app shows (log lines, idle, stopped: the
        /// owner sets the final state once the session has ended).
        public mutating func apply(_ e: TunnelController.Event) -> Bool {
            switch e {
            case .authenticating: state = .authenticating
            case .waitingForPush: state = .waitingForPush
            case .needsSecondFactor(let prompt): state = .needsSecondFactor(prompt: prompt)
            case .state(let s):
                switch s {
                case .idle, .stopped: return false
                case .connecting(let phase): state = .connecting(phase: "\(phase)")
                case .connected: state = .connected
                case .reconnecting(let n, let why): state = .reconnecting(attempt: n, reason: why)
                case .waitingForNetwork: state = .waitingForNetwork
                case .reauthenticating: state = .authenticating
                case .needsLogin(let why): state = .needsLogin(reason: why)
                }
            case .log: return false
            }
            return true
        }

        /// Takes the gateway, address, routes, times and HIP from a snapshot.
        public mutating func apply(_ snap: TunnelController.Snapshot) {
            gateway = snap.gateway
            ipv4 = snap.settings?.ipv4Address
            connectedSince = snap.connectedSince
            cookieExpiry = snap.cookieExpiry
            if let s = snap.settings {
                routes = s.isFullTunnel ? [] : s.includedIPv4.map { "\($0.address)/\($0.prefixLength)" }
                dnsDomains = s.matchDomains ?? s.searchDomains
            }
            hipRequested = snap.hipRequested
            hipLastSent = snap.hipLastSent
            lastIncident = snap.lastIncident ?? lastIncident
        }
    }

    public enum HelperBuild {
        /// A helper binary's identity for "is the running helper this build?":
        /// its size and modification time.
        public static func id(ofExecutableAt path: String) -> String? {
            guard let a = try? FileManager.default.attributesOfItem(atPath: path),
                let size = a[.size] as? NSNumber, let mtime = a[.modificationDate] as? Date
            else { return nil }
            return "\(size.intValue)-\(Int(mtime.timeIntervalSince1970))"
        }
    }

    public enum HelperCoding {
        public static func encode<T: Encodable>(_ v: T) -> Data {
            let e = JSONEncoder()
            e.dateEncodingStrategy = .secondsSince1970
            e.outputFormatting = .sortedKeys
            return (try? e.encode(v)) ?? Data()
        }

        public static func decode<T: Decodable>(_ t: T.Type, _ d: Data) throws -> T {
            let dec = JSONDecoder()
            dec.dateDecodingStrategy = .secondsSince1970
            return try dec.decode(t, from: d)
        }
    }
#endif
