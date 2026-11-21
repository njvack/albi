#if os(macOS)
    import AlbiConstants
    import Diagnostics
    import Foundation
    import GPCore

    /// The root helper's XPC interface. Requests and replies are JSON
    /// (`HelperRequest`, `HelperReply`), so the protocol itself never changes
    /// shape as messages are added.
    @objc public protocol AlbiHelperXPC {
        func call(_ request: Data, reply: @escaping @Sendable (Data) -> Void)
    }

    /// What the app exports back on the same connection, so the helper can push
    /// status as it changes.
    @objc public protocol AlbiHelperClientXPC {
        func statusChanged(_ status: Data)
    }

    public enum AlbiHelper {
        /// The Mach service and launchd label.
        public static let label = AlbiIDs.helperLabel
        /// The launchd plist inside the app's Contents/Library/LaunchDaemons.
        public static let plistName = AlbiIDs.helperPlist
        /// Root-owned state, readable by everyone.
        public static let directory = URL(fileURLWithPath: AlbiPaths.supportDirectory)
        public static let profilesFile = URL(fileURLWithPath: AlbiPaths.profiles)
        /// `{profile, wantConnected}`: what launchd's KeepAlive restart reconnects.
        public static let stateFile = URL(fileURLWithPath: AlbiPaths.helperState)
        /// Bumped when requests or replies change incompatibly.
        public static let protocolVersion = 1

        public static func interface() -> NSXPCInterface { NSXPCInterface(with: AlbiHelperXPC.self) }
        public static func clientInterface() -> NSXPCInterface { NSXPCInterface(with: AlbiHelperClientXPC.self) }
    }

    /// One saved VPN, as the helper keeps it in profiles.json.
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

    /// helper-state.json.
    public struct HelperDesiredState: Codable, Equatable, Sendable {
        public var profile: UUID?
        public var wantConnected: Bool

        public init(profile: UUID?, wantConnected: Bool) {
            self.profile = profile
            self.wantConnected = wantConnected
        }
    }

    public enum HelperRequest: Codable, Sendable {
        /// The helper's protocol version and build, for the setup check.
        case hello
        case loadProfiles
        case saveProfile(StoredProfile)
        case deleteProfile(UUID)
        case hasSavedPassword(UUID)
        case connect(UUID, password: String?)
        case disconnect
        case answerSecondFactor(String)
        case status
        case diagnosticsSettings
        case setDiagnosticsSettings(DiagnosticsSettings)
        case saveDiagnosticsNow
    }

    public struct HelperReply: Codable, Sendable {
        public var error: String?
        public var profiles: [StoredProfile]?
        public var flag: Bool?
        public var status: HelperStatus?
        public var diagnostics: DiagnosticsSettings?
        public var version: Int?
        public var build: String?

        public init(
            error: String? = nil, profiles: [StoredProfile]? = nil, flag: Bool? = nil, status: HelperStatus? = nil,
            diagnostics: DiagnosticsSettings? = nil, version: Int? = nil, build: String? = nil
        ) {
            self.error = error
            self.profiles = profiles
            self.flag = flag
            self.status = status
            self.diagnostics = diagnostics
            self.version = version
            self.build = build
        }
    }

    /// The tunnel's status as the helper reports it, and as the packet tunnel
    /// extension reports it in `ProviderMessage.Status.tunnel`. The app maps it
    /// onto its own `TunnelStatus`.
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
