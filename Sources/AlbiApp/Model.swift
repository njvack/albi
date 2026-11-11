#if canImport(SwiftUI)
import Foundation
import GPMac

/// One saved VPN. `settings` is what the extension reads from the VPN
/// configuration; the id and name are the app's own.
public struct VPNProfile: Identifiable, Equatable, Sendable {
    public var id: UUID
    public var name: String
    public var settings: Profile

    public init(id: UUID = UUID(), name: String, settings: Profile) {
        self.id = id
        self.name = name
        self.settings = settings
    }

    /// The profile's second-factor setting, over `Profile.secondFactor`.
    public var secondFactor: SecondFactor {
        get { settings.secondFactor.map(SecondFactor.fixed) ?? .askEachTime }
        set {
            switch newValue {
            case .askEachTime: settings.secondFactor = nil
            case .fixed(let answer): settings.secondFactor = answer
            }
        }
    }

    /// Whether the extension can log in again by itself, without the user.
    public var canReconnectUnattended: Bool {
        settings.savePassword && secondFactor != .askEachTime
    }
}

/// What Albi does with the VPN when it opens ("At launch" in Settings).
public enum LaunchBehavior: String, CaseIterable, Sendable {
    case connect
    case dontConnect
    /// Connect if the user's last explicit choice was Connect. A drop, a quit
    /// or a reboot while connected still counts as connected; only Disconnect
    /// counts as disconnected.
    case restore

    public var title: String {
        switch self {
        case .connect: "Connect"
        case .dontConnect: "Don't connect"
        case .restore: "Restore last state"
        }
    }
}

public enum SecondFactor: Equatable, Hashable, Sendable {
    /// Prompt for the code each time the gateway asks.
    case askEachTime
    /// Always send this answer; "1" asks for a push.
    case fixed(String)
}

/// How the tunnel carries packets.
public enum Transport: String, Equatable, Sendable {
    case esp = "ESP"
    case https = "HTTPS"
}

/// What the tunnel is doing, as the UI shows it.
public enum TunnelState: Equatable, Sendable {
    case disconnected
    case authenticating
    /// Login is waiting for the user to approve a push on their phone.
    case waitingForPush
    /// The gateway wants a second-factor code and the profile asks each time.
    case needsSecondFactor(prompt: String)
    case connecting(Phase)
    case connected(Transport)
    /// Lost the tunnel and retrying with the same cookie.
    case reconnecting(attempt: Int, reason: String)
    case waitingForNetwork
    case disconnecting
    /// The cookie is gone and the extension cannot log in by itself.
    case needsLogin(reason: String)
    case failed(reason: String)

    public enum Phase: Equatable, Sendable {
        case config, hip, tunnel
    }

    public var isActive: Bool {
        switch self {
        case .disconnected, .needsLogin, .failed: false
        default: true
        }
    }

    public var isConnected: Bool {
        if case .connected = self { true } else { false }
    }
}

/// Everything the menu and the HIP panel show about the tunnel.
public struct TunnelStatus: Equatable, Sendable {
    public var profileID: UUID?
    public var state: TunnelState
    public var gateway: String?
    public var ipv4: String?
    public var connectedSince: Date?
    /// When the gateway's cookie lifetime ends.
    public var cookieExpiry: Date?
    /// Split-tunnel routes, as CIDR strings. Empty means everything goes through the tunnel.
    public var routes: [String]
    public var dnsDomains: [String]
    public var hip: HIPStatus?
    /// Path of the newest incident file diagnostics mode wrote.
    public var lastIncident: String?

    public init(profileID: UUID? = nil, state: TunnelState = .disconnected, gateway: String? = nil, ipv4: String? = nil,
                connectedSince: Date? = nil, cookieExpiry: Date? = nil, routes: [String] = [], dnsDomains: [String] = [],
                hip: HIPStatus? = nil, lastIncident: String? = nil) {
        self.profileID = profileID
        self.state = state
        self.gateway = gateway
        self.ipv4 = ipv4
        self.connectedSince = connectedSince
        self.cookieExpiry = cookieExpiry
        self.routes = routes
        self.dnsDomains = dnsDomains
        self.hip = hip
        self.lastIncident = lastIncident
    }

    public static let disconnected = TunnelStatus()
}

/// HIP for the current session. The gateway never says pass or fail; the
/// expected values come from a local policy file.
public struct HIPStatus: Equatable, Sendable {
    /// Whether the gateway asked for a report this session (hipreportcheck.esp).
    public var requested: Bool
    public var lastSent: Date?
    public var checks: [HIPCheck]

    public init(requested: Bool, lastSent: Date? = nil, checks: [HIPCheck] = []) {
        self.requested = requested
        self.lastSent = lastSent
        self.checks = checks
    }

    public var failing: [HIPCheck] { checks.filter { $0.passed == false } }
    public var isCompliant: Bool { failing.isEmpty }
}

public struct HIPCheck: Identifiable, Equatable, Sendable {
    public var id: String
    /// "Disk encryption", "Firewall", …
    public var category: String
    public var name: String
    public var expected: String
    public var actual: String
    /// How the value was collected, such as "fdesetup status".
    public var method: String
    /// nil when the policy has no expectation for this check.
    public var passed: Bool?

    public init(id: String, category: String, name: String, expected: String, actual: String, method: String, passed: Bool?) {
        self.id = id
        self.category = category
        self.name = name
        self.expected = expected
        self.actual = actual
        self.method = method
        self.passed = passed
    }
}

/// The pieces macOS has to approve before Albi can connect.
public struct SetupStatus: Equatable, Sendable {
    public enum Extension: Equatable, Sendable {
        case notActivated, awaitingApproval, active
        case failed(String)
    }
    public enum Helper: Equatable, Sendable {
        case notRegistered, awaitingApproval, registered
    }

    public var systemExtension: Extension
    public var vpnConfigurationAllowed: Bool
    /// The HIP helper is optional: without it, root-only checks report n/a.
    public var hipHelper: Helper

    public init(systemExtension: Extension = .notActivated, vpnConfigurationAllowed: Bool = false,
                hipHelper: Helper = .notRegistered) {
        self.systemExtension = systemExtension
        self.vpnConfigurationAllowed = vpnConfigurationAllowed
        self.hipHelper = hipHelper
    }

    /// Ready to connect. The optional helper doesn't count.
    public var isReady: Bool { systemExtension == .active && vpnConfigurationAllowed }
}
#endif
