#if canImport(SwiftUI)
import Foundation

/// A menu-bar icon: a template image in the app's asset catalog, or an SF
/// Symbol.
public enum MenuBarIcon: Equatable, Sendable {
    case asset(String)
    case symbol(String)
}

/// How each tunnel state reads in the menu bar and the menu.
extension TunnelState {
    /// The menu-bar icon: the bridge glyphs from the app's asset catalog for
    /// the tunnel's own states, and SF Symbols where the user has to act.
    public var menuBarIcon: MenuBarIcon {
        switch self {
        case .disconnected, .disconnecting: .asset("MenuBarDisconnected")
        case .authenticating, .connecting, .reconnecting, .waitingForNetwork: .asset("MenuBarConnecting")
        case .connected: .asset("MenuBarConnected")
        case .waitingForPush, .needsSecondFactor: .symbol("iphone.radiowaves.left.and.right")
        case .needsLogin: .symbol("person.crop.circle.badge.exclamationmark")
        case .failed: .symbol("exclamationmark.shield")
        }
    }

    /// One line for the top of the menu.
    public func title(profile: String?) -> String {
        let name = profile ?? "VPN"
        return switch self {
        case .disconnected: "Not Connected"
        case .authenticating: "Logging In to \(name)…"
        case .waitingForPush: "Waiting for Push Approval…"
        case .needsSecondFactor: "Verification Code Needed"
        case .connecting(.config): "Getting Configuration…"
        case .connecting(.hip): "Sending HIP Report…"
        case .connecting(.tunnel): "Opening Tunnel…"
        case .connected(let t): "Connected to \(name) (\(t.rawValue))"
        case .reconnecting(let n, _): "Reconnecting (Attempt \(n))…"
        case .waitingForNetwork: "Waiting for Network…"
        case .disconnecting: "Disconnecting…"
        case .needsLogin: "Login Needed"
        case .failed: "Connection Failed"
        }
    }

    /// The reason behind a reconnect, login or failure state.
    public var detail: String? {
        switch self {
        case .reconnecting(_, let r), .needsLogin(let r), .failed(let r): r
        case .needsSecondFactor(let p): p
        case .waitingForPush: "Approve the sign-in on your phone."
        default: nil
        }
    }

    public var accessibilityLabel: String { "Albi: \(title(profile: nil))" }
}

extension TunnelStatus {
    /// "Expires in 7 hr, 59 min", for the menu.
    public func expiryText(now: Date = Date()) -> String? {
        guard let cookieExpiry else { return nil }
        let left = cookieExpiry.timeIntervalSince(now)
        guard left > 0 else { return "Login expired" }
        let f = DateComponentsFormatter()
        f.allowedUnits = left >= 3600 ? [.hour, .minute] : [.minute]
        f.unitsStyle = .abbreviated
        return "Login expires in " + (f.string(from: left) ?? "")
    }
}
#endif
