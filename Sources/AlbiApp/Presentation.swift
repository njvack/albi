#if canImport(SwiftUI)
import Foundation

/// How each tunnel state reads in the menu bar and the menu.
extension TunnelState {
    /// SF Symbol for the menu-bar icon.
    public var symbolName: String {
        switch self {
        case .disconnected: "shield"
        case .authenticating, .connecting: "shield.lefthalf.filled"
        case .waitingForPush, .needsSecondFactor: "iphone.radiowaves.left.and.right"
        case .connected(.esp): "lock.shield.fill"
        case .connected(.https): "lock.shield"
        case .reconnecting, .waitingForNetwork: "arrow.triangle.2.circlepath"
        case .disconnecting: "shield.slash"
        case .needsLogin: "person.crop.circle.badge.exclamationmark"
        case .failed: "exclamationmark.shield"
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
