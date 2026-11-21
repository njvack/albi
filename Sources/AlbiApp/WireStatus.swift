#if canImport(SwiftUI)
    import Foundation
    import GPMac

    extension TunnelStatus {
        /// The status albi-helper and the packet tunnel extension send, as the
        /// UI shows it. Both backends map through here.
        public init(_ s: HelperStatus) {
            let state: TunnelState =
                switch s.state {
                case .disconnected: .disconnected
                case .authenticating: .authenticating
                case .waitingForPush: .waitingForPush
                case .needsSecondFactor(let p): .needsSecondFactor(prompt: p)
                case .connecting(let phase): .connecting(phase == "hip" ? .hip : phase == "tunnel" ? .tunnel : .config)
                case .connected: .connected(.https)
                case .reconnecting(let n, let why): .reconnecting(attempt: n, reason: why)
                case .waitingForNetwork: .waitingForNetwork
                case .disconnecting: .disconnecting
                case .needsLogin(let why): .needsLogin(reason: why)
                case .failed(let why): .failed(reason: why)
                }
            self.init(
                profileID: s.profileID, state: state, gateway: s.gateway, ipv4: s.ipv4,
                connectedSince: s.connectedSince, cookieExpiry: s.cookieExpiry, routes: s.routes,
                dnsDomains: s.dnsDomains,
                hip: s.hipRequested ? HIPStatus(requested: true, lastSent: s.hipLastSent) : nil,
                lastIncident: s.lastIncident)
        }
    }
#endif
