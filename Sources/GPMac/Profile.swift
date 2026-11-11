#if canImport(Network)
import Foundation
import GPCore

/// One VPN profile, as the app saves it in the VPN configuration's
/// `providerConfiguration` and the extension reads it back.
public struct Profile: Codable, Equatable, Sendable {
    public enum Mode: String, Codable, Sendable { case auto, portal, gateway }

    /// Portal or gateway, `host` or `host:port`.
    public var server: String
    public var username: String
    public var mode: Mode = .auto
    /// openconnect-style `pin-sha256:` pins; empty means the system trust store.
    public var pins: [String] = []
    /// Fixed answer to the second-factor challenge ("1" for a push), or nil to
    /// need the user each time (no unattended re-auth then).
    public var secondFactor: String? = "1"
    /// Save the password so the extension can log in again by itself.
    public var savePassword = true

    public init(server: String, username: String) {
        self.server = server
        self.username = username
    }

    public var trust: TrustPolicy { pins.isEmpty ? .system : .pinned(pins) }

    public var target: Login.Target {
        switch mode {
        case .auto: .auto(server)
        case .portal: .portal(server)
        case .gateway: .gateway(server)
        }
    }

    public static let key = "albi.profile"

    /// For `NETunnelProviderProtocol.providerConfiguration`.
    public var providerConfiguration: [String: Any] {
        [Profile.key: (try? JSONEncoder().encode(self)) ?? Data()]
    }

    public init?(providerConfiguration: [String: Any]?) {
        guard let d = providerConfiguration?[Profile.key] as? Data,
              let p = try? JSONDecoder().decode(Profile.self, from: d) else { return nil }
        self = p
    }
}

/// Messages from the app to the running extension (`sendProviderMessage`),
/// and the extension's answers. JSON on the wire.
public enum ProviderMessage {
    public struct Request: Codable, Sendable {
        /// Ask for status, and whether a HIP report is wanted.
        public var poll: Bool?
        /// The report for the pending HIP request.
        public var hipReport: String?
        /// The app has no way to make a report.
        public var hipUnavailable: Bool?
        /// "Save diagnostics now": write an incident file from the current
        /// window, whatever the session is doing. Needs diagnostics mode on.
        public var diagnosticsDump: Bool?

        public init(poll: Bool? = nil, hipReport: String? = nil, hipUnavailable: Bool? = nil,
                    diagnosticsDump: Bool? = nil) {
            self.poll = poll
            self.hipReport = hipReport
            self.hipUnavailable = hipUnavailable
            self.diagnosticsDump = diagnosticsDump
        }
    }

    public struct HIPRequest: Codable, Equatable, Sendable {
        /// openconnect's cookie string, for `--cookie`.
        public var cookie: String
        public var clientIPv4: String?
        public var clientIPv6: String?
        public var md5: String
        public var clientOS: String
        public var appVersion: String

        public init(_ c: HIPContext) {
            cookie = c.cookie.form.encoded
            clientIPv4 = c.clientIPv4
            clientIPv6 = c.clientIPv6
            md5 = c.md5
            clientOS = c.clientOS
            appVersion = c.appVersion
        }

        /// Arguments for a `--csd-wrapper` style HIP script, as openconnect passes them.
        public var wrapperArguments: [String] {
            var a = ["--cookie", cookie]
            if let clientIPv4 { a += ["--client-ip", clientIPv4] }
            if let clientIPv6 { a += ["--client-ipv6", clientIPv6] }
            return a + ["--md5", md5, "--client-os", clientOS]
        }
    }

    public struct Status: Codable, Equatable, Sendable {
        public var state: String
        public var gateway: String?
        public var ipv4: String?
        public var expiresIn: Double?
        public var hipRequest: HIPRequest?
        public var lastHIPReport: Date?
        /// Path of the newest incident file diagnostics mode wrote this
        /// session. The app notifies when it changes.
        public var lastIncident: String?
        public var diagnosticsEnabled: Bool?

        public init(state: String, gateway: String? = nil, ipv4: String? = nil, expiresIn: Double? = nil,
                    hipRequest: HIPRequest? = nil, lastHIPReport: Date? = nil, lastIncident: String? = nil,
                    diagnosticsEnabled: Bool? = nil) {
            self.lastIncident = lastIncident
            self.diagnosticsEnabled = diagnosticsEnabled
            self.state = state
            self.gateway = gateway
            self.ipv4 = ipv4
            self.expiresIn = expiresIn
            self.hipRequest = hipRequest
            self.lastHIPReport = lastHIPReport
        }
    }
}

/// Holds a HIP request from the session until the app answers it.
public actor HIPBridge {
    private var pending: (HIPContext, CheckedContinuation<String?, Error>)?
    public private(set) var lastReport: Date?

    public init() {}

    public var request: ProviderMessage.HIPRequest? { pending.map { ProviderMessage.HIPRequest($0.0) } }

    /// Waits for the app to supply a report. Throws after `timeout` seconds,
    /// so the session retries later.
    public func report(for c: HIPContext, timeout: Double) async throws -> String? {
        if let old = pending {
            pending = nil
            old.1.resume(throwing: CancellationError())
        }
        let t = Task { [weak self] in
            try? await Task.sleep(for: .seconds(timeout))
            await self?.expire()
        }
        defer { t.cancel() }
        return try await withCheckedThrowingContinuation { pending = (c, $0) }
    }

    public func answer(report: String?) {
        guard let p = pending else { return }
        pending = nil
        if report != nil { lastReport = Date() }
        p.1.resume(returning: report)
    }

    private func expire() {
        guard let p = pending else { return }
        pending = nil
        p.1.resume(throwing: GPError.server("the app did not supply a HIP report in time"))
    }
}
#endif
