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
        /// Make HIP reports with the hipreport embedded in the extension's own
        /// bundle, instead of asking the app. Optional so profiles saved before
        /// it existed still decode.
        public var bundledHIP: Bool?
        /// "Clear stored cookies": the extension ignores cookies it saved at or
        /// before this time.
        public var cookiesClearedAt: Date?
        /// GlobalProtect version to report at login and in HIP reports, whatever
        /// the portal says. nil uses the portal's version.
        public var reportedVersion: String?

        public init(server: String, username: String) {
            self.server = server
            self.username = username
        }

        public var trust: TrustPolicy { pins.isEmpty ? .system : .pinned(pins) }

        /// Whether `server` is `host` or `host:port`, with host a DNS name, an
        /// IPv4 address or a bracketed IPv6 address: nothing a URL could be
        /// built around to reach somewhere else.
        public static func isValidServer(_ s: String) -> Bool {
            guard !s.isEmpty, s.utf8.count <= 260 else { return false }
            var host: Substring
            var port: Substring?
            if s.hasPrefix("[") {
                guard let end = s.firstIndex(of: "]") else { return false }
                host = s[s.index(after: s.startIndex)..<end]
                let rest = s[s.index(after: end)...]
                if !rest.isEmpty {
                    guard rest.hasPrefix(":") else { return false }
                    port = rest.dropFirst()
                }
                guard host.contains(":"), host.allSatisfy({ $0.isHexDigit || $0 == ":" || $0 == "." }) else {
                    return false
                }
            } else {
                let parts = s.split(separator: ":", omittingEmptySubsequences: false)
                guard parts.count <= 2 else { return false }
                host = parts[0]
                port = parts.count == 2 ? parts[1] : nil
                let labels = host.split(separator: ".", omittingEmptySubsequences: false)
                guard !host.isEmpty, host.utf8.count <= 253,
                    labels.allSatisfy({ l in
                        (1...63).contains(l.utf8.count) && l.first != "-" && l.last != "-"
                            && l.utf8.allSatisfy { b in
                                (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a)
                                    || b == 0x2d
                            }
                    })
                else { return false }
            }
            if let port {
                guard port.allSatisfy(\.isASCII), let n = Int(port), (1...65535).contains(n) else { return false }
            }
            return true
        }

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
                let p = try? JSONDecoder().decode(Profile.self, from: d)
            else { return nil }
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
            /// Step 1 probe: run the extension's bundled hipreport once and
            /// report what happened in `Status.hipProbe`.
            public var probeBundledHIP: Bool?
            /// "Clear stored cookies" while connected: forget the saved cookie,
            /// and log out when the tunnel stops.
            public var clearCookies: Bool?
            /// The answer to a `needsSecondFactor` prompt.
            public var secondFactorCode: String?

            public init(
                poll: Bool? = nil, hipReport: String? = nil, hipUnavailable: Bool? = nil,
                diagnosticsDump: Bool? = nil, probeBundledHIP: Bool? = nil, clearCookies: Bool? = nil,
                secondFactorCode: String? = nil
            ) {
                self.secondFactorCode = secondFactorCode
                self.clearCookies = clearCookies
                self.probeBundledHIP = probeBundledHIP
                self.poll = poll
                self.hipReport = hipReport
                self.hipUnavailable = hipUnavailable
                self.diagnosticsDump = diagnosticsDump
            }
        }

        public struct HIPRequest: Codable, Equatable, Sendable {
            /// The cookie's user, domain and computer in openconnect's cookie
            /// format, for `--cookie`. Never the authcookie.
            public var cookie: String
            public var clientIPv4: String?
            public var clientIPv6: String?
            public var md5: String
            public var clientOS: String
            public var appVersion: String

            public init(_ c: HIPContext) {
                // Only the fields a report names. The authcookie is a live
                // session token: it never goes on a command line (where `ps`
                // shows it to every user) or to another process.
                var f = Form()
                f.append("user", c.cookie.user)
                f.append("domain", c.cookie.domain)
                f.append("computer", c.cookie.computer)
                cookie = f.encoded
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
            /// The last bundled-hipreport probe, if one ran.
            public var hipProbe: HIPProbe?
            /// The session as the app shows it: the same status albi-helper
            /// sends, so both backends map onto the UI the same way.
            public var tunnel: HelperStatus?

            public init(
                state: String, gateway: String? = nil, ipv4: String? = nil, expiresIn: Double? = nil,
                hipRequest: HIPRequest? = nil, lastHIPReport: Date? = nil, lastIncident: String? = nil,
                diagnosticsEnabled: Bool? = nil
            ) {
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

        /// What happened when the extension ran a bundled helper.
        public struct HIPProbe: Codable, Equatable, Sendable {
            public var at: Date
            /// Where the helper was looked for; nil if the bundle has none.
            public var path: String?
            /// Set when the process could not be started (sandbox, signing, missing).
            public var launchError: String?
            public var exitStatus: Int32?
            public var seconds: Double?
            public var stdoutBytes: Int?
            /// The first bytes of stdout and stderr.
            public var stdoutHead: String?
            public var stderrHead: String?
            public var uid: UInt32

            public init(
                at: Date, path: String?, launchError: String? = nil, exitStatus: Int32? = nil, seconds: Double? = nil,
                stdoutBytes: Int? = nil, stdoutHead: String? = nil, stderrHead: String? = nil, uid: UInt32
            ) {
                self.at = at
                self.path = path
                self.launchError = launchError
                self.exitStatus = exitStatus
                self.seconds = seconds
                self.stdoutBytes = stdoutBytes
                self.stdoutHead = stdoutHead
                self.stderrHead = stderrHead
                self.uid = uid
            }

            public var summary: String {
                if path == nil { return "no hipreport in the extension's bundle" }
                if let launchError { return "could not start: \(launchError)" }
                let secs = seconds.map { String(format: "%.1f", $0) } ?? "?"
                return "exit \(exitStatus.map(String.init) ?? "?"), \(stdoutBytes ?? 0) bytes in \(secs) s, uid \(uid)"
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

    /// Holds a second-factor prompt from the session until the app answers it.
    /// Nobody may be there to answer, so it gives up after `timeout` and the
    /// session says a login is needed.
    public actor CodeBridge {
        private var pending: CheckedContinuation<String, Error>?

        public init() {}

        public func code(timeout: Double = 300) async throws -> String {
            pending?.resume(throwing: GPError.cancelled)
            pending = nil
            let t = Task { [weak self] in
                try? await Task.sleep(for: .seconds(timeout))
                await self?.expire()
            }
            defer { t.cancel() }
            return try await withCheckedThrowingContinuation { pending = $0 }
        }

        public func answer(_ code: String) {
            pending?.resume(returning: code)
            pending = nil
        }

        public func cancel() {
            pending?.resume(throwing: GPError.cancelled)
            pending = nil
        }

        private func expire() {
            pending?.resume(throwing: GPError.badCredentials("no verification code was entered"))
            pending = nil
        }
    }
#endif
