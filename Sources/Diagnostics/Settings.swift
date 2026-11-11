import Foundation
import GPCore

/// The diagnostics-mode setting. The app saves it in the VPN configuration's
/// `providerConfiguration` under `key`; the extension reads it at start.
public struct DiagnosticsSettings: Codable, Equatable, Sendable {
    public var enabled = false
    /// History to keep, in minutes (2 to 30).
    public var windowMinutes = 10
    /// How long an outage with a usable network may last before it is an incident.
    public var graceSeconds = 60
    /// Dumps to keep on disk; older ones are deleted.
    public var keep = 20

    public init(enabled: Bool = false, windowMinutes: Int = 10) {
        self.enabled = enabled
        self.windowMinutes = windowMinutes
    }

    public static let key = "albi.diagnostics"
    /// Where the extension (root) writes dumps. Readable by everyone: dumps
    /// are redacted before they are written.
    public static let systemDirectory = URL(fileURLWithPath: "/Library/Application Support/Albi/Diagnostics")

    public var recorderPolicy: FlightRecorder.Policy {
        var p = FlightRecorder.Policy()
        p.window = Double(min(30, max(2, windowMinutes)) * 60)
        p.grace = Double(max(10, graceSeconds))
        return p
    }

    public init?(providerConfiguration: [String: Any]?) {
        guard let d = providerConfiguration?[Self.key] as? Data,
              let s = try? JSONDecoder().decode(Self.self, from: d) else { return nil }
        self = s
    }

    /// Adds this setting to a `providerConfiguration` dictionary.
    public func store(in config: inout [String: Any]) {
        config[Self.key] = (try? JSONEncoder().encode(self)) ?? Data()
    }
}
