#if canImport(SwiftUI)
import Foundation

/// Everything the app asks of macOS and the tunnel extension. The live
/// implementation sits on NETunnelProviderManager, OSSystemExtensionManager
/// and provider messages; `MockVPNService` stands in for previews, demos and
/// tests. The app holds no tunnel logic.
@MainActor
public protocol VPNService: AnyObject {
    /// Saved profiles, one VPN configuration each.
    func loadProfiles() async throws -> [VPNProfile]
    func save(_ profile: VPNProfile) async throws
    func delete(_ id: VPNProfile.ID) async throws
    /// Whether the extension holds a saved password for this profile.
    func hasSavedPassword(for id: VPNProfile.ID) async -> Bool

    /// Starts the tunnel. With `password` nil the extension uses its saved one.
    func connect(_ id: VPNProfile.ID, password: String?) async throws
    /// Disconnects and logs out, so the cookie is gone.
    func disconnect() async
    /// Answers a `.needsSecondFactor` prompt.
    func answerSecondFactor(_ code: String) async

    /// The status right now.
    func currentStatus() async -> TunnelStatus
    /// The current status, then each change. Each call gets its own stream.
    func statusUpdates() -> AsyncStream<TunnelStatus>

    func setupStatus() async -> SetupStatus
    func activateSystemExtension() async
    func allowVPNConfiguration() async
    func registerHIPHelper() async
}

/// Hands each subscriber of `statusUpdates()` the latest status and every
/// change after it.
@MainActor
public final class StatusBroadcaster {
    public private(set) var current: TunnelStatus
    private var subscribers: [UUID: AsyncStream<TunnelStatus>.Continuation] = [:]

    public init(_ initial: TunnelStatus = .disconnected) { current = initial }

    public func send(_ status: TunnelStatus) {
        current = status
        for c in subscribers.values { c.yield(status) }
    }

    public func update(_ change: (inout TunnelStatus) -> Void) {
        var s = current
        change(&s)
        send(s)
    }

    public func stream() -> AsyncStream<TunnelStatus> {
        let (stream, continuation) = AsyncStream.makeStream(of: TunnelStatus.self, bufferingPolicy: .bufferingNewest(16))
        let id = UUID()
        subscribers[id] = continuation
        continuation.onTermination = { [weak self] _ in
            Task { @MainActor in self?.subscribers[id] = nil }
        }
        continuation.yield(current)
        return stream
    }
}
#endif
