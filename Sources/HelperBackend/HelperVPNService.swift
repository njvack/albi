#if canImport(SwiftUI)
import AlbiApp
import Diagnostics
import Foundation
import GPMac
import ServiceManagement

/// `VPNService` over XPC to albi-helper, the root LaunchDaemon that runs the
/// tunnel. The app registers the helper with SMAppService from its own
/// bundle; the helper keeps the profiles, the passwords and the tunnel, and
/// pushes status as it changes.
@MainActor
public final class HelperVPNService: VPNService {
    private var connection: NSXPCConnection?
    private let status = StatusBroadcaster()
    private lazy var receiver = StatusReceiver { [weak self] s in self?.received(s) }
    private var retry: Task<Void, Never>?

    public init() {}

    /// The helper inside this app: Contents/MacOS/albi-helper.
    static var bundledHelper: URL {
        Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/albi-helper")
    }

    /// The helper's launchd job: Contents/Library/LaunchDaemons/<plistName>.
    static var bundledPlist: URL {
        Bundle.main.bundleURL.appendingPathComponent("Contents/Library/LaunchDaemons/\(AlbiHelper.plistName)")
    }

    static var daemon: SMAppService { SMAppService.daemon(plistName: AlbiHelper.plistName) }

    // MARK: XPC

    private func xpc() -> NSXPCConnection {
        if let c = connection { return c }
        let c = NSXPCConnection(machServiceName: AlbiHelper.label, options: .privileged)
        c.remoteObjectInterface = AlbiHelper.interface()
        c.exportedInterface = AlbiHelper.clientInterface()
        c.exportedObject = receiver
        // The helper restarted (interrupted) or went away (invalidated):
        // ask again, which reconnects and resubscribes. XPC calls these and
        // the proxy's error handler on its own queue, so they must be
        // @Sendable: written bare in this @MainActor class they'd be
        // main-actor isolated, and Swift 6 traps when XPC calls them.
        c.interruptionHandler = { @Sendable [weak self] in Task { @MainActor in self?.lost() } }
        c.invalidationHandler = { @Sendable [weak self] in Task { @MainActor in self?.lost(invalidated: true) } }
        c.resume()
        connection = c
        return c
    }

    private func lost(invalidated: Bool = false) {
        if invalidated {
            connection?.invalidationHandler = nil
            connection = nil
        }
        guard retry == nil else { return }
        retry = Task { [weak self] in
            try? await Task.sleep(for: .seconds(1))
            guard let self else { return }
            self.retry = nil
            do {
                let r = try await self.call(.status, timeout: 5)
                if let s = r.status { self.received(s) }
            } catch {
                if self.status.current.state.isActive {
                    self.status.update { $0.state = .failed(reason: "The Albi helper isn't answering.") }
                }
            }
        }
    }

    struct Failure: LocalizedError {
        var message: String
        var errorDescription: String? { message }
    }

    /// Sends one request and waits for the reply. Throws the helper's error,
    /// or if it doesn't answer within `timeout` seconds.
    func call(_ req: HelperRequest, timeout: Double = 15) async throws -> HelperReply {
        let c = xpc()
        let data = HelperCoding.encode(req)
        let reply: Data = try await withCheckedThrowingContinuation { cont in
            let once = ResumeOnce(cont)
            let proxy = c.remoteObjectProxyWithErrorHandler { @Sendable e in
                once.resume(throwing: Failure(message: "The Albi helper isn't answering (\(e.localizedDescription))."))
            } as? AlbiHelperXPC
            guard let proxy else {
                once.resume(throwing: Failure(message: "The Albi helper connection is broken."))
                return
            }
            proxy.call(data) { once.resume(returning: $0) }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                once.resume(throwing: Failure(message: "The Albi helper didn't answer in \(Int(timeout)) seconds."))
            }
        }
        let r = try HelperCoding.decode(HelperReply.self, reply)
        if let e = r.error { throw Failure(message: e) }
        return r
    }

    private func received(_ s: HelperStatus) {
        status.send(Self.tunnelStatus(s))
    }

    // MARK: Profiles

    public func loadProfiles() async throws -> [VPNProfile] {
        try await call(.loadProfiles).profiles?.map(Self.vpnProfile) ?? []
    }

    public func save(_ profile: VPNProfile) async throws {
        _ = try await call(.saveProfile(StoredProfile(id: profile.id, name: profile.name, profile: profile.settings)))
    }

    public func delete(_ id: VPNProfile.ID) async throws {
        _ = try await call(.deleteProfile(id))
    }

    public func hasSavedPassword(for id: VPNProfile.ID) async -> Bool {
        (try? await call(.hasSavedPassword(id)))?.flag ?? false
    }

    // MARK: Tunnel

    public func connect(_ id: VPNProfile.ID, password: String?) async throws {
        _ = try await call(.connect(id, password: password))
    }

    public func disconnect() async {
        _ = try? await call(.disconnect)
    }

    public func answerSecondFactor(_ code: String) async {
        _ = try? await call(.answerSecondFactor(code))
    }

    public func currentStatus() async -> TunnelStatus {
        if let s = (try? await call(.status, timeout: 5))?.status { received(s) }
        return status.current
    }

    public func statusUpdates() -> AsyncStream<TunnelStatus> {
        // The helper pushes to clients it has heard from; make sure it has.
        Task { _ = await currentStatus() }
        return status.stream()
    }

    // MARK: Diagnostics

    public func diagnosticsSettings() async -> DiagnosticsSettings {
        (try? await call(.diagnosticsSettings, timeout: 5))?.diagnostics ?? DiagnosticsSettings()
    }

    public func setDiagnosticsSettings(_ settings: DiagnosticsSettings) async throws {
        _ = try await call(.setDiagnosticsSettings(settings))
    }

    public func saveDiagnosticsNow() async {
        _ = try? await call(.saveDiagnosticsNow)
    }

    // MARK: Setup

    public func setupStatus() async -> SetupStatus {
        SetupStatus(backend: .helper, helper: await helperState())
    }

    func helperState() async -> SetupStatus.Helper {
        guard FileManager.default.fileExists(atPath: Self.bundledHelper.path) else {
            return .unavailable("This copy of Albi has no helper in Contents/MacOS. Build the HelperApp scheme.")
        }
        switch Self.daemon.status {
        case .notRegistered: return .notRegistered
        case .requiresApproval: return .awaitingApproval
        case .notFound:
            // macOS also says notFound for a daemon that was never
            // registered, so only a missing plist means we can't offer it.
            guard FileManager.default.fileExists(atPath: Self.bundledPlist.path) else {
                return .unavailable("This copy of Albi has no helper plist in Contents/Library/LaunchDaemons.")
            }
            return .notRegistered
        case .enabled: break
        @unknown default: return .notRegistered
        }
        do {
            let hello = try await call(.hello, timeout: 5)
            if hello.version != AlbiHelper.protocolVersion {
                return .needsReinstall("The running helper speaks another version.")
            }
            if let mine = HelperBuild.id(ofExecutableAt: Self.bundledHelper.path), hello.build != mine {
                return .needsReinstall("The running helper is from another build of Albi.")
            }
            return .registered
        } catch {
            return .needsReinstall("The helper is registered but doesn't answer.")
        }
    }

    /// Registers the helper, first unregistering one that's stale. macOS
    /// asks the user to allow it in System Settings the first time (and may
    /// again after an unregister).
    public func registerHelper() async {
        let svc = Self.daemon
        if case .needsReinstall = await helperState() {
            try? await svc.unregister()
            connection?.invalidate()
            connection = nil
            try? await Task.sleep(for: .seconds(1))
        }
        do {
            try svc.register()
        } catch {
            // Usually "Operation not permitted" until the user allows it.
            NSLog("Albi: registering the helper: %@", String(describing: error))
        }
        if svc.status == .requiresApproval { SMAppService.openSystemSettingsLoginItems() }
    }

    public func activateSystemExtension() async {}
    public func allowVPNConfiguration() async {}

    // MARK: Mapping

    static func vpnProfile(_ p: StoredProfile) -> VPNProfile {
        VPNProfile(id: p.id, name: p.name, settings: p.profile)
    }

    static func tunnelStatus(_ s: HelperStatus) -> TunnelStatus { TunnelStatus(s) }
}

/// Receives the helper's status pushes on an XPC thread and hands them to
/// the main actor.
final class StatusReceiver: NSObject, AlbiHelperClientXPC, @unchecked Sendable {
    private let handler: @MainActor @Sendable (HelperStatus) -> Void

    init(_ handler: @escaping @MainActor @Sendable (HelperStatus) -> Void) { self.handler = handler }

    func statusChanged(_ data: Data) {
        guard let s = try? HelperCoding.decode(HelperStatus.self, data) else { return }
        let handler = handler
        Task { @MainActor in handler(s) }
    }
}

/// Resumes a continuation once: the reply, the error handler and the
/// timeout race.
final class ResumeOnce<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var cont: CheckedContinuation<T, Error>?

    init(_ c: CheckedContinuation<T, Error>) { cont = c }

    func resume(returning v: T) { take()?.resume(returning: v) }
    func resume(throwing e: Error) { take()?.resume(throwing: e) }

    private func take() -> CheckedContinuation<T, Error>? {
        lock.withLock {
            defer { cont = nil }
            return cont
        }
    }
}
#endif
