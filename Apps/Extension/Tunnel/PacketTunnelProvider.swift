import AlbiConstants
import Diagnostics
import Foundation
import GPCore
import GPMac
import NetworkExtension
import os
import Synchronization

private let log = Logger(subsystem: AlbiIDs.logSubsystem, category: "tunnel")

/// The packet tunnel. `TunnelController` logs in (or reuses a saved cookie)
/// and runs the session; macOS owns routes and DNS, which go away when this
/// process does.
///
/// NetworkExtension calls the overrides on its own queue, while
/// TunnelController's events and the Tasks here run elsewhere, so the
/// provider's mutable state lives in `state`, behind a mutex. That is what
/// makes it safe to share; it is `@unchecked` only because
/// NEPacketTunnelProvider itself isn't Sendable.
///
/// NetworkExtension lets its completion handlers be called from any thread,
/// but the SDK doesn't mark them @Sendable, so each override that finishes in
/// a Task first copies its handler into a `nonisolated(unsafe)` local.
final class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    private struct State {
        var controller: TunnelController?
        var lastProbe: ProviderMessage.HIPProbe?
        var connectedOnce = false
        var lastState: SessionState = .idle
        /// What the app shows, in the same shape albi-helper sends.
        var report = HelperStatus()
    }
    private let state = Mutex(State())
    private var controller: TunnelController? { state.withLock { $0.controller } }

    private let hip = HIPBridge()
    /// Second-factor codes from the app, for profiles that ask each time.
    private let codes = CodeBridge()
    /// hipreport inside this extension's bundle (Contents/MacOS), out of
    /// the user's reach. Used when the profile sets `bundledHIP`.
    private let bundledHIP = BundledHIP()

    /// Secrets live in the System keychain: this process runs as root.
    private let keychain = KeychainStore(service: AlbiIDs.tunnelKeychainService)

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let profile = Profile(providerConfiguration: proto.providerConfiguration) else {
            completionHandler(TunnelError("the VPN configuration has no Albi profile"))
            return
        }
        let diagSettings = DiagnosticsSettings(providerConfiguration: proto.providerConfiguration) ?? DiagnosticsSettings()
        let config = TunnelController.Configuration(profile: profile, password: options?["password"] as? String,
                                                    diagnostics: diagSettings, keychain: keychain)
        let controller = TunnelController(
            config,
            hipReport: { [hip, bundledHIP] ctx in
                if profile.bundledHIP == true { return try await bundledHIP.report(for: ctx) }
                return try await hip.report(for: ctx, timeout: 20)
            },
            askSecondFactor: { [codes] _ in try await codes.code() },
            makeHost: { [weak self] hooks, _, _ in
                guard let self else { throw TunnelError("the provider went away") }
                return PacketFlowHost(provider: self, hooks: hooks)
            },
            onEvent: { [weak self] e in
                self?.state.withLock { _ = $0.report.apply(e) }
                switch e {
                case .state(let s): self?.stateChanged(s)
                case .log(let m): log.info("\(m, privacy: .public)")
                default: break
                }
            })
        state.withLock {
            $0.controller = controller
            $0.report = HelperStatus(state: .authenticating)
        }

        nonisolated(unsafe) let completionHandler = completionHandler
        Task {
            do {
                try await controller.start()
                // Report success to macOS once the tunnel is up the first time.
                try await controller.waitUntilConnected()
                completionHandler(nil)
            } catch {
                log.error("start failed: \(String(describing: error), privacy: .public)")
                completionHandler(TunnelError("\(error)"))
            }
        }
    }

    private func stateChanged(_ s: SessionState) {
        let connectedOnce = state.withLock { st in
            st.lastState = s
            if case .connected = s { st.connectedOnce = true }
            return st.connectedOnce
        }
        switch s {
        case .connected:
            reasserting = false
        case .connecting, .reconnecting, .waitingForNetwork, .reauthenticating:
            if connectedOnce { reasserting = true }
        case .needsLogin(let why):
            if connectedOnce { cancelTunnelWithError(TunnelError("login needed: \(why)")) }
        case .stopped, .idle:
            break
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.info("stopping (reason \(reason.rawValue))")
        nonisolated(unsafe) let completionHandler = completionHandler
        Task {
            await codes.cancel()
            await controller?.stop()
            completionHandler()
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        nonisolated(unsafe) let completionHandler = completionHandler
        Task {
            await controller?.sleep()
            completionHandler()
        }
    }

    override func wake() {
        Task { await controller?.wake() }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let req = try? JSONDecoder().decode(ProviderMessage.Request.self, from: messageData) else {
            completionHandler?(nil)
            return
        }
        nonisolated(unsafe) let completionHandler = completionHandler
        Task {
            if let report = req.hipReport {
                await hip.answer(report: report)
            } else if req.hipUnavailable == true {
                await hip.answer(report: nil)
            }
            if let code = req.secondFactorCode { await codes.answer(code) }
            if req.diagnosticsDump == true { controller?.saveDiagnosticsNow() }
            if req.clearCookies == true {
                controller?.clearCookies()
                log.notice("stored cookie cleared; logging out on stop")
            }
            if req.probeBundledHIP == true {
                let p = await bundledHIP.probe()
                log.notice("bundled hipreport probe: \(p.summary, privacy: .public) stderr: \(p.stderrHead ?? "", privacy: .public)")
                state.withLock { $0.lastProbe = p }
            }
            let (sessionState, lastProbe) = state.withLock { ($0.lastState, $0.lastProbe) }
            let snap = await controller?.snapshot()
            var status = ProviderMessage.Status(state: "\(sessionState)", gateway: snap?.gateway, ipv4: snap?.settings?.ipv4Address,
                                                hipRequest: await hip.request, lastHIPReport: await hip.lastReport,
                                                lastIncident: snap?.lastIncident,
                                                diagnosticsEnabled: controller?.configuration.diagnostics.enabled)
            status.hipProbe = lastProbe
            var report = state.withLock { $0.report }
            if let snap { report.apply(snap) }
            status.tunnel = report
            completionHandler?(try? JSONEncoder().encode(status))
        }
    }
}

struct TunnelError: LocalizedError {
    var message: String
    init(_ m: String) { message = m }
    var errorDescription: String? { message }
}
