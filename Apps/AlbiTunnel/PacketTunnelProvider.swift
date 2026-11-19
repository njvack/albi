import AlbiConstants
import Diagnostics
import Foundation
import GPCore
import GPMac
import NetworkExtension
import os

private let log = Logger(subsystem: AlbiIDs.logSubsystem, category: "tunnel")

/// The packet tunnel. `TunnelController` logs in (or reuses a saved cookie)
/// and runs the session; macOS owns routes and DNS, which go away when this
/// process does.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var controller: TunnelController?
    private let hip = HIPBridge()
    /// hipreport inside this extension's bundle (Contents/MacOS), out of
    /// the user's reach. Used when the profile sets `bundledHIP`.
    private let bundledHIP = BundledHIP()
    private let probeLock = NSLock()
    private var lastProbe: ProviderMessage.HIPProbe?
    private var connectedOnce = false
    private var lastState: SessionState = .idle
    private let stateLock = NSLock()

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
            makeHost: { [weak self] hooks, _, _ in
                guard let self else { throw TunnelError("the provider went away") }
                return PacketFlowHost(provider: self, hooks: hooks)
            },
            onEvent: { [weak self] e in
                switch e {
                case .state(let s): self?.stateChanged(s)
                case .log(let m): log.info("\(m, privacy: .public)")
                default: break
                }
            })
        self.controller = controller

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
        stateLock.withLock { lastState = s }
        switch s {
        case .connected:
            connectedOnce = true
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
        Task {
            await controller?.stop()
            completionHandler()
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
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
        Task {
            if let report = req.hipReport {
                await hip.answer(report: report)
            } else if req.hipUnavailable == true {
                await hip.answer(report: nil)
            }
            if req.diagnosticsDump == true { controller?.saveDiagnosticsNow() }
            if req.clearCookies == true {
                controller?.clearCookies()
                log.notice("stored cookie cleared; logging out on stop")
            }
            if req.probeBundledHIP == true {
                let p = await bundledHIP.probe()
                log.notice("bundled hipreport probe: \(p.summary, privacy: .public) stderr: \(p.stderrHead ?? "", privacy: .public)")
                probeLock.withLock { lastProbe = p }
            }
            let state = stateLock.withLock { lastState }
            let snap = await controller?.snapshot()
            var status = ProviderMessage.Status(state: "\(state)", gateway: snap?.gateway, ipv4: snap?.settings?.ipv4Address,
                                                hipRequest: await hip.request, lastHIPReport: await hip.lastReport,
                                                lastIncident: snap?.lastIncident,
                                                diagnosticsEnabled: controller?.configuration.diagnostics.enabled)
            status.hipProbe = probeLock.withLock { lastProbe }
            completionHandler?(try? JSONEncoder().encode(status))
        }
    }
}

struct TunnelError: LocalizedError {
    var message: String
    init(_ m: String) { message = m }
    var errorDescription: String? { message }
}
