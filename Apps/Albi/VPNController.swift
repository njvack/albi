import AppKit
import Diagnostics
import Foundation
import GPMac
import NetworkExtension
import SystemExtensions

/// Talks to macOS (system extension activation, the VPN configuration) and to
/// the running extension (status, HIP reports). Holds no tunnel logic.
@MainActor
final class VPNController: NSObject, ObservableObject {
    @Published var profile = Profile(server: "", username: "")
    @Published var hipCommand = UserDefaults.standard.string(forKey: "hipCommand") ?? "" {
        didSet { UserDefaults.standard.set(hipCommand, forKey: "hipCommand") }
    }
    @Published var extensionStatus = "unknown"
    @Published var vpnStatus = "not configured"
    @Published var sessionState = "-"
    @Published var ipv4: String?
    @Published var gateway: String?
    @Published var lastHIPReport: Date?
    @Published var message = ""
    /// Diagnostics mode; saved in the VPN configuration with the profile and
    /// read by the extension when it starts.
    @Published var diagnostics = DiagnosticsSettings()
    @Published var lastIncident: String?
    /// The last run of the extension's bundled hipreport (Step 1 probe).
    @Published var hipProbe: ProviderMessage.HIPProbe?

    private var manager: NETunnelProviderManager?
    private var pollTask: Task<Void, Never>?
    private var hipInFlight = false

    var tunnelBundleID: String {
        Bundle.main.object(forInfoDictionaryKey: "AlbiTunnelBundleIdentifier") as? String ?? ""
    }

    func load() async {
        do {
            let all = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = all.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == tunnelBundleID }
            if let proto = manager?.protocolConfiguration as? NETunnelProviderProtocol,
               let p = Profile(providerConfiguration: proto.providerConfiguration) {
                profile = p
                diagnostics = DiagnosticsSettings(providerConfiguration: proto.providerConfiguration) ?? DiagnosticsSettings()
            }
        } catch {
            message = "Loading VPN configurations failed: \(error.localizedDescription)"
        }
        NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.statusChanged() }
        }
        statusChanged()
    }

    // MARK: System extension

    func activateExtension() {
        let req = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: tunnelBundleID, queue: .main)
        req.delegate = self
        OSSystemExtensionManager.shared.submitRequest(req)
        extensionStatus = "activating…"
    }

    // MARK: VPN configuration

    func save() async {
        do {
            let m = manager ?? NETunnelProviderManager()
            let proto = (m.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
            proto.providerBundleIdentifier = tunnelBundleID
            proto.serverAddress = profile.server
            proto.username = profile.username
            var config = profile.providerConfiguration
            diagnostics.store(in: &config)
            proto.providerConfiguration = config
            m.protocolConfiguration = proto
            m.localizedDescription = "Albi (\(profile.server))"
            m.isEnabled = true
            try await m.saveToPreferences()
            try await m.loadFromPreferences()
            manager = m
            message = "Saved."
        } catch {
            message = "Saving the VPN configuration failed: \(error.localizedDescription)"
        }
        statusChanged()
    }

    func connect(password: String?) async {
        if manager == nil { await save() }
        guard let m = manager else { return }
        do {
            var options: [String: NSObject] = [:]
            if let password { options["password"] = password as NSString }
            try m.connection.startVPNTunnel(options: options)
            message = ""
        } catch {
            message = "Connect failed: \(error.localizedDescription)"
        }
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    // MARK: Status and HIP

    private func statusChanged() {
        guard let c = manager?.connection else {
            vpnStatus = "not configured"
            return
        }
        vpnStatus = Self.describe(c.status)
        switch c.status {
        case .connecting, .connected, .reasserting:
            startPolling()
        default:
            pollTask?.cancel()
            pollTask = nil
            if c.status == .disconnected { sessionState = "-" }
        }
    }

    private func startPolling() {
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.poll(ProviderMessage.Request(poll: true))
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    private func poll(_ req: ProviderMessage.Request) async {
        guard let session = manager?.connection as? NETunnelProviderSession,
              let data = try? JSONEncoder().encode(req) else { return }
        let reply: Data? = await withCheckedContinuation { cont in
            do {
                try session.sendProviderMessage(data) { cont.resume(returning: $0) }
            } catch {
                cont.resume(returning: nil)
            }
        }
        guard let reply, let status = try? JSONDecoder().decode(ProviderMessage.Status.self, from: reply) else { return }
        sessionState = status.state
        ipv4 = status.ipv4
        gateway = status.gateway
        lastHIPReport = status.lastHIPReport
        hipProbe = status.hipProbe
        if let path = status.lastIncident, path != lastIncident {
            lastIncident = path
            message = "Diagnostics saved an incident file: \(path)"
        }
        if let hip = status.hipRequest, !hipInFlight {
            hipInFlight = true
            let answer = await makeHIPReport(hip)
            await poll(answer)
            hipInFlight = false
        }
    }

    /// Asks the running extension to exec the hipreport in its own bundle
    /// once; the result comes back in the status.
    func probeBundledHIP() async {
        guard manager?.connection.status == .connected || manager?.connection.status == .reasserting else {
            message = "Connect first: the probe runs inside the extension."
            return
        }
        await poll(ProviderMessage.Request(probeBundledHIP: true))
        if let p = hipProbe { message = "Bundled hipreport: \(p.summary)" }
    }

    /// Asks the extension to write an incident file from its current window.
    func saveDiagnosticsNow() async {
        await poll(ProviderMessage.Request(diagnosticsDump: true))
    }

    func showDiagnostics() {
        let dir = DiagnosticsSettings.systemDirectory
        if let last = lastIncident {
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: last)])
        } else {
            NSWorkspace.shared.open(dir)
        }
    }

    /// Runs the HIP command as openconnect runs a --csd-wrapper.
    private func makeHIPReport(_ r: ProviderMessage.HIPRequest) async -> ProviderMessage.Request {
        let cmd = hipCommand.trimmingCharacters(in: .whitespaces)
        guard !cmd.isEmpty else { return ProviderMessage.Request(hipUnavailable: true) }
        let result: String? = await Task.detached {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: cmd)
            p.arguments = r.wrapperArguments
            var env = ProcessInfo.processInfo.environment
            env["APP_VERSION"] = r.appVersion
            p.environment = env
            let out = Pipe()
            p.standardOutput = out
            do { try p.run() } catch { return nil }
            let data = out.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            return p.terminationStatus == 0 ? String(decoding: data, as: UTF8.self) : nil
        }.value
        if let result { return ProviderMessage.Request(hipReport: result) }
        message = "The HIP command failed; the tunnel will retry the HIP check."
        return ProviderMessage.Request(hipUnavailable: true)
    }

    static func describe(_ s: NEVPNStatus) -> String {
        switch s {
        case .invalid: "invalid"
        case .disconnected: "disconnected"
        case .connecting: "connecting"
        case .connected: "connected"
        case .reasserting: "reconnecting"
        case .disconnecting: "disconnecting"
        @unknown default: "unknown"
        }
    }
}

extension VPNController: OSSystemExtensionRequestDelegate {
    nonisolated func request(_ request: OSSystemExtensionRequest,
                             actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in self.extensionStatus = "waiting for approval in System Settings › General › Login Items & Extensions" }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor in self.extensionStatus = result == .completed ? "active" : "active after restart" }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let msg = error.localizedDescription
        Task { @MainActor in self.extensionStatus = "failed: \(msg)" }
    }
}
