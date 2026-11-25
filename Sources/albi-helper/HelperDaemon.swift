#if os(macOS)
    import AlbiConstants
    import Foundation
    import GPCore
    import GPMac
    import os

    private let log = Logger(subsystem: AlbiIDs.logSubsystem, category: "helper")

    enum HelperDaemon {
        /// Identifies this binary: its size and modification time. The app
        /// compares it with the helper in its own bundle to spot a helper that
        /// launchd is still running from before a rebuild.
        static var build: String {
            executable.flatMap { HelperBuild.id(ofExecutableAt: $0.path) } ?? "unknown"
        }

        /// This process's binary. Not Bundle.main: inside the app, that is the
        /// app's own executable.
        static var executable: URL? {
            var size: UInt32 = 0
            _ = _NSGetExecutablePath(nil, &size)
            var buf = [CChar](repeating: 0, count: Int(size) + 1)
            guard _NSGetExecutablePath(&buf, &size) == 0 else { return nil }
            let path = String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            return URL(fileURLWithPath: path).resolvingSymlinksInPath()
        }

        static func main() {
            signal(SIGPIPE, SIG_IGN)
            let removed = NetConfig.sweep { log.notice("\($0, privacy: .public)") }
            if !removed.isEmpty { log.notice("startup sweep removed \(removed.count) route(s)") }

            let core = HelperCore()
            let listener = NSXPCListener(machServiceName: AlbiHelper.label)
            let requirement = executable.flatMap(AlbiHelper.clientRequirement(helper:))
            if let requirement {
                log.notice("accepting clients that meet: \(requirement, privacy: .public)")
            } else {
                log.fault("albi-helper is unsigned or its signature is broken; refusing every client")
            }
            let delegate = ListenerDelegate(core: core, requirement: requirement)
            listener.delegate = delegate
            listener.resume()
            log.notice("albi-helper started (build \(build, privacy: .public), pid \(getpid()))")

            // launchd sends SIGTERM to stop us (unload, shutdown, unregister).
            // Take out whatever we set up; the session in the app sees the
            // connection go and reconnects when we're back.
            var sources: [DispatchSourceSignal] = []
            for sig in [SIGTERM, SIGINT] {
                signal(sig, SIG_IGN)
                let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
                src.setEventHandler {
                    log.notice("signal \(sig): stopping")
                    Task {
                        await core.shutdown()
                        exit(0)
                    }
                }
                src.resume()
                sources.append(src)
            }
            withExtendedLifetime((listener, delegate, sources)) { dispatchMain() }
        }
    }

    // The listener delegate and the exported object hold only the HelperCore
    // actor, so they are Sendable and their Tasks can capture them.
    final class ListenerDelegate: NSObject, NSXPCListenerDelegate, Sendable {
        let core: HelperCore
        /// The code-signing requirement a client must meet; nil accepts nobody.
        let requirement: String?

        init(core: HelperCore, requirement: String?) {
            self.core = core
            self.requirement = requirement
        }

        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
            // XPC checks the requirement against the caller's audit token on
            // every message, not its PID or path, so a process can't pass by
            // exec'ing something else after connecting.
            guard let requirement else { return false }
            c.setCodeSigningRequirement(requirement)
            let client = HelperClient(pid: c.processIdentifier, uid: c.effectiveUserIdentifier)
            c.exportedInterface = AlbiHelper.interface()
            c.exportedObject = Exported(core: core, client: client)
            // Whatever this client set up goes with it, however it ends.
            c.invalidationHandler = { [core] in Task { await core.release(client) } }
            c.interruptionHandler = { [core] in Task { await core.release(client) } }
            c.resume()
            return true
        }
    }

    /// One XPC connection, by identity.
    final class HelperClient: Sendable, Hashable, CustomStringConvertible {
        let pid: pid_t
        let uid: uid_t
        init(pid: pid_t, uid: uid_t) {
            self.pid = pid
            self.uid = uid
        }

        var description: String { "pid \(pid) uid \(uid)" }
        static func == (a: HelperClient, b: HelperClient) -> Bool { a === b }
        func hash(into h: inout Hasher) { h.combine(ObjectIdentifier(self)) }
    }

    final class Exported: NSObject, AlbiHelperXPC, Sendable {
        let core: HelperCore
        let client: HelperClient
        init(core: HelperCore, client: HelperClient) {
            self.core = core
            self.client = client
        }

        func call(_ request: Data, reply: @escaping @Sendable (Data) -> Void) {
            let req: HelperRequest
            do {
                req = try HelperCoding.decode(HelperRequest.self, request)
            } catch {
                reply(HelperCoding.encode(HelperReply(error: "albi-helper could not read the request: \(error)")))
                return
            }
            Task { [core, client] in
                let r = await core.handle(req, from: client)
                reply(HelperCoding.encode(r))
            }
        }

        func openTunnel(reply: @escaping @Sendable (FileHandle?, Data) -> Void) {
            Task { [core, client] in
                let (handle, r) = await core.open(for: client)
                reply(handle, HelperCoding.encode(r))
            }
        }
    }

    /// The one tunnel the helper has set up, and the client it's for. The
    /// helper keeps no other state: profiles, credentials and the session
    /// are the app's.
    actor HelperCore {
        private struct Lease {
            let client: HelperClient
            let device: UtunDevice
            let network: LocalTunnelNetwork
            var summary: String?
        }

        private var lease: Lease?

        // MARK: The utun

        /// Opens a utun for `client` and hands back a descriptor for it. One
        /// tunnel at a time: routes and DNS from two would fight.
        func open(for client: HelperClient) -> (FileHandle?, HelperReply) {
            if let l = lease {
                guard l.client == client else {
                    log.error(
                        "\(client, privacy: .public) asked for a tunnel while \(l.client, privacy: .public) has one")
                    return (nil, HelperReply(error: "Another Albi session has the VPN open."))
                }
                close("reopened")
            }
            // Routes a crashed run journaled and nobody swept.
            NetConfig.sweep { log.notice("\($0, privacy: .public)") }
            let device: UtunDevice
            do { device = try UtunDevice() } catch {
                log.error("opening a utun: \(String(describing: error), privacy: .public)")
                return (nil, HelperReply(error: "The helper couldn't open a tunnel interface: \(error)"))
            }
            let copy = dup(device.fd)
            guard copy >= 0 else {
                device.close()
                return (nil, HelperReply(error: "The helper couldn't hand over the tunnel interface."))
            }
            let network = LocalTunnelNetwork(interface: device.interface) { log.notice("\($0, privacy: .public)") }
            lease = Lease(client: client, device: device, network: network)
            log.notice("\(device.name, privacy: .public) opened for \(client, privacy: .public)")
            return (FileHandle(fileDescriptor: copy, closeOnDealloc: true), HelperReply(interface: device.name))
        }

        /// The client went away: take out what it set up.
        func release(_ client: HelperClient) {
            guard lease?.client == client else { return }
            close("\(client) went away")
        }

        func shutdown() {
            close("helper stopping")
        }

        private func close(_ why: String) {
            guard let l = lease else { return }
            lease = nil
            l.network.close()
            l.device.close()
            log.notice("\(l.device.name, privacy: .public) closed: \(why, privacy: .public)")
        }

        // MARK: Requests

        func handle(_ req: HelperRequest, from client: HelperClient) -> HelperReply {
            switch req {
            case .hello:
                return HelperReply(version: AlbiHelper.protocolVersion, build: HelperDaemon.build)
            case .status:
                guard let l = lease else { return HelperReply(summary: "no tunnel") }
                return HelperReply(
                    interface: l.device.name, summary: "\(l.client): \(l.summary ?? "no routes or DNS")")
            case .closeTunnel:
                if lease?.client == client { close("closed by \(client)") }
                return HelperReply()
            default:
                break
            }
            guard var l = lease, l.client == client else {
                return HelperReply(error: "This connection has no tunnel open.")
            }
            do {
                switch req {
                case .configureInterface(let s):
                    try l.network.configure(try s.checked())
                case .installNetwork(let s, let router, let gateways, let dnsMode):
                    let s = try s.checked()
                    try Self.checkRouter(router)
                    guard gateways.count <= AlbiHelper.maxGateways, gateways.allSatisfy(AlbiHelper.isGatewayAddress)
                    else { throw Refused("gateway addresses \(gateways)") }
                    l.summary = try l.network.install(s, router: router, gateways: gateways, dnsMode: dnsMode)
                    lease = l
                    return HelperReply(summary: l.summary)
                case .updateRouter(let router):
                    try Self.checkRouter(router)
                    try l.network.updateRouter(router)
                case .removeNetwork:
                    l.network.remove()
                    l.summary = nil
                    lease = l
                case .hello, .status, .closeTunnel:
                    break
                }
                return HelperReply()
            } catch {
                log.error("\(client, privacy: .public): \(String(describing: error), privacy: .public)")
                return HelperReply(error: "\(error)")
            }
        }

        /// Excluded and gateway routes go via the router of one of the Mac's
        /// own network services, never somewhere the client names.
        static func checkRouter(_ router: String?) throws {
            guard let router else { return }
            guard PathWatcher.serviceRouters().contains(router) else { throw Refused("router \(router)") }
        }
    }

    struct Refused: Error, CustomStringConvertible {
        var what: String
        init(_ what: String) { self.what = what }
        var description: String { "refused: \(what)" }
    }

    /// `albi-helper status`: prints the running helper's status as JSON.
    enum HelperStatusCommand {
        static func run() {
            let c = NSXPCConnection(machServiceName: AlbiHelper.label, options: .privileged)
            c.remoteObjectInterface = AlbiHelper.interface()
            c.resume()
            let done = DispatchSemaphore(value: 0)
            let proxy =
                c.remoteObjectProxyWithErrorHandler { e in
                    print("albi-helper isn't answering: \(e.localizedDescription)")
                    exit(1)
                } as? AlbiHelperXPC
            for req in [HelperRequest.hello, .status] {
                proxy?.call(HelperCoding.encode(req)) { data in
                    print(String(decoding: data, as: UTF8.self))
                    done.signal()
                }
                if done.wait(timeout: .now() + 5) == .timedOut {
                    print("albi-helper didn't answer in 5 s")
                    exit(1)
                }
            }
            exit(0)
        }
    }
#endif
