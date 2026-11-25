#if canImport(SwiftUI)
    import Foundation
    import GPCore
    import GPMac

    /// The app's XPC connection to albi-helper, the root LaunchDaemon that
    /// opens the utun and changes routes and DNS for the session. Everything
    /// it is asked is a typed `HelperRequest`; it holds the tunnel only for
    /// as long as this connection lasts.
    public final class HelperConnection: @unchecked Sendable {
        private let lock = NSLock()
        private var connection: NSXPCConnection?
        private let requirement: String?
        private let onLost: @Sendable () -> Void

        /// `requirement` is what the helper must be signed as, if anything.
        /// `onLost` runs when an open connection breaks: the helper restarted
        /// or went away, and took the tunnel's network setup with it.
        public init(requirement: String?, onLost: @escaping @Sendable () -> Void = {}) {
            self.requirement = requirement
            self.onLost = onLost
        }

        struct Failure: LocalizedError {
            var message: String
            var errorDescription: String? { message }
        }

        private func xpc() -> NSXPCConnection {
            lock.withLock {
                if let c = connection { return c }
                let c = NSXPCConnection(machServiceName: AlbiHelper.label, options: .privileged)
                if let requirement { c.setCodeSigningRequirement(requirement) }
                c.remoteObjectInterface = AlbiHelper.interface()
                // XPC calls these on its own queue, so they must not be
                // isolated to an actor.
                c.interruptionHandler = { @Sendable [weak self] in self?.lost(invalidated: false) }
                c.invalidationHandler = { @Sendable [weak self] in self?.lost(invalidated: true) }
                c.resume()
                connection = c
                return c
            }
        }

        private func lost(invalidated: Bool) {
            if invalidated {
                lock.withLock {
                    connection?.invalidationHandler = nil
                    connection = nil
                }
            }
            onLost()
        }

        /// Drops the connection, and with it anything the helper set up for it.
        public func invalidate() {
            let c = lock.withLock {
                defer { connection = nil }
                return connection
            }
            c?.invalidationHandler = nil
            c?.invalidate()
        }

        private func proxy(_ fail: @escaping @Sendable (Error) -> Void) -> AlbiHelperXPC? {
            xpc().remoteObjectProxyWithErrorHandler { @Sendable e in
                fail(Failure(message: "The Albi helper isn't answering (\(e.localizedDescription))."))
            } as? AlbiHelperXPC
        }

        static func decode(_ data: Data) throws -> HelperReply {
            let r = try HelperCoding.decode(HelperReply.self, data)
            if let e = r.error { throw Failure(message: e) }
            return r
        }

        /// Sends one request and waits for the reply. Throws the helper's
        /// error, or if it doesn't answer within `timeout` seconds.
        @discardableResult
        public func call(_ req: HelperRequest, timeout: Double = 15) async throws -> HelperReply {
            let data = HelperCoding.encode(req)
            let reply: Data = try await withCheckedThrowingContinuation { cont in
                let once = ResumeOnce(cont)
                guard let proxy = proxy({ once.resume(throwing: $0) }) else {
                    once.resume(throwing: Failure(message: "The Albi helper connection is broken."))
                    return
                }
                proxy.call(data) { once.resume(returning: $0) }
                DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                    once.resume(throwing: Failure(message: "The Albi helper didn't answer in \(Int(timeout)) seconds."))
                }
            }
            return try Self.decode(reply)
        }

        /// `call` for callers on a dispatch queue, which block until the
        /// reply: UtunHost changes the network from its own serial queue.
        @discardableResult
        public func callBlocking(_ req: HelperRequest, timeout: Double = 15) throws -> HelperReply {
            let box = ResultBox()
            let done = DispatchSemaphore(value: 0)
            let finish: @Sendable (Result<Data, Error>) -> Void = { r in
                if box.set(r) { done.signal() }
            }
            if let proxy = proxy({ finish(.failure($0)) }) {
                proxy.call(HelperCoding.encode(req)) { finish(.success($0)) }
            } else {
                finish(.failure(Failure(message: "The Albi helper connection is broken.")))
            }
            if done.wait(timeout: .now() + timeout) == .timedOut {
                _ = box.set(.failure(Failure(message: "The Albi helper didn't answer in \(Int(timeout)) seconds.")))
            }
            return try Self.decode(try box.get())
        }

        /// Has the helper open a utun for this connection and takes over the
        /// descriptor it hands back.
        public func openTunnel(timeout: Double = 15) async throws -> UtunDevice {
            let (sent, data): (SendableHandle?, Data) = try await withCheckedThrowingContinuation { cont in
                let once = ResumeOnce(cont)
                guard let proxy = proxy({ once.resume(throwing: $0) }) else {
                    once.resume(throwing: Failure(message: "The Albi helper connection is broken."))
                    return
                }
                proxy.openTunnel { h, d in once.resume(returning: (h.map(SendableHandle.init), d)) }
                DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                    once.resume(throwing: Failure(message: "The Albi helper didn't answer in \(Int(timeout)) seconds."))
                }
            }
            let reply = try Self.decode(data)
            guard let handle = sent?.handle, let name = reply.interface else {
                throw Failure(message: "The Albi helper opened no tunnel interface.")
            }
            // Our own descriptor: the handle closes its copy when it goes.
            let fd = dup(handle.fileDescriptor)
            guard fd >= 0 else { throw Failure(message: "Couldn't take over the tunnel interface.") }
            return UtunDevice(adopting: fd, name: name)
        }
    }

    /// `TunnelNetwork` through the root helper: UtunHost's network changes,
    /// as typed requests on the connection that opened the utun.
    public final class HelperTunnelNetwork: TunnelNetwork, @unchecked Sendable {
        let helper: HelperConnection

        public init(_ helper: HelperConnection) { self.helper = helper }

        public func configure(_ settings: TunnelSettings) throws {
            try helper.callBlocking(.configureInterface(settings))
        }

        public func install(
            _ settings: TunnelSettings, router: String?, gateways: [String], dnsMode: NetConfig.DNSMode
        ) throws -> String {
            let gateways = Array(gateways.filter(AlbiHelper.isGatewayAddress).prefix(AlbiHelper.maxGateways))
            let r = try helper.callBlocking(
                .installNetwork(settings, router: router, gateways: gateways, dnsMode: dnsMode))
            return r.summary ?? ""
        }

        public func updateRouter(_ router: String?) throws {
            try helper.callBlocking(.updateRouter(router))
        }

        public func remove() { _ = try? helper.callBlocking(.removeNetwork) }

        public func close() { _ = try? helper.callBlocking(.closeTunnel) }
    }

    /// FileHandle isn't Sendable; this one is only passed along, then read once.
    struct SendableHandle: @unchecked Sendable {
        let handle: FileHandle
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

    /// The first result wins.
    final class ResultBox: @unchecked Sendable {
        private let lock = NSLock()
        private var result: Result<Data, Error>?

        func set(_ r: Result<Data, Error>) -> Bool {
            lock.withLock {
                guard result == nil else { return false }
                result = r
                return true
            }
        }

        func get() throws -> Data { try lock.withLock { result }!.get() }
    }
#endif
