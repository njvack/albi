#if os(macOS)
    import Darwin
    import Foundation

    /// A system error with the call that failed.
    public struct SystemError: Error, CustomStringConvertible {
        public var call: String
        public var code: Int32
        public init(_ call: String, _ code: Int32 = errno) {
            self.call = call
            self.code = code
        }

        public var description: String { "\(call): \(String(cString: strerror(code)))" }
    }

    /// `_IOW(group, num, T)` from <sys/ioccom.h>, which Swift doesn't import.
    func ioW<T>(_ group: Character, _ num: UInt, _: T.Type) -> UInt {
        0x8000_0000 | (UInt(MemoryLayout<T>.size) & 0x1fff) << 16 | UInt(group.asciiValue!) << 8 | num
    }

    /// `_IOWR(group, num, T)`.
    func ioWR<T>(_ group: Character, _ num: UInt, _: T.Type) -> UInt {
        0xC000_0000 | (UInt(MemoryLayout<T>.size) & 0x1fff) << 16 | UInt(group.asciiValue!) << 8 | num
    }

    /// A utun interface. The kernel makes it when the control socket connects and
    /// removes it, with its addresses and every route through it, when the last
    /// descriptor closes, however the process ends. Packets on the descriptor
    /// carry a 4-byte protocol family in front.
    public final class UtunDevice: @unchecked Sendable {
        public let fd: Int32
        public let name: String
        public var index: UInt32 { if_nametoindex(name) }

        private let lock = NSLock()
        private var source: DispatchSourceRead?
        private var closed = false

        public init() throws {
            let fd = socket(PF_SYSTEM, SOCK_DGRAM, 2 /* SYSPROTO_CONTROL */)
            guard fd >= 0 else { throw SystemError("socket(PF_SYSTEM)") }
            do {
                var info = ctl_info()
                withUnsafeMutableBytes(of: &info.ctl_name) { buf in
                    for (i, b) in "com.apple.net.utun_control".utf8.enumerated() { buf[i] = b }
                }
                let irc = withUnsafeMutablePointer(to: &info) { ioctl(fd, ioWR("N", 3, ctl_info.self), $0) }
                guard irc == 0 else { throw SystemError("CTLIOCGINFO") }

                var addr = sockaddr_ctl()
                addr.sc_len = UInt8(MemoryLayout<sockaddr_ctl>.size)
                addr.sc_family = UInt8(AF_SYSTEM)
                addr.ss_sysaddr = 2  // AF_SYS_CONTROL
                addr.sc_id = info.ctl_id
                addr.sc_unit = 0  // the next free utun
                let rc = withUnsafePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        connect(fd, $0, socklen_t(MemoryLayout<sockaddr_ctl>.size))
                    }
                }
                guard rc == 0 else { throw SystemError("connect utun_control") }

                var buf = [CChar](repeating: 0, count: Int(IFNAMSIZ))
                var len = socklen_t(buf.count)
                guard getsockopt(fd, 2 /* SYSPROTO_CONTROL */, 2 /* UTUN_OPT_IFNAME */, &buf, &len) == 0 else {
                    throw SystemError("UTUN_OPT_IFNAME")
                }
                name = String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
                _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
                _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
            } catch {
                Darwin.close(fd)
                throw error
            }
            self.fd = fd
        }

        deinit { close() }

        /// Sets the IPv4 address, point-to-point to itself as NetworkExtension
        /// does, replacing `previous` if given. Bringing an address up also
        /// brings the interface up.
        public func setIPv4(_ address: String, previous: String? = nil) throws {
            let s = socket(AF_INET, SOCK_DGRAM, 0)
            guard s >= 0 else { throw SystemError("socket(AF_INET)") }
            defer { Darwin.close(s) }
            if let previous, previous != address {
                var req = ifreq()
                setName(&req.ifr_name)
                withUnsafeMutableBytes(of: &req.ifr_ifru) { raw in
                    raw.storeBytes(of: Self.sockaddrIn(previous), as: sockaddr_in.self)
                }
                // SIOCDIFADDR; gone already is fine
                _ = withUnsafeMutablePointer(to: &req) { ioctl(s, ioW("i", 25, ifreq.self), $0) }
            }
            var req = ifaliasreq()
            setName(&req.ifra_name)
            let a = Self.sockaddrIn(address)
            withUnsafeMutableBytes(of: &req.ifra_addr) { $0.storeBytes(of: a, as: sockaddr_in.self) }
            withUnsafeMutableBytes(of: &req.ifra_broadaddr) { $0.storeBytes(of: a, as: sockaddr_in.self) }
            withUnsafeMutableBytes(of: &req.ifra_mask) {
                $0.storeBytes(of: Self.sockaddrIn("255.255.255.255"), as: sockaddr_in.self)
            }
            let rc = withUnsafeMutablePointer(to: &req) { ioctl(s, ioW("i", 26, ifaliasreq.self), $0) }
            guard rc == 0 else { throw SystemError("SIOCAIFADDR \(address)") }
        }

        /// Adds an IPv6 address. Through ifconfig: `in6_aliasreq` isn't in the
        /// SDK's public headers.
        public func addIPv6(_ address: String, prefixLength: Int) throws {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")
            p.arguments = [name, "inet6", address, "prefixlen", "\(prefixLength)", "alias"]
            try p.run()
            p.waitUntilExit()
            guard p.terminationStatus == 0 else { throw SystemError("ifconfig inet6 \(address)", EINVAL) }
        }

        public func setMTU(_ mtu: Int) throws {
            let s = socket(AF_INET, SOCK_DGRAM, 0)
            guard s >= 0 else { throw SystemError("socket(AF_INET)") }
            defer { Darwin.close(s) }
            var req = ifreq()
            setName(&req.ifr_name)
            req.ifr_ifru.ifru_mtu = Int32(mtu)
            let rc = withUnsafeMutablePointer(to: &req) { ioctl(s, ioW("i", 52, ifreq.self), $0) }
            guard rc == 0 else { throw SystemError("SIOCSIFMTU \(mtu)") }
        }

        /// Calls `handler` with each batch of packets the system sends into the
        /// tunnel, without their protocol-family header, on `queue`.
        public func startReading(on queue: DispatchQueue, _ handler: @escaping @Sendable ([[UInt8]]) -> Void) {
            let src = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
            let fd = self.fd
            src.setEventHandler {
                var buf = [UInt8](repeating: 0, count: 65536 + 4)
                var batch: [[UInt8]] = []
                while batch.count < 64 {
                    let n = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
                    guard n > 4 else { break }
                    batch.append(Array(buf[4..<n]))
                }
                if !batch.isEmpty { handler(batch) }
            }
            lock.withLock { source = src }
            src.resume()
        }

        /// Hands packets to the system. Drops what doesn't fit, as a link would.
        public func write(_ packets: [[UInt8]]) {
            for p in packets where !p.isEmpty {
                let family: UInt8 = p[0] >> 4 == 6 ? UInt8(AF_INET6) : UInt8(AF_INET)
                var out: [UInt8] = [0, 0, 0, family]
                out += p
                _ = out.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
            }
        }

        /// Closes the descriptor; the kernel removes the interface.
        public func close() {
            let (first, src): (Bool, DispatchSourceRead?) = lock.withLock {
                defer { closed = true }
                return (!closed, source)
            }
            guard first else { return }
            if let src {
                src.setCancelHandler { [fd] in _ = Darwin.close(fd) }
                src.cancel()
            } else {
                Darwin.close(fd)
            }
        }

        private func setName<T>(_ field: inout T) {
            withUnsafeMutableBytes(of: &field) { buf in
                for i in 0..<buf.count { buf[i] = 0 }
                for (i, b) in name.utf8.prefix(buf.count - 1).enumerated() { buf[i] = b }
            }
        }

        static func sockaddrIn(_ s: String) -> sockaddr_in {
            var a = sockaddr_in()
            a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            a.sin_family = sa_family_t(AF_INET)
            _ = inet_pton(AF_INET, s, &a.sin_addr)
            return a
        }
    }
#endif
