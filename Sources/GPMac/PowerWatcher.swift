#if os(macOS)
    import Foundation
    import IOKit
    import IOKit.pwr_mgt

    /// Reports system sleep and wake, for `Session`'s `.sleep` and `.wake`.
    /// NetworkExtension does this for a packet tunnel provider; a root helper has
    /// to ask IOKit itself.
    public final class PowerWatcher: @unchecked Sendable {
        public enum Event: Sendable {
            case willSleep
            case didWake
        }

        // iokit_common_msg(n) is 0xE0000000 | n; the macros don't import.
        static let canSystemSleep: UInt32 = 0xE000_0270
        static let systemWillSleep: UInt32 = 0xE000_0280
        static let systemHasPoweredOn: UInt32 = 0xE000_0300

        private let onEvent: @Sendable (Event) -> Void
        private let queue = DispatchQueue(label: "albi.power")
        private var rootPort: io_connect_t = 0
        private var notifier: io_object_t = 0
        private var port: IONotificationPortRef?

        public init(onEvent: @escaping @Sendable (Event) -> Void) {
            self.onEvent = onEvent
        }

        deinit { stop() }

        /// Starts watching. Returns false if IOKit refused.
        @discardableResult
        public func start() -> Bool {
            guard rootPort == 0 else { return true }
            let refcon = Unmanaged.passUnretained(self).toOpaque()
            rootPort = IORegisterForSystemPower(
                refcon, &port,
                { refcon, _, type, arg in
                    guard let refcon else { return }
                    Unmanaged<PowerWatcher>.fromOpaque(refcon).takeUnretainedValue().handle(type, arg)
                }, &notifier)
            guard rootPort != 0, let port else { return false }
            IONotificationPortSetDispatchQueue(port, queue)
            return true
        }

        public func stop() {
            guard rootPort != 0 else { return }
            IODeregisterForSystemPower(&notifier)
            IOServiceClose(rootPort)
            if let port { IONotificationPortDestroy(port) }
            rootPort = 0
            port = nil
        }

        private func handle(_ type: UInt32, _ arg: UnsafeMutableRawPointer?) {
            switch type {
            case Self.canSystemSleep:
                IOAllowPowerChange(rootPort, Int(bitPattern: arg))
            case Self.systemWillSleep:
                // Tell the session first; it closes the tunnel without waiting.
                onEvent(.willSleep)
                IOAllowPowerChange(rootPort, Int(bitPattern: arg))
            case Self.systemHasPoweredOn:
                onEvent(.didWake)
            default:
                break
            }
        }
    }
#endif
