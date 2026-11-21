#if canImport(Network)
    import Foundation
    import GPCore

    /// Somewhere to keep small secrets by name: the keychain in the extension,
    /// a dictionary in tests.
    public protocol SecretStore: Sendable {
        func get(_ account: String) -> Data?
        func put(_ account: String, _ data: Data?)
    }

    /// A gateway session the extension can pick up again without a login.
    public struct SavedCookie: Codable, Equatable, Sendable {
        public var cookie: AuthCookie
        public var gateway: String
        public var appVersion: String?
        public var hipInterval: Double?
        /// nil for cookies saved before this was recorded.
        public var savedAt: Date?

        public init(
            cookie: AuthCookie, gateway: String, appVersion: String? = nil, hipInterval: Double? = nil,
            savedAt: Date? = nil
        ) {
            self.cookie = cookie
            self.gateway = gateway
            self.appVersion = appVersion
            self.hipInterval = hipInterval
            self.savedAt = savedAt
        }
    }

    /// Saved cookies, one per user and gateway, plus which gateway each profile
    /// last used. Disconnecting keeps them: a GlobalProtect cookie outlives the
    /// tunnel (72 h with a 12 h idle timeout on the gateway in #15), so the next
    /// connect can skip the login and its push. A rejected cookie is removed and
    /// the session logs in again.
    public struct CookieStore: Sendable {
        public var store: any SecretStore
        public var username: String
        /// The profile's server, portal or gateway.
        public var server: String

        public init(store: any SecretStore, username: String, server: String) {
            self.store = store
            self.username = username
            self.server = server
        }

        func cookieKey(_ gateway: String) -> String { "cookie:\(username)@\(gateway)" }
        /// The gateway this profile's last session used.
        var gatewayKey: String { "gateway:\(username)@\(server)" }
        /// Where cookies were saved before they were kept per gateway: one per
        /// profile. For a gateway-mode profile it is the same key.
        var profileKey: String { "cookie:\(username)@\(server)" }

        /// The cookie to try first. A gateway-mode profile only takes one for its
        /// own server. Cookies saved at or before `clearedAt` don't count.
        public func load(mode: Profile.Mode, clearedAt: Date?) -> SavedCookie? {
            var keys: [String] = []
            if mode == .gateway {
                keys.append(cookieKey(server))
            } else if let gw = store.get(gatewayKey).map({ String(decoding: $0, as: UTF8.self) }) {
                keys.append(cookieKey(gw))
            }
            if !keys.contains(profileKey) { keys.append(profileKey) }
            for key in keys {
                guard let d = store.get(key), let saved = try? JSONDecoder().decode(SavedCookie.self, from: d) else {
                    continue
                }
                if mode == .gateway && saved.gateway != server { continue }
                if let cleared = clearedAt, (saved.savedAt ?? .distantPast) <= cleared { continue }
                return saved
            }
            return nil
        }

        public func save(_ saved: SavedCookie) {
            guard let d = try? JSONEncoder().encode(saved) else { return }
            store.put(cookieKey(saved.gateway), d)
            store.put(gatewayKey, Data(saved.gateway.utf8))
            if profileKey != cookieKey(saved.gateway) { store.put(profileKey, nil) }
        }

        /// Forgets this profile's cookie for `gateway`, or for the gateway it
        /// last used.
        public func remove(gateway: String? = nil) {
            let gw = gateway ?? store.get(gatewayKey).map { String(decoding: $0, as: UTF8.self) }
            if let gw { store.put(cookieKey(gw), nil) }
            store.put(profileKey, nil)
        }
    }

    #if canImport(Security)
        extension KeychainStore: SecretStore {
            public func put(_ account: String, _ data: Data?) { set(account, data) }
        }
    #endif
#endif
