#if canImport(Network)
import Foundation
import Testing
import GPCore
@testable import GPMac

final class MemoryStore: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]
    func get(_ account: String) -> Data? { lock.withLock { items[account] } }
    func put(_ account: String, _ data: Data?) { lock.withLock { items[account] = data } }
    var keys: Set<String> { lock.withLock { Set(items.keys) } }
}

@Suite struct CookieStoreTests {
    func saved(_ value: String, gateway: String, at: Date? = Date()) -> SavedCookie {
        SavedCookie(cookie: AuthCookie(authcookie: value, portal: nil, user: "nate", domain: nil, computer: "mac"),
                    gateway: gateway, savedAt: at)
    }

    @Test func keepsOneCookiePerGateway() {
        let m = MemoryStore()
        let c = CookieStore(store: m, username: "nate", server: "portal.example.edu")
        c.save(saved("a", gateway: "gw1.example.edu"))
        c.save(saved("b", gateway: "gw2.example.edu"))
        #expect(m.keys.contains("cookie:nate@gw1.example.edu"))
        #expect(m.keys.contains("cookie:nate@gw2.example.edu"))
        // The last gateway used is tried first.
        #expect(c.load(mode: .auto, clearedAt: nil)?.cookie.authcookie == "b")
        c.save(saved("a2", gateway: "gw1.example.edu"))
        #expect(c.load(mode: .portal, clearedAt: nil)?.cookie.authcookie == "a2")
    }

    @Test func gatewayModeTakesOnlyItsOwnServer() {
        let m = MemoryStore()
        CookieStore(store: m, username: "nate", server: "portal.example.edu").save(saved("p", gateway: "gw.example.edu"))
        let gw = CookieStore(store: m, username: "nate", server: "other.example.edu")
        #expect(gw.load(mode: .gateway, clearedAt: nil) == nil)
        let same = CookieStore(store: m, username: "nate", server: "gw.example.edu")
        #expect(same.load(mode: .gateway, clearedAt: nil)?.cookie.authcookie == "p")
    }

    @Test func readsTheOldPerProfileKey() throws {
        let m = MemoryStore()
        let old = saved("old", gateway: "gw.example.edu", at: nil)
        m.put("cookie:nate@portal.example.edu", try JSONEncoder().encode(old))
        let c = CookieStore(store: m, username: "nate", server: "portal.example.edu")
        #expect(c.load(mode: .auto, clearedAt: nil) == old)
        c.save(saved("new", gateway: "gw.example.edu"))
        #expect(!m.keys.contains("cookie:nate@portal.example.edu"))
    }

    @Test func ignoresCookiesSavedBeforeAClear() {
        let m = MemoryStore()
        let c = CookieStore(store: m, username: "nate", server: "gw.example.edu")
        let t = Date()
        c.save(saved("x", gateway: "gw.example.edu", at: t.addingTimeInterval(-60)))
        #expect(c.load(mode: .gateway, clearedAt: t) == nil)
        #expect(c.load(mode: .gateway, clearedAt: nil) != nil)
        c.save(saved("y", gateway: "gw.example.edu", at: t.addingTimeInterval(60)))
        #expect(c.load(mode: .gateway, clearedAt: t)?.cookie.authcookie == "y")
        // A cookie with no save time predates any clear.
        c.save(saved("z", gateway: "gw.example.edu", at: nil))
        #expect(c.load(mode: .gateway, clearedAt: t) == nil)
    }

    @Test func removeForgetsTheLastGateway() {
        let m = MemoryStore()
        let c = CookieStore(store: m, username: "nate", server: "portal.example.edu")
        c.save(saved("a", gateway: "gw1.example.edu"))
        c.save(saved("b", gateway: "gw2.example.edu"))
        c.remove()
        #expect(!m.keys.contains("cookie:nate@gw2.example.edu"))
        #expect(m.keys.contains("cookie:nate@gw1.example.edu"))
        c.remove(gateway: "gw1.example.edu")
        #expect(c.load(mode: .auto, clearedAt: nil) == nil)
    }
}
#endif
