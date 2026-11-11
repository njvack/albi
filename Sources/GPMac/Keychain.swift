#if canImport(Security)
import Foundation
import Security

/// Generic-password items. In the system extension, which runs as root, these
/// land in the System keychain, out of reach of the user's processes.
public struct KeychainStore: Sendable {
    public var service: String

    public init(service: String) { self.service = service }

    public func get(_ account: String) -> Data? {
        let q: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service,
                                  kSecAttrAccount: account, kSecReturnData: true, kSecMatchLimit: kSecMatchLimitOne]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    @discardableResult
    public func set(_ account: String, _ data: Data?) -> OSStatus {
        let q: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: account]
        guard let data else { return SecItemDelete(q as CFDictionary) }
        let status = SecItemUpdate(q as CFDictionary, [kSecValueData: data] as CFDictionary)
        if status != errSecItemNotFound { return status }
        var add = q
        add[kSecValueData] = data
        add[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return SecItemAdd(add as CFDictionary, nil)
    }
}
#endif
