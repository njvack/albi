#if canImport(Security) && canImport(CryptoKit)
import CryptoKit
import Foundation
import Security

/// How to decide whether to trust the gateway's certificate.
public enum TrustPolicy: Equatable, Sendable {
    /// The system trust store, with the host name checked.
    case system
    /// Only certificates whose public key matches one of these openconnect
    /// style pins (`pin-sha256:BASE64`, SHA-256 of the SubjectPublicKeyInfo).
    case pinned([String])

    public func evaluate(_ trust: SecTrust, host: String) -> Bool {
        switch self {
        case .system:
            SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString))
            var error: CFError?
            return SecTrustEvaluateWithError(trust, &error)
        case .pinned(let pins):
            guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                  let leaf = chain.first, let pin = spkiPin(leaf) else { return false }
            return pins.contains(pin)
        }
    }
}

/// The openconnect-style pin for a certificate: `pin-sha256:` and the
/// base64 SHA-256 of its DER SubjectPublicKeyInfo.
public func spkiPin(_ cert: SecCertificate) -> String? {
    guard let key = SecCertificateCopyKey(cert), let der = spkiDER(key) else { return nil }
    return "pin-sha256:" + Data(SHA256.hash(data: der)).base64EncodedString()
}

/// Rebuilds the SubjectPublicKeyInfo, since Security only exports the bare key.
func spkiDER(_ key: SecKey) -> Data? {
    guard let attrs = SecKeyCopyAttributes(key) as? [CFString: Any],
          let raw = SecKeyCopyExternalRepresentation(key, nil) as Data? else { return nil }
    let type = attrs[kSecAttrKeyType] as? String
    let bits = attrs[kSecAttrKeySizeInBits] as? Int
    if type == (kSecAttrKeyTypeECSECPrimeRandom as String) {
        // AlgorithmIdentifier { id-ecPublicKey, named curve }
        let curve: [UInt8]
        switch bits {
        case 256: curve = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
        case 384: curve = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]
        case 521: curve = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]
        default: return nil
        }
        let alg = der(0x30, [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01] + curve)
        return Data(der(0x30, alg + der(0x03, [0] + [UInt8](raw))))
    }
    if type == (kSecAttrKeyTypeRSA as String) {
        // AlgorithmIdentifier { rsaEncryption, NULL }; raw is PKCS#1 RSAPublicKey.
        let alg = der(0x30, [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00])
        return Data(der(0x30, alg + der(0x03, [0] + [UInt8](raw))))
    }
    return nil
}

func der(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
    let n = content.count
    var len: [UInt8]
    if n < 0x80 {
        len = [UInt8(n)]
    } else {
        var b: [UInt8] = []
        var v = n
        while v > 0 { b.insert(UInt8(v & 0xff), at: 0); v >>= 8 }
        len = [0x80 | UInt8(b.count)] + b
    }
    return [tag] + len + content
}
#endif
