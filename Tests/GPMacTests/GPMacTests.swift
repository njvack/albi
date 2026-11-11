import Testing
@testable import GPCore
#if canImport(NetworkExtension)
@testable import GPMac
import NetworkExtension
import Security

@Suite struct NetworkSettingsTests {
    @Test func splitTunnelMapsToNESettings() throws {
        let body = "<response><ip-address>10.99.0.2</ip-address><netmask>255.255.255.255</netmask><ip-address-v6>fd99::2</ip-address-v6><mtu>1300</mtu><dns><member>10.99.0.53</member></dns><dns-suffix><member>fake.test</member></dns-suffix><access-routes><member>10.99.0.0/24</member></access-routes><access-routes-v6><member>fd99::/64</member></access-routes-v6><exclude-access-routes><member>10.99.0.128/25</member></exclude-access-routes><gw-address>192.0.2.1</gw-address></response>"
        let c = try GatewayConfig(Reply.document(status: 200, body: body))
        let s = TunnelSettings(config: c, remoteAddress: c.gatewayAddress!).networkSettings()
        #expect(s.tunnelRemoteAddress == "192.0.2.1")
        #expect(s.ipv4Settings?.addresses == ["10.99.0.2"])
        #expect(s.ipv4Settings?.subnetMasks == ["255.255.255.255"])
        #expect(s.ipv4Settings?.includedRoutes?.map(\.destinationAddress) == ["10.99.0.0"])
        #expect(s.ipv4Settings?.includedRoutes?.map(\.destinationSubnetMask) == ["255.255.255.0"])
        #expect(s.ipv4Settings?.excludedRoutes?.map(\.destinationSubnetMask) == ["255.255.255.128"])
        #expect(s.ipv6Settings?.addresses == ["fd99::2"])
        #expect(s.ipv6Settings?.includedRoutes?.map(\.destinationNetworkPrefixLength) == [64])
        #expect(s.dnsSettings?.servers == ["10.99.0.53"])
        #expect(s.dnsSettings?.matchDomains == ["fake.test"])
        #expect(s.mtu == 1300)
    }

    @Test func fullTunnelUsesDefaultRoute() throws {
        let c = try GatewayConfig(Reply.document(status: 200, body: "<response><ip-address>10.0.0.2</ip-address><dns><member>10.0.0.53</member></dns></response>"))
        let s = TunnelSettings(config: c, remoteAddress: "gw").networkSettings()
        let r = try #require(s.ipv4Settings?.includedRoutes?.first)
        #expect(r.destinationAddress == NEIPv4Route.default().destinationAddress)
        #expect(r.destinationSubnetMask == "0.0.0.0")
        #expect(s.dnsSettings?.matchDomains == nil)
    }
}

@Suite struct TrustTests {
    @Test func hostPort() {
        #expect(splitHostPort("gw.example.com") == ("gw.example.com", 443))
        #expect(splitHostPort("127.0.0.1:8443") == ("127.0.0.1", 8443))
        #expect(splitHostPort("[::1]:8443") == ("::1", 8443))
    }

    @Test func derLength() {
        #expect(der(0x04, [1, 2]) == [0x04, 2, 1, 2])
        #expect(Array(der(0x04, [UInt8](repeating: 0, count: 300)).prefix(4)) == [0x04, 0x82, 0x01, 0x2c])
    }

    @Test func ecSPKIMatchesKnownLayout() throws {
        // A P-256 key's SPKI is the fixed 26-byte prefix plus the 65-byte point.
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256]
        var err: Unmanaged<CFError>?
        let priv = try #require(SecKeyCreateRandomKey(attrs as CFDictionary, &err))
        let pub = try #require(SecKeyCopyPublicKey(priv))
        let spki = try #require(spkiDER(pub))
        #expect(spki.count == 91)
        #expect([UInt8](spki.prefix(4)) == [0x30, 0x59, 0x30, 0x13])
    }
}
#endif

#if canImport(NetworkExtension)
import Foundation

@Suite struct BundledHIPTests {
    func script(_ body: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("bundledhip-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("hipreport")
        try ("#!/bin/sh\n" + body + "\n").write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        return url
    }

    @Test func probeRunsTheHelperWithACleanEnvironment() async throws {
        let url = try script(#"echo "<hip-report>$*</hip-report>"; echo "path=$PATH home=${HOME:-none}" >&2"#)
        let p = await BundledHIP(executable: url).probe()
        #expect(p.launchError == nil)
        #expect(p.exitStatus == 0)
        #expect(p.stdoutHead?.contains("--md5 probe") == true)
        #expect(p.stderrHead?.contains("home=none") == true)
        #expect(p.summary.hasPrefix("exit 0"))
    }

    @Test func probeReportsAMissingHelper() async {
        let p = await BundledHIP(executable: nil).probe()
        #expect(p.path == nil)
        #expect(p.summary == "no hipreport in the extension's bundle")
    }

    @Test func probeReportsALaunchFailure() async {
        let p = await BundledHIP(executable: URL(fileURLWithPath: "/nonexistent/hipreport")).probe()
        #expect(p.launchError != nil)
    }

    @Test func failingHelperReportsItsStatus() async throws {
        let url = try script("echo broken >&2; exit 3")
        let out = try await BundledHIP(executable: url).run([])
        #expect(out.status == 3)
        #expect(String(decoding: out.stderr, as: UTF8.self) == "broken\n")
    }

    @Test func slowHelperTimesOut() async throws {
        let url = try script("sleep 5")
        await #expect(throws: BundledHIP.Failure.self) {
            _ = try await BundledHIP(executable: url, timeout: 0.3).run([])
        }
    }

    @Test func largeOutputDoesNotBlock() async throws {
        let url = try script("head -c 300000 /dev/zero | tr '\\0' x")
        let out = try await BundledHIP(executable: url).run([])
        #expect(out.status == 0)
        #expect(out.stdout.count == 300000)
    }
}
#endif
