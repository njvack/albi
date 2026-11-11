import Foundation
import Testing
@testable import GPCapture
@testable import GPCore

/// Builds openconnect `-v --timestamp --dump-http-traffic` output.
struct LogBuilder {
    var lines: [String] = []
    var t = 0

    mutating func ts() -> String {
        t += 1
        return String(format: "[2026-11-11 09:%02d:%02d] ", t / 60, t % 60)
    }

    mutating func event(_ s: String) { lines.append(ts() + s) }
    mutating func bare(_ s: String) { lines.append(s) }

    mutating func exchange(_ target: String, method: String = "POST", host: String, body: String = "",
                           status: String = "HTTP/1.1 200 OK", headers: [String] = [], response: String?) {
        event("\(method) https://\(host)\(target.split(separator: "?").first!)")
        for l in ["\(method) \(target) HTTP/1.1", "Host: \(host)", "User-Agent: PAN GlobalProtect",
                  "Content-Type: application/x-www-form-urlencoded", "Content-Length: \(body.utf8.count)", ""] {
            lines.append(ts() + "> " + l)
        }
        if !body.isEmpty { lines.append(ts() + "> " + body) }
        guard let response else { return }
        event("Got HTTP response: \(status)")
        event("Content-Type: application/xml; charset=UTF-8")
        for h in headers { event(h) }
        event("HTTP body length:  (\(response.utf8.count))")
        for l in response.split(separator: "\n", omittingEmptySubsequences: false) { lines.append(ts() + "< " + l) }
    }

    var text: String { lines.joined(separator: "\n") + "\n" }
}

let portalHost = "vpn.acme-u.edu"
let gatewayHost = "gw-east.vpn.acme-u.edu"
let cookie = "4f2a9c1e8b7d6a5f4e3d2c1b0a998877"
let persistent = "0123456789abcdef0123456789abcdef01234567"
let portalCookie = "c3VwZXJzZWNyZXRwb3J0YWxjb29raWU="
let inputStr = "9a8b7c6d5e4f3a2b"
let encKey = "00112233445566778899aabbccddeeff"
let authKey = "ffeeddccbbaa99887766554433221100aabbccdd"
let password = "Hunter2-correct-horse"

let portalConfig = """
<?xml version="1.0" encoding="UTF-8" ?>
<policy><portal-name>ACME-Portal</portal-name><version>6.2.8-1045</version>
<portal-userauthcookie>\(portalCookie)</portal-userauthcookie>
<user-email>jdoe@acme-u.edu</user-email>
<root-ca><entry name="ACME Root"><cert>-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUQ2k
-----END CERTIFICATE-----</cert></entry></root-ca>
<gateways><external><list>
<entry name="\(gatewayHost)"><priority-rule><entry name="Any"><priority>1</priority></entry></priority-rule><description>ACME East</description></entry>
<entry name="gw-west.vpn.acme-u.edu"><description>ACME West</description></entry>
</list></external></gateways>
<hip-collection><hip-report-interval>3600</hip-report-interval></hip-collection>
<welcome-page><page>Questions? Call the ACME-U help desk at 608-555-1234 or see https://it.acme-u.edu/vpn</page></welcome-page>
</policy>
"""

let jnlp = """
<?xml version="1.0" encoding="utf-8"?><jnlp><application-desc><argument>(null)</argument><argument>\(cookie)</argument><argument>\(persistent)</argument><argument>ACME-Portal</argument><argument>jdoe</argument><argument>ACME-LDAP</argument><argument>vsys1</argument><argument>ACMEDOM</argument><argument>(null)</argument><argument></argument><argument></argument><argument></argument><argument>tunnel</argument><argument>-1</argument><argument>4100</argument><argument>10.140.7.23</argument><argument></argument><argument></argument><argument>2607:f388:1000:7::23</argument><argument>4</argument><argument>unknown</argument></application-desc></jnlp>
"""

let gatewayConfig = """
<response><need-tunnel>yes</need-tunnel><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><portal>ACME-Portal</portal><user>jdoe</user><lifetime>43200</lifetime><timeout>7200</timeout><disconnect-on-idle>3600</disconnect-on-idle><ip-address>10.140.7.23</ip-address><netmask>255.255.255.255</netmask><ip-address-v6>2607:f388:1000:7::23</ip-address-v6><dns><member>10.140.0.53</member><member>128.104.254.254</member></dns><dns-suffix><member>ad.acme-u.edu</member><member>acme-u.edu</member></dns-suffix><mtu>0</mtu><access-routes><member>10.140.0.0/16</member><member>128.104.0.0/16</member><member>144.92.0.0/16</member></access-routes><access-routes-v6><member>2607:f388::/32</member></access-routes-v6><exclude-access-routes><member>128.104.30.0/24</member></exclude-access-routes><gw-address>128.104.30.40</gw-address><ipsec><udp-port>4501</udp-port><ipsec-mode>esp-tunnel</ipsec-mode><enc-algo>aes-128-cbc</enc-algo><hmac-algo>sha1</hmac-algo><c2s-spi>0x8E3A12F4</c2s-spi><s2c-spi>0x1B2C3D4E</s2c-spi><akey-s2c><bits>160</bits><val>\(authKey)</val></akey-s2c><ekey-s2c><bits>128</bits><val>\(encKey)</val></ekey-s2c><akey-c2s><bits>160</bits><val>\(authKey)</val></akey-c2s><ekey-c2s><bits>128</bits><val>\(encKey)</val></ekey-c2s></ipsec></response>
"""

let hipReport = """
<?xml version="1.0" encoding="UTF-8"?>
<hip-report>
  <md5-sum>d41d8cd98f00b204e9800998ecf8427e</md5-sum>
  <user-name>jdoe</user-name>
  <domain>ACMEDOM</domain>
  <host-name>jdoes-mbp</host-name>
  <host-id>a4:83:e7:12:34:56</host-id>
  <ip-address>10.140.7.23</ip-address>
  <categories><entry name="host-info">
    <serial-number>C02XK1ZZJG5H</serial-number>
    <network-interface><entry name="en0"><description>en0</description><mac-address>a4:83:e7:12:34:56</mac-address>
    <ip-address><entry name="192.168.86.31"/></ip-address></entry></network-interface>
  </entry></categories>
</hip-report>
"""

func sampleLog() -> String {
    var b = LogBuilder()
    b.event("OpenConnect version v9.12")
    let form = "jnlpReady=jnlpReady&ok=Login&direct=yes&clientVer=4100&prot=https:&internal=no&ipv6-support=yes&clientos=Mac&os-version=mac-intel&server=\(portalHost)&computer=jdoes-mbp"
    b.exchange("/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac", host: portalHost, body: "cas-support=yes",
               response: "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<prelogin-response>\n<status>Success</status>\n<username-label>ACME NetID</username-label>\n<password-label>Password</password-label>\n<panos-version>1</panos-version>\n</prelogin-response>")
    b.exchange("/global-protect/getconfig.esp", host: portalHost,
               body: form + "&user=jdoe&passwd=" + Form.escape(password),
               headers: ["Set-Cookie: PHPSESSID=7d1f00aa77bb; path=/"], response: portalConfig)
    b.event("  ACME East (\(gatewayHost)) [priority 1]")
    b.exchange("/ssl-vpn/login.esp", host: gatewayHost,
               body: form.replacingOccurrences(of: portalHost, with: gatewayHost) + "&portal-userauthcookie=" + Form.escape(portalCookie) + "&user=jdoe&passwd=" + Form.escape(password),
               response: "<challenge><user>jdoe</user><inputstr>\(inputStr)</inputstr><respmsg>Duo Push to XXX-XXX-4321</respmsg></challenge>")
    b.bare("Challenge: ")
    b.exchange("/ssl-vpn/login.esp", host: gatewayHost,
               body: form + "&inputStr=\(inputStr)&user=jdoe&passwd=1", response: jnlp)
    b.event("GlobalProtect login returned authentication-source=ACME-LDAP")
    let auth = "authcookie=\(cookie)&portal=ACME-Portal&user=jdoe&domain=ACMEDOM&preferred-ip=10.140.7.23&preferred-ipv6=2607%3af388%3a1000%3a7%3a%3a23&computer=jdoes-mbp"
    b.exchange("/ssl-vpn/getconfig.esp", host: gatewayHost, body: "client-type=1&protocol-version=p1&" + auth, response: gatewayConfig)
    b.event("ESP encryption type AES-128-CBC (RFC3602) key 0x\(encKey)")
    b.exchange("/ssl-vpn/hipreportcheck.esp", host: gatewayHost,
               body: "client-role=global-protect-full&" + auth + "&client-ip=10.140.7.23&md5=d41d8cd98f00b204e9800998ecf8427e",
               response: "<response status=\"success\"><hip-report-needed>yes</hip-report-needed></response>")
    b.exchange("/ssl-vpn/hipreport.esp", host: gatewayHost,
               body: "client-role=global-protect-full&" + auth + "&client-ip=10.140.7.23&report=" + Form.escape(hipReport),
               response: "<response status=\"success\"/>")
    b.lines.append(b.ts() + "> GET /ssl-tunnel-connect.sslvpn?authcookie=\(cookie)&user=jdoe HTTP/1.1")
    b.lines.append(b.ts() + "> ")
    b.event("ESP session to 128.104.30.40 port 4501 established")
    b.event("ESP session established with server")
    b.event("Configured as 10.140.7.23 + 2607:f388:1000:7::23, with SSL connected and ESP established")
    b.exchange("/ssl-vpn/logout.esp", host: gatewayHost, body: auth, response: "<response status=\"success\"/>")
    b.event("User cancelled (SIGINT/SIGTERM); exiting.")
    return b.text
}

@Suite struct LogTests {
    @Test func splitsExchanges() {
        let log = CaptureLog(parsing: sampleLog())
        #expect(log.exchanges.map(\.label) == [
            "portal-prelogin", "portal-getconfig", "gateway-login", "gateway-login", "gateway-getconfig",
            "gateway-hipreportcheck", "gateway-hipreport", "tunnel-connect", "gateway-logout",
        ])
        let pre = log.exchanges[0]
        #expect(pre.host == portalHost)
        #expect(pre.requestBody == "cas-support=yes")
        #expect(pre.status == 200)
        #expect(pre.responseBody?.hasPrefix("<?xml") == true)
        #expect(pre.responseBody?.hasSuffix("</prelogin-response>") == true)
        #expect(log.exchanges[1].responseHeaders.contains { $0.name == "Set-Cookie" })
        #expect(log.exchanges[7].responseBody == nil)
        #expect(log.events.contains { $0.text == "Challenge: " && $0.after == 2 })
        #expect(!log.events.contains { $0.text.hasPrefix(">") || $0.text.hasPrefix("<") })
    }

    @Test func skipsHexDumps() {
        let log = CaptureLog(parsing: "[2026-11-11 09:00:01] < 0000:  01 02 03 04  |....|\nhello\n")
        #expect(log.exchanges.isEmpty)
        #expect(log.events.map(\.text) == ["hello"])
    }
}

@Suite struct RedactionTests {
    let fx = FixtureSet(log: CaptureLog(parsing: sampleLog()), redactor: Redactor(password: password, words: ["Acme"]))

    func file(_ suffix: String) -> String {
        fx.files.first { $0.name.hasSuffix(suffix) }!.contents
    }

    var everything: String { fx.files.map(\.contents).joined(separator: "\n") }

    @Test func nothingIdentifyingRemains() {
        let all = everything
        let decoded = Form.unescape(all)
        for secret in [cookie, persistent, portalCookie, inputStr, encKey, authKey, password, "jdoe", "acme", "ACME",
                       "10.140", "128.104", "144.92", "2607:f388", "192.168.86.31", "a4:83:e7", "C02XK1ZZJG5H",
                       "d41d8cd98f00b204e9800998ecf8427e", "MIIBszCC", "608-555-1234", "4321", "8E3A12F4", "7d1f00aa77bb"] {
            #expect(!all.contains(secret), "\(secret) left in fixtures")
            #expect(!decoded.contains(secret), "\(secret) left in decoded fixtures")
        }
        #expect(fx.leaks.isEmpty, "\(fx.leaks)")
    }

    @Test func passwordFieldsAreReplaced() {
        let login = fx.files.first { $0.name == "03-gateway-login.request.form" }!.contents
        #expect(login.contains("passwd=REDACTED"))
        let challenge = fx.files.first { $0.name == "04-gateway-login.request.form" }!.contents
        #expect(challenge.contains("passwd=REDACTED"))
    }

    @Test func fixturesStillParse() throws {
        let jnlpDoc = try #require(XMLElement.parse(file("04-gateway-login.response.xml")))
        let c = try AuthCookie(jnlp: jnlpDoc, computer: "x")
        #expect(c.authcookie.count == cookie.count && c.authcookie.allSatisfy(\.isHexDigit))
        #expect(c.user == "user1")

        let portal = try PortalConfig(#require(XMLElement.parse(file("02-portal-getconfig.response.xml"))))
        #expect(portal.gateways.map(\.address) == ["host2.example.test", "host3.example.test"])
        #expect(portal.gateways.map(\.description) == ["Gateway 1", "Gateway 2"])
        #expect(portal.userAuthCookie != nil && portal.userAuthCookie != portalCookie)

        let gc = try GatewayConfig(#require(XMLElement.parse(file("05-gateway-getconfig.response.xml"))))
        #expect(gc.lifetime == 43200 && gc.rekeyTimeout == 7200 && gc.idleTimeout == 3600)
        #expect(gc.dnsSuffixes == ["example.test", "example2.test"] || gc.dnsSuffixes == ["example2.test", "example.test"])
        let esp = try #require(gc.esp)
        #expect(esp.c2sEncKey.count == 16 && esp.c2sAuthKey.count == 20)
        #expect(esp.c2sSPI != nil && esp.c2sSPI != 0x8E3A12F4)
    }

    @Test func addressesKeepTheirSubnets() throws {
        let gc = try GatewayConfig(#require(XMLElement.parse(file("05-gateway-getconfig.response.xml"))))
        let ip = try #require(gc.ipv4)
        #expect(ip.hasPrefix("10."))
        // The client address is still inside the first access route.
        let route = gc.accessRoutes[0]
        #expect(route.hasSuffix(".0.0/16"))
        #expect(ip.split(separator: ".").prefix(2) == route.split(separator: ".").prefix(2))
        // Public networks stay distinct and move to 198.18.0.0/15 and up.
        #expect(gc.accessRoutes[1].hasPrefix("198.") && gc.accessRoutes[2].hasPrefix("198."))
        #expect(gc.accessRoutes[1] != gc.accessRoutes[2])
        // The excluded subnet and the gateway stay inside their /16.
        let gwNet = gc.accessRoutes[1].split(separator: ".").prefix(2)
        #expect(gc.excludeRoutes[0].split(separator: ".").prefix(2) == gwNet)
        #expect(gc.gatewayAddress?.split(separator: ".").prefix(3) == gc.excludeRoutes[0].split(separator: ".").prefix(3))
        #expect(gc.netmask == "255.255.255.255")
        let v6 = try #require(gc.ipv6)
        #expect(v6.hasPrefix("2001:db8:"))
        #expect(gc.accessRoutes.contains("2001:db8::/32"))
    }

    @Test func sameValueSameFakeEverywhere() {
        let fakeCookie = Form.parse(file("05-gateway-getconfig.request.form"))["authcookie"]!
        #expect(file("index.tsv").contains("authcookie=\(fakeCookie)"))
        #expect(file("09-gateway-logout.request.form").contains(fakeCookie))
        let report = Form.unescape(Form.parse(file("07-gateway-hipreport.request.form"))["report"]!)
        #expect(report.contains("<user-name>user1</user-name>"))
        #expect(report.contains("<host-name>computer1</host-name>"))
        // host-id and the interface MAC are the same address, so they stay equal.
        let mac = XMLElement.parse(report)!.value("host-id")!
        #expect(report.contains("<mac-address>\(mac)</mac-address>"))
        #expect(mac.hasPrefix("02:00:00"))
    }

    @Test func summaryHasTheTimers() {
        let s = file("summary.txt")
        #expect(s.contains("lifetime: 43200 s (12 h)"))
        #expect(s.contains("timeout (rekey): 7200 s (2 h)"))
        #expect(s.contains("disconnect-on-idle: 3600 s (1 h)"))
        #expect(s.contains("ESP: established"))
        #expect(s.contains("ESP offered: yes, aes-128-cbc / sha1, UDP port 4501"))
        #expect(s.contains("hip-report-needed: yes"))
        #expect(s.contains("gateways offered: 2"))
    }

    @Test func leakCheckCatchesWhatItLearned() {
        var r = fx.redactor
        _ = r.redact("x")
        #expect(!r.leaks(in: "user=jdoe").isEmpty)
        #expect(!r.leaks(in: "report=%3cuser-name%3ejdoe%3c").isEmpty)
        #expect(!r.leaks(in: "x \(cookie) y").isEmpty)
        #expect(r.leaks(in: "user=user1").isEmpty)
    }
}

@Suite struct AddressMapTests {
    @Test func ipv4KeepsSpecialAddresses() {
        var m = IPv4Map()
        #expect(m.map("0.0.0.0") == "0.0.0.0")
        #expect(m.map("127.0.0.1") == "127.0.0.1")
        #expect(m.map("255.255.240.0") == "255.255.240.0")
        #expect(m.map("172.20.1.5").hasPrefix("172.16."))
        #expect(m.map("192.168.4.9").hasPrefix("192.168."))
        #expect(m.map("8.8.8.8") == "198.18.1.1")
        #expect(m.map("8.8.4.4") == "198.18.2.1")
        #expect(m.map("1.1.1.1") == "198.19.1.1")
    }

    @Test func ipv6RoundTrips() {
        #expect(IPv6Map.parse("2001:db8::1") == [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])
        #expect(IPv6Map.format([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]) == "2001:db8::1")
        #expect(IPv6Map.parse("12:36:14") == nil)
        #expect(IPv6Map.parse("a4:83:e7:12:34:56") == nil)
        var m = IPv6Map()
        #expect(m.map("fe80::1c2b:3a4d:5e6f:7081")?.hasPrefix("fe80::") == true)
    }
}
