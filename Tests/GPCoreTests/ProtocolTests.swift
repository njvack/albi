import Testing
@testable import GPCore

// Responses below are what gp-fake-gateway sends, plus shapes seen from real
// gateways in openconnect's tests and source comments.

@Suite struct XMLTests {
    @Test func parsesNestedElementsAndEntities() throws {
        let x = try #require(XMLElement.parse(#"<?xml version="1.0"?><a k='v &amp; w'><b>1 &lt; 2</b><b><![CDATA[<raw>]]></b><!-- c --><c/></a>"#))
        #expect(x.name == "a")
        #expect(x.attributes["k"] == "v & w")
        #expect(x.children("b").map(\.text) == ["1 < 2", "<raw>"])
        #expect(x.child("c") != nil)
    }

    @Test func recoversFromBadMarkup() throws {
        let x = try #require(XMLElement.parse("<response><a>1</b><c>2</response>"))
        // The stray </b> is skipped; <a> and <c> are closed by </response>.
        #expect(x.child("a")?.trimmedText == "12")
        #expect(x.child("a")?.value("c") == "2")
    }

    @Test func numericEntities() throws {
        #expect(XMLElement.parse("<a>&#x41;&#66;&bogus;</a>")?.text == "AB&bogus;")
    }

    @Test func notXML() {
        #expect(XMLElement.parse("var respStatus = \"Challenge\";") == nil)
    }
}

@Suite struct FormTests {
    @Test func encodesLikeOpenconnect() {
        let f: Form = ["a b": "x,y/z", "ok": "Login~.-_"]
        #expect(f.encoded == "a%20b=x%2cy%2fz&ok=Login~.-_")
    }

    @Test func roundTrips() {
        let f: Form = ["user": "nate@example.com", "passwd": "p&ss=wörd"]
        #expect(Form.parse(f.encoded) == f)
    }
}

@Suite struct MD5Tests {
    @Test func vectors() {
        #expect(MD5.hex("") == "d41d8cd98f00b204e9800998ecf8427e")
        #expect(MD5.hex("abc") == "900150983cd24fb0d6963f7d28e17f72")
        #expect(MD5.hex("The quick brown fox jumps over the lazy dog") == "9e107d9d372bb6826bd81d3542a419d6")
        #expect(MD5.hex(String(repeating: "a", count: 1000)) == "cabe45dcc9ae5b66ba86600cca6b8ba8")
    }
}

@Suite struct ReplyTests {
    @Test func challengeXML() throws {
        let r = try Reply.classify(status: 200, body: "<challenge><user>test</user><inputstr>abc123</inputstr><respmsg>Approve the push</respmsg></challenge>")
        #expect(r == .challenge(prompt: "Approve the push", inputStr: "abc123"))
    }

    @Test func challengeJavaScript() throws {
        let body = """
        var respStatus = "Challenge";
        var respMsg = "Enter \\"1\\" for a push";
        thisForm.inputStr.value = "5e7a";
        """
        #expect(try Reply.classify(status: 200, body: body) == .challenge(prompt: "Enter \"1\" for a push", inputStr: "5e7a"))
    }

    @Test func challengeInHTML() throws {
        let body = #"<html><head></head><body>var respStatus = "Challenge"; var respMsg = "Code"; thisForm.inputStr.value = "xyz";</body></html>"#
        #expect(try Reply.classify(status: 200, body: body) == .challenge(prompt: "Code", inputStr: "xyz"))
    }

    @Test func errors() {
        #expect(throws: GPError.badCredentials("Invalid username or password")) {
            try Reply.classify(status: 512, body: "")
        }
        #expect(throws: GPError.cookieRejected("Invalid authentication cookie")) {
            try Reply.classify(status: 200, body: #"<response status="error"><error>Invalid authentication cookie</error></response>"#)
        }
        #expect(throws: GPError.notFound("GlobalProtect portal does not exist")) {
            try Reply.classify(status: 200, body: "<prelogin-response><status>Error</status><msg>GlobalProtect portal does not exist</msg></prelogin-response>")
        }
        #expect(throws: GPError.http(500)) { try Reply.classify(status: 500, body: "") }
        #expect(throws: GPError.badCredentials("Authentication failed")) {
            try Reply.classify(status: 200, body: #"var respStatus = "Error"; var respMsg = "Authentication failed";"#)
        }
    }
}

let fakeLoginJNLP = """
<?xml version="1.0" encoding="utf-8"?><jnlp><application-desc><argument>(null)</argument><argument>c00k1e</argument><argument>PersistentCookie</argument><argument>fake-portal</argument><argument>test</argument><argument>Fake-Auth</argument><argument>vsys1</argument><argument>%28empty_domain%29</argument><argument>(null)</argument><argument></argument><argument></argument><argument></argument><argument>tunnel</argument><argument>-1</argument><argument>4100</argument><argument>10.99.0.2</argument><argument></argument><argument></argument><argument></argument></application-desc></jnlp>
"""

let fakeGetConfig = """
<response><need-tunnel>yes</need-tunnel><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><portal>fake-portal</portal><user>test</user><lifetime>86400</lifetime><timeout>3600</timeout><disconnect-on-idle>10800</disconnect-on-idle><bw-c2s>1000</bw-c2s><bw-s2c>1000</bw-s2c><ip-address>10.99.0.2</ip-address><netmask>255.255.255.255</netmask><ip-address-v6>fd99::2</ip-address-v6><dns><member>10.99.0.53</member></dns><dns-v6><member>10.99.0.53</member><member>fd99::53</member></dns-v6><dns-suffix><member>fake.test</member></dns-suffix><mtu>0</mtu><access-routes><member>10.99.0.0/24</member><member>10.98.0.5</member></access-routes><access-routes-v6><member>fd99::/64</member></access-routes-v6><exclude-access-routes><member>10.99.0.128/25</member><member>bogus</member></exclude-access-routes><gw-address>127.0.0.1</gw-address></response>
"""

@Suite struct ModelTests {
    @Test func loginCookie() throws {
        let doc = try Reply.document(status: 200, body: fakeLoginJNLP)
        let c = try AuthCookie(jnlp: doc, computer: "albi-test")
        #expect(c == AuthCookie(authcookie: "c00k1e", portal: "fake-portal", user: "test", domain: "(empty_domain)",
                                preferredIP: "10.99.0.2", computer: "albi-test"))
        #expect(c.form.encoded == "authcookie=c00k1e&portal=fake-portal&user=test&domain=%28empty_domain%29&preferred-ip=10.99.0.2&computer=albi-test")
    }

    @Test func hipTokenMatchesOpenconnect() {
        // build_csd_token: md5 of the cookie string minus authcookie and preferred-ip(v6).
        let c = AuthCookie(authcookie: "x", portal: "p", user: "u", domain: "d", preferredIP: "1.2.3.4", computer: "c")
        #expect(c.hipToken == MD5.hex("portal=p&user=u&domain=d&computer=c"))
    }

    @Test func gatewayConfig() throws {
        let c = try GatewayConfig(Reply.document(status: 200, body: fakeGetConfig))
        #expect(c.ipv4 == "10.99.0.2")
        #expect(c.ipv6 == "fd99::2")
        #expect(c.mtu == nil)
        #expect(c.lifetime == 86400)
        #expect(c.rekeyTimeout == 3600)
        #expect(c.idleTimeout == 10800)
        #expect(c.dns == ["10.99.0.53", "fd99::53"])
        #expect(c.dnsSuffixes == ["fake.test"])
        #expect(c.accessRoutes == ["10.99.0.0/24", "10.98.0.5", "fd99::/64"])
        #expect(c.excludeRoutes == ["10.99.0.128/25", "bogus"])
        #expect(c.esp == nil)
    }

    @Test func espConfig() throws {
        let body = """
        <response><ip-address>10.0.0.2</ip-address><ipsec><udp-port>4501</udp-port><ipsec-mode>esp-tunnel</ipsec-mode><enc-algo>aes-128-cbc</enc-algo><hmac-algo>sha1</hmac-algo><c2s-spi>0x1234abcd</c2s-spi><s2c-spi>0xdeadbeef</s2c-spi><akey-s2c><bits>160</bits><val>0102030405060708090a0b0c0d0e0f1011121314</val></akey-s2c><ekey-c2s><bits>128</bits><val>deadbeefdeadbeefdeadbeefdeadbee1</val></ekey-c2s></ipsec></response>
        """
        let esp = try #require(try GatewayConfig(Reply.document(status: 200, body: body)).esp)
        #expect(esp.udpPort == 4501)
        #expect(esp.c2sSPI == 0x1234abcd)
        #expect(esp.s2cSPI == 0xdeadbeef)
        #expect(esp.c2sEncKey.count == 16)
        #expect(esp.s2cAuthKey.count == 20)
    }

    @Test func portalConfig() throws {
        let body = """
        <?xml version="1.0" encoding="UTF-8" ?>
        <policy><version>6.2.8-1045</version><portal-userauthcookie>empty</portal-userauthcookie>
        <gateways><external><list>
        <entry name="gw2.example.com"><priority-rule><entry name="Any"><priority>2</priority></entry></priority-rule><description>Two</description></entry>
        <entry name="gw1.example.com"><priority-rule><entry name="Any"><priority>1</priority></entry></priority-rule><description>One</description></entry>
        </list></external></gateways>
        <hip-collection><hip-report-interval>3600</hip-report-interval></hip-collection>
        </policy>
        """
        let p = try PortalConfig(Reply.document(status: 200, body: body))
        #expect(p.version == "6.2.8-1045")
        #expect(p.userAuthCookie == nil)
        #expect(p.hipReportInterval == 3600)
        #expect(p.gateways.map(\.address) == ["gw2.example.com", "gw1.example.com"])
        #expect(Login.defaultGateway(p.gateways).address == "gw1.example.com")
    }
}

@Suite struct RequestTests {
    let client = ClientInfo(computer: "albi-test")
    let cookie = AuthCookie(authcookie: "c", portal: "p", user: "u", domain: "d", preferredIP: "10.0.0.2", computer: "albi-test")

    @Test func gatewayLogin() {
        let r = Requests.login(.gateway, client: client, server: "gw:8443", user: "test", password: "1", inputStr: "abc")
        #expect(r.path == "/ssl-vpn/login.esp")
        #expect(r.body.encoded == "jnlpReady=jnlpReady&ok=Login&direct=yes&clientVer=4100&prot=https%3a&internal=no&ipv6-support=yes&clientos=Mac&os-version=mac-intel&server=gw%3a8443&computer=albi-test&inputStr=abc&user=test&passwd=1")
    }

    @Test func getConfigReplacesPreferredIP() {
        let first = Requests.getConfig(cookie, client: client)
        #expect(first.body["preferred-ip"] == "10.0.0.2")
        let again = Requests.getConfig(cookie, client: client, previousIPv4: "10.0.0.9")
        #expect(again.body.fields.filter { $0.name == "preferred-ip" }.map(\.value) == ["10.0.0.9"])
        #expect(again.body["authcookie"] == "c")
    }

    @Test func hipCheck() throws {
        let r = Requests.hipReportCheck(cookie, clientIPv4: "10.0.0.2", clientIPv6: nil)
        #expect(r.body.encoded.hasPrefix("client-role=global-protect-full&authcookie=c&"))
        #expect(r.body["md5"] == cookie.hipToken)
        #expect(try Requests.hipReportNeeded(XMLElement.parse("<response><hip-report-needed>yes</hip-report-needed></response>")!))
    }

    @Test func tunnelRequest() {
        #expect(String(decoding: GPST.tunnelRequest(path: "/ssl-tunnel-connect.sslvpn", cookie: cookie), as: UTF8.self)
            == "GET /ssl-tunnel-connect.sslvpn?authcookie=c&user=u HTTP/1.1\r\n\r\n")
    }
}

@Suite struct GPSTTests {
    @Test func encodeDecode() throws {
        let v4: [UInt8] = [0x45, 0, 0, 20] + [UInt8](repeating: 7, count: 16)
        let v6: [UInt8] = [0x60] + [UInt8](repeating: 1, count: 39)
        let wire = GPST.encode(packet: v4) + GPST.keepaliveFrame + GPST.encode(packet: v6)
        #expect(Array(GPST.encode(packet: v4)[0..<16]) == [0x1a, 0x2b, 0x3c, 0x4d, 0x08, 0x00, 0, 20, 1, 0, 0, 0, 0, 0, 0, 0])
        #expect(Array(GPST.encode(packet: v6)[4..<6]) == [0x86, 0xDD])

        // Feed one byte at a time to check partial frames.
        var d = GPST.Decoder()
        var frames: [GPST.Frame] = []
        for b in wire {
            d.append([b])
            while let f = try d.next() { frames.append(f) }
        }
        #expect(frames == [.packet(v4), .keepalive, .packet(v6)])
    }

    @Test func badMagic() {
        var d = GPST.Decoder()
        d.append([UInt8](repeating: 0, count: 16))
        #expect(throws: GPST.DecodeError.badMagic) { try d.next() }
    }

    @Test func handshake() {
        var h = GPST.Handshake()
        #expect(h.feed(Array("START_".utf8)) == nil)
        #expect(h.feed(Array("TUNNEL".utf8) + [0x1a]) == .started(leftover: [0x1a]))

        var r = GPST.Handshake()
        #expect(r.feed(Array("HTTP/1.1 502 Bad Gateway\r\n\r\n".utf8)) == .rejected(.cookieRejected("tunnel request got HTTP 502")))
        var e = GPST.Handshake()
        #expect(e.feed(Array("HTTP/1.1 404 Not Found\r\n".utf8)) == .rejected(.http(404)))
    }
}

@Suite struct TunnelSettingsTests {
    @Test func splitTunnel() throws {
        let c = try GatewayConfig(Reply.document(status: 200, body: fakeGetConfig))
        let s = TunnelSettings(config: c, remoteAddress: "gw.example.com")
        #expect(s.ipv4Address == "10.99.0.2")
        #expect(s.ipv4Mask == "255.255.255.255")
        #expect(s.ipv6Address == "fd99::2")
        #expect(s.ipv6PrefixLength == 128)
        #expect(!s.isFullTunnel)
        #expect(s.includedIPv4 == [
            .init(address: "10.99.0.0", mask: "255.255.255.0", prefixLength: 24),
            .init(address: "10.98.0.5", mask: "255.255.255.255", prefixLength: 32),
        ])
        #expect(s.excludedIPv4 == [.init(address: "10.99.0.128", mask: "255.255.255.128", prefixLength: 25)])
        #expect(s.includedIPv6 == [.init(address: "fd99::", prefixLength: 64)])
        #expect(s.ignoredRoutes == ["bogus"])
        #expect(s.matchDomains == ["fake.test"])
        #expect(s.searchDomains == ["fake.test"])
        #expect(s.mtu == TunnelSettings.defaultMTU)
    }

    @Test func fullTunnel() throws {
        let body = "<response><ip-address>10.0.0.2</ip-address><mtu>1350</mtu><dns><member>10.0.0.53</member></dns><dns-suffix><member>corp.example</member></dns-suffix></response>"
        let s = TunnelSettings(config: try GatewayConfig(Reply.document(status: 200, body: body)), remoteAddress: "gw")
        #expect(s.isFullTunnel)
        #expect(s.includedIPv4 == [.default])
        #expect(s.includedIPv6.isEmpty)
        #expect(s.matchDomains == nil)
        #expect(s.mtu == 1350)
    }

    @Test func explicitDefaultRouteIsFull() throws {
        let body = "<response><ip-address>10.0.0.2</ip-address><access-routes><member>0.0.0.0/0</member><member>10.1.0.0/16</member></access-routes></response>"
        let s = TunnelSettings(config: try GatewayConfig(Reply.document(status: 200, body: body)), remoteAddress: "gw")
        #expect(s.includedIPv4 == [.default])
    }

    @Test func routeParsing() {
        #expect(TunnelSettings.parseIPv4Route("10.1.2.3/8") == .init(address: "10.0.0.0", mask: "255.0.0.0", prefixLength: 8))
        #expect(TunnelSettings.parseIPv4Route("10.1.2.0/255.255.255.0")?.prefixLength == 24)
        #expect(TunnelSettings.parseIPv4Route("10.1.2.0/255.0.255.0") == nil)
        #expect(TunnelSettings.parseIPv4Route("10.1.2.300") == nil)
        #expect(TunnelSettings.parseIPv6Route("2001:db8::/32") == .init(address: "2001:db8::", prefixLength: 32))
        #expect(TunnelSettings.parseIPv6Route("2001:db8::/129") == nil)
    }

    @Test func hostOnlyStripsPort() {
        #expect(hostOnly("gw.example.com:8443") == "gw.example.com")
        #expect(hostOnly("[::1]:8443") == "::1")
        #expect(hostOnly("gw") == "gw")
    }
}

@Suite struct PingTests {
    @Test func requestIsValid() throws {
        let p = try #require(Ping.request(from: "10.99.0.2", to: "10.99.0.1", id: 0x1234, sequence: 7))
        #expect(p.count == 32)
        #expect(Ping.checksum(Array(p[0..<20])) == 0)
        #expect(Ping.checksum(Array(p[20...])) == 0)
        #expect(Array(p[12..<20]) == [10, 99, 0, 2, 10, 99, 0, 1])
    }

    @Test func parsesReply() throws {
        var p = try #require(Ping.request(from: "10.99.0.1", to: "10.99.0.2", id: 9, sequence: 3))
        p[20] = 0 // echo reply
        #expect(Ping.reply(p, to: "10.99.0.2")! == (9, 3))
        #expect(Ping.reply(p, to: "10.99.0.3") == nil)
    }
}
