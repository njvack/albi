import Foundation
import Testing
@testable import HIPCore

@Suite struct ReportTests {
    @Test func goldenMacBasic() throws {
        let f = try FakeSystem.load(fixture: macBasic)
        let (set, errs) = loadChecks(f, [.builtin])
        #expect(errs.isEmpty)
        var req = Request()
        req.md5 = "0123456789abcdef0123456789abcdef"
        req.cookie = "authcookie=abc&portal=vpn&user=nate&domain=AD+Domain%21&preferred-ip=&computer=nates-mbp"
        req.clientIP = "10.99.0.2"
        req.clientOS = "Mac"
        let got = collect(Env(f), set, req).xml.document
        let goldenPath = fixtures.appendingPathComponent("mac-basic.golden.xml")
        if ProcessInfo.processInfo.environment["UPDATE_GOLDEN"] == "1" {
            try got.write(to: goldenPath, atomically: true, encoding: .utf8)
        }
        let want = try String(contentsOf: goldenPath, encoding: .utf8)
        #expect(got == want, "report differs from mac-basic.golden.xml (UPDATE_GOLDEN=1 swift test to accept)")
    }

    @Test func xmlEscaping() {
        let n = Node("r", [Node("e", attrs: [("name", "a\"b<c>&'d\n")], text: "x<y>&\"z'\u{01}")])
        #expect(n.document == """
            <?xml version="1.0" encoding="UTF-8"?>
            <r>
              <e name="a&quot;b&lt;c&gt;&amp;'d&#10;">x&lt;y&gt;&amp;"z'</e>
            </r>

            """)
    }

    @Test func cookie() {
        let m = parseCookie("user=a%40b.edu&domain=My+Domain&computer=x&user=second&bad=%zz")
        #expect(m["user"] == "a@b.edu")
        #expect(m["domain"] == "My Domain")
        #expect(m["computer"] == "x")
        #expect(m["bad"] == "%zz")
    }

    @Test func fallbacks() {
        var req = Request()
        req.userName = "localuser"
        let facts = collect(Env(FakeSystem(host: "box.example.edu")), CheckSet(), req)
        #expect(facts.userName == "localuser")
        #expect(facts.computer == "box")
        #expect(facts.hostName == "box")
        #expect(facts.clientVersion == defaultClientVersion)
        #expect(facts.xml.document.contains(#"<entry name="data-loss-prevention">"#))
    }
}

@Suite struct PolicyTests {
    static let products: [Product] = [
        Product(id: "", source: "", trusted: true, category: "anti-malware", vendor: "Apple Inc.", name: "Xprotect",
                fields: ["version": Value("5329", how: "bundle_version /x"), "real-time-protection": Value("yes", how: "value")]),
        Product(id: "", source: "", trusted: true, category: "firewall", vendor: "Apple Inc.", name: "Mac OS X Builtin Firewall",
                fields: ["is-enabled": Value("no", how: "command /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate")]),
        Product(id: "", source: "", trusted: true, category: "firewall", vendor: "OpenBSD", name: "Packet Filter",
                fields: ["is-enabled": Value("n/a", how: "privileged pf.enabled", error: "needs root")]),
        Product(id: "", source: "", trusted: true, category: "disk-encryption", vendor: "Apple Inc.", name: "FileVault",
                fields: ["drives": Value("", how: "volumes", drives: [Drive(name: "Data", state: "encrypted"), Drive(name: "All", state: "unencrypted")])]),
    ]

    @Test func evaluates() throws {
        let p = try Policy.parse("""
            [[require]]
            category = "anti-malware"
            field = "real-time-protection"
            equals = "yes"

            [[require]]
            category = "anti-malware"
            name = "Xprotect"
            field = "version"
            min_version = "5300"

            [[require]]
            description = "some firewall is on"
            category = "firewall"
            field = "is-enabled"
            equals = "yes"

            [[require]]
            category = "disk-encryption"
            field = "drive:All"
            equals = "encrypted"

            [[require]]
            category = "disk-encryption"
            field = "drive:Data"
            matches = "^encrypted$"

            [[require]]
            category = "patch-management"
            """)
        let res = p.check(Self.products)
        #expect(res.map(\.pass) == [true, true, false, false, true, false])
        let fw = res[2].detail.joined(separator: "\n")
        #expect(fw.contains("socketfilterfw") && fw.contains("needs root"))
    }

    @Test(arguments: [
        "[[require]]\nfield = \"x\"\n",
        "[[require]]\ncategory = \"firewall\"\nequals = \"yes\"\n",
        "[[require]]\ncategory = \"firewall\"\nfield = \"is-enabled\"\nmatches = \"(\"\n",
        "[[require]]\ncategory = \"firewall\"\ncolour = \"red\"\n",
    ])
    func parseErrors(_ text: String) {
        #expect(throws: CheckError.self) { try Policy.parse(text) }
    }

    @Test func versions() {
        for (a, b, want) in [("5329", "5300", 1), ("27.1", "27.1.0", 0), ("27.0.1", "27.1", -1),
                             ("6.2.8-1045", "6.2.8-999", 1), ("", "1", -1), ("1.0b", "1.0a", 1)] {
            #expect(compareVersions(a, b) == want, "\(a) vs \(b)")
        }
    }
}
