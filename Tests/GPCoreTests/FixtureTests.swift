import Foundation
import Testing
@testable import GPCore

// Foundation on macOS has its own XMLElement.
private typealias XMLElement = GPCore.XMLElement

/// Runs GPCore's parsers over every captured conversation in Fixtures/, and
/// checks that albi sends the same form fields openconnect did. Each folder
/// there is the `fixtures` output of `gp-capture`; see the README.
struct CapturedConversation: CustomTestStringConvertible, Sendable {
    struct Row: Sendable {
        var n: String, method: String, target: String, status: Int?, label: String
    }

    var name: String
    var dir: URL
    var rows: [Row]

    var testDescription: String { name }

    func response(_ r: Row) -> String? {
        try? String(contentsOf: dir.appendingPathComponent("\(r.n)-\(r.label).response.xml"), encoding: .utf8)
    }

    func request(_ r: Row) -> Form? {
        (try? String(contentsOf: dir.appendingPathComponent("\(r.n)-\(r.label).request.form"), encoding: .utf8))
            .map { Form.parse($0.trimmingCharacters(in: .newlines)) }
    }

    static let all: [CapturedConversation] = {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures")
        let names = (try? FileManager.default.contentsOfDirectory(atPath: root.path)) ?? []
        return names.sorted().compactMap { name in
            let dir = root.appendingPathComponent(name)
            guard let index = try? String(contentsOf: dir.appendingPathComponent("index.tsv"), encoding: .utf8) else { return nil }
            let rows = index.split(separator: "\n").filter { !$0.hasPrefix("#") }.map { line in
                let f = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
                return Row(n: f[0], method: f[1], target: f[2], status: Int(f[3]), label: f[4])
            }
            return CapturedConversation(name: name, dir: dir, rows: rows)
        }
    }()
}

@Suite struct FixtureTests {
    @Test func fixturesExist() {
        #expect(!CapturedConversation.all.isEmpty)
    }

    @Test(arguments: CapturedConversation.all)
    func parses(_ c: CapturedConversation) throws {
        var sawConfig = false
        for r in c.rows {
            guard let body = c.response(r), let status = r.status else { continue }
            let what = "\(c.name) \(r.n)-\(r.label)"
            switch r.label {
            case "portal-prelogin":
                _ = Prelogin(try Reply.document(status: status, body: body))
            case "portal-getconfig" where status == 200:
                let pc = try PortalConfig(try Reply.document(status: status, body: body))
                #expect(!pc.gateways.isEmpty, "\(what): no gateways")
            case "gateway-login" where status == 200:
                switch try Reply.classify(status: status, body: body) {
                case .challenge(_, let inputStr):
                    #expect(!inputStr.isEmpty, "\(what): challenge without inputstr")
                case .document(let d):
                    let cookie = try AuthCookie(jnlp: d, computer: "computer1")
                    #expect(!cookie.authcookie.isEmpty)
                }
            case "gateway-getconfig" where status == 200:
                let gc = try GatewayConfig(try Reply.document(status: status, body: body))
                #expect(gc.ipv4 != nil || gc.ipv6 != nil, "\(what)")
                sawConfig = true
            case "gateway-hipreportcheck" where status == 200:
                _ = try Requests.hipReportNeeded(try Reply.document(status: status, body: body))
            default:
                break
            }
        }
        #expect(sawConfig, "\(c.name): no gateway getconfig answer")
    }

    /// albi's requests carry the same fields as openconnect's, which the
    /// gateway accepted.
    @Test(arguments: CapturedConversation.all)
    func requestFieldsMatchOpenConnect(_ c: CapturedConversation) throws {
        let cookie = AuthCookie(authcookie: "c", portal: "p", user: "u", domain: "d", preferredIP: "10.0.0.2",
                                preferredIPv6: "fd00::2", computer: "computer1")
        func names(_ f: Form) -> Set<String> { Set(f.fields.map(\.name)) }
        // Optional fields that depend on the session, not on the client.
        let optional: Set<String> = ["preferred-ip", "preferred-ipv6", "client-ip", "client-ipv6", "portal", "domain"]
        for r in c.rows {
            guard let sent = c.request(r) else { continue }
            let ours: Form
            switch r.label {
            case "gateway-getconfig":
                ours = Requests.getConfig(cookie, client: ClientInfo(computer: "computer1")).body
            case "gateway-hipreportcheck":
                ours = Requests.hipReportCheck(cookie, clientIPv4: "10.0.0.2", clientIPv6: "fd00::2").body
            case "gateway-logout":
                ours = Requests.logout(cookie).body
            default:
                continue
            }
            #expect(names(ours).subtracting(optional) == names(sent).subtracting(optional),
                    "\(c.name) \(r.n)-\(r.label): albi sends \(names(ours).sorted()), openconnect sent \(names(sent).sorted())")
        }
    }
}
