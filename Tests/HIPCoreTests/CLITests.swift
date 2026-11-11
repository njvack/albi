import Foundation
import Testing
@testable import HIPCore

@Suite struct CLITests {
    let base = ["--checks-dir", "/nonexistent", "--fixture", macBasic]

    /// openconnect's exact wrapper invocation, plus an option it might add one day.
    @Test func wrapperMode() {
        let r = runCLI(["--cookie", "user=nate&domain=D&computer=c", "--client-ip", "10.99.0.2",
                        "--md5", "feedface", "--client-os", "Mac", "--future-option", "x"] + base)
        #expect(r.code == 0, "\(r.err)")
        #expect(r.err.contains("ignoring unknown option --future-option"))
        #expect(r.out.hasPrefix("<?xml"))
        #expect(r.out.contains("<md5-sum>feedface</md5-sum>"))
        #expect(r.out.contains("<user-name>nate</user-name>"))
        #expect(r.out.contains("<ip-address>10.99.0.2</ip-address>"))
    }

    @Test func clientVersion() {
        var r = runCLI(["--md5", "x"] + base, environment: ["APP_VERSION": "6.3.0-99"])
        #expect(r.out.contains("<client-version>6.3.0-99</client-version>"))
        r = runCLI(["--md5", "x", "--client-version=7.0"] + base, environment: ["APP_VERSION": "6.3.0-99"])
        #expect(r.out.contains("<client-version>7.0</client-version>"))
    }

    @Test func factsJSON() throws {
        let r = runCLI(["facts", "--json"] + base)
        #expect(r.code == 0, "\(r.err)")
        struct F: Decodable {
            var trusted: Bool
            var products: [P]
            struct P: Decodable {
                var name: String
                var fields: [String: V]
            }
            struct V: Decodable {
                var value: String
                var how: String
            }
        }
        let f = try JSONDecoder().decode(F.self, from: Data(r.out.utf8))
        #expect(f.trusted)
        let gk = f.products.first { $0.name == "Gatekeeper" }
        #expect(gk?.fields["real-time-protection"]?.how == "command /usr/sbin/spctl --status")
        #expect(gk?.fields["real-time-protection"]?.value == "yes")
    }

    @Test func devChecksAreMarkedUntrusted() {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        write(dir, "x.toml", """
            category = "firewall"
            vendor = "Objective Development"
            name = "Little Snitch"
            [fields]
            version = { value = "6" }
            is-enabled = { value = "yes" }
            """)
        let r = runCLI(["--md5", "x", "--dev-checks", dir.path] + base)
        #expect(r.err.contains("untrusted"))
        #expect(r.out.contains("Little Snitch"))
    }

    @Test func checkPolicy() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        write(dir, "policy.toml", """
            [[require]]
            category = "disk-encryption"
            field = "drive:All"
            equals = "encrypted"

            [[require]]
            category = "firewall"
            name = "Mac OS X Builtin Firewall"
            field = "is-enabled"
            equals = "yes"
            """)
        let pol = dir.appendingPathComponent("policy.toml").path
        let r = runCLI(["check", "--policy", pol] + base)
        #expect(r.code == 1)
        #expect(r.out.contains("FAIL  disk-encryption drive:All = encrypted"))
        #expect(r.out.contains("PASS  firewall"))
        let j = runCLI(["check", "--policy", pol, "--json"] + base)
        struct R: Decodable { var requirement: String; var pass: Bool; var detail: [String] }
        let results = try JSONDecoder().decode([R].self, from: Data(j.out.utf8))
        #expect(results.map(\.pass) == [false, true])
    }

    @Test func lint() {
        var r = runCLI(["lint", "--checks-dir", "/nonexistent"])
        #expect(r.code == 0, "\(r.out)\(r.err)")
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        write(dir, "bad.toml", """
            category = "anti-malware"
            vendor = "v"
            name = "n"
            [fields]
            version = { value = "1" }
            """)
        r = runCLI(["lint", "--no-builtin", "--checks-dir", "/nonexistent", dir.appendingPathComponent("bad.toml").path])
        #expect(r.code == 1)
        #expect(r.err.contains("real-time-protection"))
    }

    /// A recording replayed as a fixture gives the same report.
    @Test func recordReplay() throws {
        let f = try FakeSystem.load(fixture: macBasic)
        let args = ["--md5", "x", "--checks-dir", "/nonexistent"]
        let live = runCLI(args, system: f).out
        let rec = runCLI(["record"] + args, system: f).out
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        write(dir, "rec.toml", rec)
        let replay = runCLI(args + ["--fixture", dir.appendingPathComponent("rec.toml").path]).out
        #expect(live == replay)
    }

    @Test func fixtureFromGoReporterParses() throws {
        // The fixture format is shared with njvack/openconnect-hipreports.
        let f = try FakeSystem.load(fixture: macBasic)
        #expect(f.host == "nates-mbp.local")
        #expect(f.userID == 501)
        #expect(f.zone.secondsFromGMT() == -6 * 3600)
        #expect(!f.commands.isEmpty && !f.files.isEmpty)
    }
}
