import Foundation
import Testing
@testable import HIPCore

@Suite struct LibraryTests {
    @Test func libraryIsValidAndOrdered() {
        let (set, errs) = loadChecks(FakeSystem(), [.builtin])
        #expect(errs.isEmpty, "\(messages(errs))")
        #expect(set.checks.map { "\($0.category)/\($0.name)" } == [
            "anti-malware/Xprotect", "anti-malware/Gatekeeper",
            "disk-backup/Time Machine",
            "disk-encryption/FileVault",
            "firewall/Mac OS X Builtin Firewall", "firewall/Packet Filter",
            "patch-management/Software Update",
        ])
    }

    @Test func contribIsValidAndOrdered() {
        let (set, errs) = loadChecks(FakeSystem(), [.builtin, Source(dir: contribDir.path, dev: true)])
        #expect(errs.isEmpty, "\(messages(errs))")
        #expect(set.checks.map { "\($0.category)/\($0.name)" } == [
            "anti-malware/Xprotect", "anti-malware/Gatekeeper", "anti-malware/Cisco Secure Endpoint",
            "disk-backup/Time Machine", "disk-backup/Google Drive",
            "disk-encryption/FileVault",
            "firewall/Mac OS X Builtin Firewall", "firewall/Packet Filter",
            "patch-management/Software Update", "patch-management/Workspace ONE Intelligent Hub",
            "patch-management/Qualys Cloud Security Agent", "patch-management/Microsoft AutoUpdate",
            "custom-plist/",
        ])
    }

    /// BuiltinLibrary.swift must match Sources/HIPCore/Library; run
    /// scripts/gen-library.sh after editing a check file.
    @Test func embeddedLibraryMatchesFiles() throws {
        let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../Sources/HIPCore/Library").standardized
        let rels = (FileManager.default.enumerator(atPath: dir.path)?.allObjects as? [String] ?? [])
            .filter { $0.hasSuffix(".toml") }.sorted()
        #expect(rels == builtinLibrary.map(\.path).sorted(), "run scripts/gen-library.sh")
        for entry in builtinLibrary {
            let text = try String(contentsOf: dir.appendingPathComponent(entry.path), encoding: .utf8)
            #expect(text == entry.text, "\(entry.path) is stale; run scripts/gen-library.sh")
        }
    }
}

@Suite struct ValidateTests {
    static let cases: [(String, String, String)] = [
        ("unknown category", """
            category = "antivirus"
            vendor = "v"
            name = "n"
            """, #"unknown category "antivirus""#),
        ("missing required field", """
            category = "anti-malware"
            vendor = "v"
            name = "n"
            [fields]
            version = { value = "1" }
            """, #"needs field "real-time-protection""#),
        ("unknown field", """
            category = "firewall"
            vendor = "v"
            name = "n"
            [fields]
            version = { value = "1" }
            is-enabled = { value = "yes" }
            colour = { value = "red" }
            """, #"no field "colour""#),
        ("relative command", """
            category = "firewall"
            vendor = "v"
            name = "n"
            [fields]
            version = { value = "1" }
            is-enabled = { probe = "command", argv = ["pfctl"], map = [{ match = "x", value = "yes" }] }
            """, "not an absolute path"),
        ("bad regexp", """
            category = "firewall"
            vendor = "v"
            name = "n"
            [fields]
            version = { value = "1" }
            is-enabled = { probe = "command", argv = ["/bin/x"], map = [{ match = "(", value = "yes" }] }
            """, "invalid regular expression"),
        ("missing param", """
            category = "firewall"
            vendor = "v"
            name = "n"
            [fields]
            version = { probe = "bundle_version" }
            is-enabled = { value = "yes" }
            """, "needs path"),
        ("extra param", """
            category = "firewall"
            vendor = "v"
            name = "n"
            [fields]
            version = { probe = "os_version", path = "/x" }
            is-enabled = { value = "yes" }
            """, "does not take path"),
        ("volumes on a string field", """
            category = "firewall"
            vendor = "v"
            name = "n"
            [fields]
            version = { probe = "volumes" }
            is-enabled = { value = "yes" }
            """, "only fits a drives field"),
        ("launchd without domain", """
            category = "firewall"
            vendor = "v"
            name = "n"
            [fields]
            version = { value = "1" }
            is-enabled = { probe = "launchd", label = "com.example" }
            """, "needs a domain"),
        ("unknown fact", """
            category = "firewall"
            vendor = "v"
            name = "n"
            [fields]
            version = { value = "1" }
            is-enabled = { probe = "privileged", fact = "sip.enabled" }
            """, "unknown privileged fact"),
        ("relative when", """
            category = "firewall"
            vendor = "v"
            name = "n"
            when.exists = "Applications/X.app"
            [fields]
            version = { value = "1" }
            is-enabled = { value = "yes" }
            """, "not an absolute path"),
        ("custom plist without path", """
            category = "custom-plist"
            keys = ["Label"]
            """, "absolute path"),
    ]

    @Test(arguments: cases)
    func reportsProblem(_ c: (String, String, String)) throws {
        let errs = messages(try check(c.1).validate())
        #expect(errs.contains(c.2), "\(c.0): got \(errs)")
    }

    @Test func rejectsUnknownKeys() {
        #expect(throws: CheckError.self) {
            try check("""
                category = "firewall"
                vendor = "v"
                name = "n"
                [fields]
                version = { value = "1", probe_typo = "x" }
                """)
        }
        do {
            _ = try check("category = \"firewall\"\ncolour = \"red\"\n")
            Issue.record("no error")
        } catch {
            #expect("\(error)".contains("colour"))
        }
    }

    @Test func rejectsWrongTypes() {
        #expect(throws: CheckError.self) { try check("category = 3\n") }
        #expect(throws: CheckError.self) { try check("[fields]\nversion = \"1\"\n") }
    }

    @Test func whenExistsTakesStringOrArray() throws {
        #expect(try check(#"when.exists = "/a""#).whenExists == ["/a"])
        #expect(try check(#"when.exists = ["/a", "/b"]"#).whenExists == ["/a", "/b"])
    }
}

@Suite struct LoadTests {
    @Test func overridesDisablesAndSkipsBroken() {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        write(dir, "anti-malware/20-apple-gatekeeper.toml", """
            category = "anti-malware"
            vendor = "Apple Inc."
            name = "Gatekeeper (local)"
            [fields]
            version = { value = "1" }
            real-time-protection = { value = "yes" }
            """)
        write(dir, "disk-backup/10-apple-time-machine.toml", "disabled = true\n")
        write(dir, "firewall/90-little-snitch.toml", """
            category = "firewall"
            vendor = "Objective Development"
            name = "Little Snitch"
            [fields]
            version = { value = "6" }
            is-enabled = { value = "yes" }
            """)
        write(dir, "firewall/99-broken.toml", "category = \"firewall\"\n")

        let (set, errs) = loadChecks(FakeSystem(), [.builtin, Source(dir: dir.path, dev: true)])
        #expect(!errs.isEmpty)
        #expect(errs.allSatisfy { $0.description.contains("99-broken.toml") }, "\(messages(errs))")
        #expect(!set.trusted)
        let names = Dictionary(set.checks.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })
        #expect(names["Gatekeeper"] == nil)
        #expect(names["Gatekeeper (local)"]?.trusted == false)
        #expect(names["Time Machine"] == nil)
        #expect(names["Little Snitch"] != nil)
    }

    @Test func missingDirIsSkipped() {
        let (_, errs) = loadChecks(FakeSystem(), [Source(dir: "/nonexistent/Albi/checks.d")])
        #expect(errs.isEmpty)
    }

    @Test func userOwnedDirOnRealFilesystemIsRefused() throws {
        // A temp dir is under world-writable /tmp, and owned by us; as
        // either a user or root it must not be trusted.
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        write(dir, "x.toml", "disabled = true\n")
        let (_, errs) = loadChecks(RealSystem(), [Source(dir: dir.path)])
        #expect(errs.count == 1 && errs[0].description.contains("untrusted"), "\(messages(errs))")
    }
}

@Suite struct TrustTests {
    static let dir = "/Library/Application Support/Albi/checks.d"
    static let base: [FakeSystem.File] = [
        .init(path: "/", isDirectory: true, mode: 0o755),
        .init(path: "/Library", isDirectory: true, mode: 0o755),
        .init(path: "/Library/Application Support", isDirectory: true, mode: 0o755, gid: 80),
        .init(path: "/Library/Application Support/Albi", isDirectory: true, mode: 0o755),
        .init(path: dir, isDirectory: true, mode: 0o755),
    ]

    static let cases: [(String, [FakeSystem.File], String)] = [
        ("root owned", [.init(path: dir + "/a.toml", mode: 0o644)], ""),
        ("user owned file", [.init(path: dir + "/a.toml", uid: 501)], "owned by uid 501"),
        ("world writable file", [.init(path: dir + "/a.toml", mode: 0o666)], "writable by anyone"),
        ("group writable, admin", [.init(path: dir + "/a.toml", mode: 0o664, gid: 80)], "writable by group 80"),
        ("group writable, wheel", [.init(path: dir + "/a.toml", mode: 0o664, gid: 0)], ""),
        ("symlink to user file", [
            .init(path: dir + "/a.toml", mode: 0o777, symlink: "/Users/nate/a.toml"),
            .init(path: "/Users", isDirectory: true, mode: 0o755),
            .init(path: "/Users/nate", isDirectory: true, mode: 0o755, uid: 501),
            .init(path: "/Users/nate/a.toml", uid: 501),
        ], "/Users/nate"),
        ("symlink to root file", [
            .init(path: dir + "/a.toml", mode: 0o777, symlink: "/etc/albi/a.toml"),
            .init(path: "/etc", isDirectory: true, mode: 0o755),
            .init(path: "/etc/albi", isDirectory: true, mode: 0o755),
            .init(path: "/etc/albi/a.toml"),
        ], ""),
    ]

    @Test(arguments: cases)
    func trust(_ c: (String, [FakeSystem.File], String)) {
        let f = FakeSystem(files: Self.base + c.1)
        let e = checkTrusted(f, Self.dir + "/a.toml")
        if c.2.isEmpty {
            #expect(e == nil, "\(c.0): \(String(describing: e))")
        } else {
            #expect(e?.description.contains(c.2) == true, "\(c.0): \(String(describing: e))")
        }
    }

    @Test func userOwnedParentTaintsEverythingBelow() {
        var files = Self.base
        files[3] = .init(path: "/Library/Application Support/Albi", isDirectory: true, mode: 0o755, uid: 501)
        files.append(.init(path: Self.dir + "/a.toml"))
        #expect(checkTrusted(FakeSystem(files: files), Self.dir + "/a.toml") != nil)
    }
}
