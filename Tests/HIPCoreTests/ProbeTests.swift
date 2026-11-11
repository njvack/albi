import Foundation
import Testing
@testable import HIPCore

@Suite struct ProbeTests {
    static let plist = """
        <?xml version="1.0"?><plist version="1.0"><dict>
        <key>CFBundleShortVersionString</key><string>2.5</string>
        <key>Nested</key><dict><key>On</key><true/><key>N</key><integer>7</integer><key>F</key><real>1.5</real></dict>
        </dict></plist>
        """

    static func system() -> FakeSystem {
        FakeSystem(uid: 501, commands: [
            .init(argv: ["/bin/ps", "-axo", "comm="], stdout: "/sbin/launchd\n/usr/bin/a\n"),
            .init(argv: ["/bin/launchctl", "print", "gui/501/com.example.agent"], stdout: "ok"),
            .init(argv: ["/bin/launchctl", "print", "system/com.example.missing"], exit: 113),
            .init(argv: ["/usr/bin/tool"], stdout: "Firewall is disabled. (blocking off)\n"),
            .init(argv: ["/usr/bin/odd"], stdout: "something else\n"),
        ], files: [
            .init(path: "/A.app/Contents/Info.plist", content: plist,
                  modified: Date(timeIntervalSince1970: 1_793_783_700)),
        ])
    }

    static let cases: [(String, Probe, String)] = [
        ("value", Probe(value: "yes"), "yes"),
        ("bundle_version", Probe(probe: "bundle_version", path: "/A.app"), "2.5"),
        ("bundle_version missing", Probe(probe: "bundle_version", path: "/B.app"), ""),
        ("plist bool", Probe(probe: "plist", path: "/A.app/Contents/Info.plist", key: "Nested.On"), "true"),
        ("plist int", Probe(probe: "plist", path: "/A.app/Contents/Info.plist", key: "Nested.N"), "7"),
        ("plist real", Probe(probe: "plist", path: "/A.app/Contents/Info.plist", key: "Nested.F"), "1.5"),
        ("plist missing key", Probe(probe: "plist", path: "/A.app/Contents/Info.plist", key: "Nope"), ""),
        ("mtime", Probe(probe: "mtime", path: "/A.app/Contents/Info.plist"), "1793783700"),
        ("exists", Probe(probe: "exists", path: "/A.app"), "yes"),
        ("not exists", Probe(probe: "exists", path: "/B.app"), "no"),
        ("process running", Probe(probe: "process", path: "/usr/bin/a"), "yes"),
        ("process not running", Probe(probe: "process", path: "/usr/bin/b"), "no"),
        ("launchd gui", Probe(probe: "launchd", label: "gui/com.example.agent"), "yes"),
        ("launchd missing", Probe(probe: "launchd", label: "system/com.example.missing"), "no"),
        ("command first match wins", Probe(probe: "command", argv: ["/usr/bin/tool"], map: [
            MapEntry(match: "disabled", value: "no"), MapEntry(match: "enabled|blocking", value: "yes")]), "no"),
        ("command no match", Probe(probe: "command", argv: ["/usr/bin/odd"], map: [MapEntry(match: "on", value: "yes")]), "n/a"),
        ("command default", Probe(probe: "command", argv: ["/usr/bin/odd"], map: [MapEntry(match: "^on", value: "yes")],
                                  defaultValue: "no"), "no"),
        ("command missing", Probe(probe: "command", argv: ["/usr/bin/none"], map: [MapEntry(match: ".", value: "yes")]), "n/a"),
        ("privileged as user", Probe(probe: "privileged", fact: "pf.enabled"), "n/a"),
        ("all yes", Probe(probe: "all", all: [Probe(probe: "process", path: "/usr/bin/a"), Probe(probe: "exists", path: "/A.app")]), "yes"),
        ("all one no", Probe(probe: "all", all: [Probe(probe: "process", path: "/usr/bin/a"), Probe(probe: "process", path: "/usr/bin/b")]), "no"),
        ("all unknown", Probe(probe: "all", all: [Probe(probe: "process", path: "/usr/bin/a"), Probe(value: "n/a")]), "n/a"),
    ]

    @Test(arguments: cases)
    func probe(_ c: (String, Probe, String)) {
        let v = Env(Self.system()).eval(c.1)
        #expect(v.value == c.2, "\(c.0): \(v.how) \(v.error ?? "")")
    }

    @Test func privilegedAsRoot() {
        let f = FakeSystem(uid: 0, commands: [.init(argv: ["/sbin/pfctl", "-s", "info"], stdout: "Status: Enabled for 0 days 01:02:03\n")])
        #expect(Env(f).eval(Probe(probe: "privileged", fact: "pf.enabled")).value == "yes")
    }

    @Test func binaryPlist() throws {
        let data = try PropertyListSerialization.data(fromPropertyList: ["CFBundleShortVersionString": "9.1", "B": true],
                                                      format: .binary, options: 0)
        let f = FakeSystem(files: [.init(path: "/X.app/Contents/Info.plist")])
        f.files[0].content = ""
        // Binary content can't live in a String fixture, so go through the
        // recorder's conversion, as a recording of a real Mac would.
        f.files[0].content = textForFixture(data)
        #expect(Env(f).eval(Probe(probe: "bundle_version", path: "/X.app")).value == "9.1")
        #expect(Env(f).eval(Probe(probe: "plist", path: "/X.app/Contents/Info.plist", key: "B")).value == "true")
    }

    @Test func whenExists() {
        let f = FakeSystem(files: [.init(path: "/Applications/X.app/Contents/Info.plist")])
        var c = Check()
        c.category = "firewall"
        c.vendor = "v"
        c.name = "n"
        c.whenExists = ["/Applications/X.app", "/Applications/Y.app"]
        #expect(Env(f).evaluate(c) == nil)
        c.whenExists = ["/Applications/X.app"]
        #expect(Env(f).evaluate(c)?.fields["version"]?.value == "")
    }

    @Test func mountLines() {
        #expect(parseMountLine("/dev/disk5s1 on /Volumes/Scratch & Stuff (apfs, local, nodev)")?.0 == "/Volumes/Scratch & Stuff")
        #expect(parseMountLine("map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)")?.1
                == ["autofs", "automounted", "nobrowse"])
        #expect(parseMountLine("garbage") == nil)
    }

    @Test func volumesFromNativeAnswers() {
        let f = FakeSystem()
        f.volumes = [
            Volume(mountPoint: "/", name: "Macintosh HD", isInternal: true, encrypted: true),
            Volume(mountPoint: "/System/Volumes/Data", name: "Data", browsable: false, isInternal: true, encrypted: true),
            Volume(mountPoint: "/System/Volumes/VM", name: "VM", browsable: false, isInternal: true, encrypted: false),
            Volume(mountPoint: "/Volumes/Backup", name: "Backup", isInternal: false, encrypted: false),
            Volume(mountPoint: "/Volumes/Scratch", name: "Scratch", isInternal: true),
            Volume(mountPoint: "/Volumes/share", name: "share", local: false, encrypted: false),
        ]
        let (drives, err) = Env(f).volumes()
        #expect(err == nil)
        #expect(drives == [Drive(name: "Macintosh HD", state: "encrypted"), Drive(name: "Data", state: "encrypted"),
                           Drive(name: "Scratch", state: "unknown"), Drive(name: "All", state: "unknown")])
        f.volumes = []
        #expect(Env(f).volumes().0 == [Drive(name: "All", state: "unknown")])
    }

    @Test func nativeAnswersSurviveAFixture() throws {
        let f = FakeSystem(host: "h")
        f.os = "27.1"
        f.processes = ["/usr/libexec/a", "/Applications/B.app/Contents/MacOS/B"]
        f.volumes = [Volume(mountPoint: "/", name: "Macintosh HD", isInternal: true, encrypted: true),
                     Volume(mountPoint: "/Volumes/X", name: "X", local: false, browsable: false)]
        f.interfaces = [Interface(device: "en0", mac: "aa:bb:cc:dd:ee:ff", ipv4: ["10.0.0.2"], ipv6: ["fe80::1"])]
        let g = try FakeSystem.parse(fixture: f.fixtureText())
        #expect(g.osVersion() == "27.1")
        #expect(g.processPaths() == f.processes)
        #expect(g.mountedVolumes() == f.volumes)
        #expect(g.networkInterfaces() == f.interfaces)
    }

    @Test func realSystemRunsCommandsWithFixedEnvironment() {
        let s = RealSystem()
        let r = s.run(["/bin/sh", "-c", "echo $PATH; echo oops >&2; exit 3"], timeout: 5)
        #expect(r.stdout == safePath + "\n")
        #expect(r.exitCode == 3)
        #expect(s.run(["sh", "-c", "true"], timeout: 5).exitCode == nil, "relative paths must not run")
        let start = Date()
        #expect(s.run(["/bin/sleep", "10"], timeout: 0.5).exitCode == nil)
        #expect(Date().timeIntervalSince(start) < 5)
    }
}
