import Foundation
import Testing
@testable import HIPCore

@Suite struct PatchTests {
    // The three updates GP reported for a Mac on Tahoe 26.7.
    static let listing = """
        Software Update Tool

        Software Update found the following new or updated software:
        * Label: Safari27.2TahoeAuto-27.2
        \tTitle: Safari, Version: 27.2, Size: 182451K, Recommended: YES,\u{20}
        * Label: macOS Tahoe 26.7.3-25G342
        \tTitle: macOS Tahoe 26.7.3, Version: 26.7.3, Size: 1534223KiB, Recommended: YES, Action: restart,\u{20}
        * Label: macOS 27.2.1-26B131
        \tTitle: macOS 27.2.1, Version: 27.2.1, Size: 7340032KiB, Recommended: YES, Action: restart,\u{20}

        """

    static func system(_ stdout: String, exit: Int32 = 0) -> FakeSystem {
        FakeSystem(commands: [.init(argv: softwareUpdateList, stdout: stdout, exit: exit)])
    }

    @Test func parsesListing() {
        let got = parseSoftwareUpdateList(Self.listing)
        #expect(got == [
            MissingPatch(title: "Safari27.2TahoeAuto-27.2", description: "Safari 27.2", product: "Safari", severity: 1),
            MissingPatch(title: "macOS Tahoe 26.7.3-25G342", description: "macOS Tahoe 26.7.3",
                         product: "macOS Tahoe 26.7.3", severity: 2),
            MissingPatch(title: "macOS 27.2.1-26B131", description: "macOS 27.2.1", product: "macOS 27.2.1", severity: 2),
        ])
    }

    @Test func restartMeansImportant() {
        let got = parseSoftwareUpdateList("""
            * Label: Command Line Tools for Xcode-27.1
            \tTitle: Command Line Tools for Xcode, Version: 27.1, Size: 900000K, Recommended: YES, Action: restart,
            * Label: XProtectPlistConfigData-5300
            \tTitle: XProtectPlistConfigData, Version: 5300, Size: 100K, Recommended: NO,
            """)
        #expect(got.map(\.severity) == [2, 1])
    }

    @Test func nothingPending() {
        #expect(parseSoftwareUpdateList("").isEmpty)
        #expect(parseSoftwareUpdateList("Software Update Tool\n\nNo new software available.\n").isEmpty)
    }

    @Test func labelWithoutTitleLine() {
        let got = parseSoftwareUpdateList("* Label: Mystery-1.0\n")
        #expect(got == [MissingPatch(title: "Mystery-1.0", severity: 1)])
    }

    @Test func commandFailureReportsNone() {
        let scan = Env(Self.system("", exit: 1)).missingPatches()
        #expect(scan.patches.isEmpty)
        #expect(scan.error == "softwareupdate exit 1; reporting none")
        let missing = Env(FakeSystem()).missingPatches()
        #expect(missing.patches.isEmpty)
        #expect(missing.error == "softwareupdate did not finish; reporting none")
    }

    @Test func reportListsPatchesOnce() throws {
        let doc = collect(Env(Self.system(Self.listing)), CheckSet(), Request()).xml.document
        #expect(doc.components(separatedBy: "<missing-patches>").count == 2)
        #expect(doc.contains("""
                  <missing-patches>
                    <entry>
                      <title>Safari27.2TahoeAuto-27.2</title>
                      <description>Safari 27.2</description>
                      <product>Safari</product>
                      <vendor>Apple Inc.</vendor>
                      <info-url/>
                      <kb-article-id/>
                      <security-bulletin-id/>
                      <severity>1</severity>
                      <category/>
                      <is-installed>no</is-installed>
                    </entry>
            """))
        #expect(doc.contains("<title>macOS Tahoe 26.7.3-25G342</title>"))
    }

    @Test func facts() throws {
        let json = runCLI(["facts", "--json", "--no-builtin"], system: Self.system(Self.listing)).out
        let top = try #require(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        let scan = try #require(top["missing_patches"] as? [String: Any])
        let patches = try #require(scan["patches"] as? [[String: Any]])
        #expect(patches.count == 3)
        #expect(patches[1]["title"] as? String == "macOS Tahoe 26.7.3-25G342")
        #expect(patches[1]["kb_article_id"] as? String == "")
        #expect(patches[1]["severity"] as? Int == 2)
        let text = runCLI(["facts", "--no-builtin"], system: Self.system(Self.listing)).out
        #expect(text.contains("missing patches: 3  via /usr/sbin/softwareupdate --list --no-scan\n"))
        #expect(text.contains("  severity 2  macOS Tahoe 26.7.3-25G342\n"))
    }
}
