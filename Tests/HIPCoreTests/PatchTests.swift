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

    // Trimmed from the real v2 feeds, 2026-11-19.
    static let macFeed = """
        {"OSVersions": [
          {"OSVersion": "Golden Gate 27", "SecurityReleases": [
            {"UpdateName": "macOS Golden Gate 27.2.1", "ProductVersion": "27.2.1", "Build": "26B8132",
             "AllBuilds": ["26B8132", "26B7131", "26B131"], "SecurityInfo": "https://support.apple.com/en-us/149718",
             "Advisory": {"Number": "149718", "URL": "https://support.apple.com/en-us/149718", "Severity": "Medium"},
             "CVEs": {"CVE-2026-111497": {"ActivelyExploited": true}}, "ActivelyExploitedCVEs": ["CVE-2026-111497"]},
            {"UpdateName": "macOS Golden Gate 27.0.1", "ProductVersion": "27.0.1", "Build": "26A101",
             "SecurityInfo": "This update has no published CVE entries.", "CVEs": {}, "ActivelyExploitedCVEs": []}
          ]},
          {"OSVersion": "Tahoe 26", "SecurityReleases": [
            {"UpdateName": "macOS Tahoe 26.7.3", "ProductVersion": "26.7.3", "Build": "25G342", "AllBuilds": ["25G342"],
             "SecurityInfo": "https://support.apple.com/en-us/149719",
             "Advisory": {"Number": "149719", "URL": "https://support.apple.com/en-us/149719", "Severity": "Medium"},
             "ActivelyExploitedCVEs": ["CVE-2026-111497"]},
            {"UpdateName": "macOS Tahoe 26.7.1", "ProductVersion": "26.7.1", "Build": "25G100",
             "SecurityInfo": "https://support.apple.com/en-us/149228", "ActivelyExploitedCVEs": []}
          ]}
        ]}
        """

    static let safariFeed = """
        {"AppVersions": [{"AppVersion": "Safari 27", "SecurityReleases": [
          {"UpdateName": "Safari 27.2", "ProductVersion": "27.2", "SecurityInfo": "https://support.apple.com/en-us/149527",
           "Advisory": {"Number": "149527", "URL": "https://support.apple.com/en-us/149527", "Severity": "Medium"},
           "ActivelyExploitedCVEs": []}
        ]}]}
        """

    static let now = Date(timeIntervalSince1970: 1_800_000_000)

    static func system(_ stdout: String, exit: Int32 = 0, feeds: Bool = true) -> FakeSystem {
        let f = FakeSystem(now: now, commands: [.init(argv: softwareUpdateList, stdout: stdout, exit: exit)])
        if feeds {
            f.fetches = [SofaFeed.macOS.url: macFeed, SofaFeed.safari.url: safariFeed]
        }
        return f
    }

    static func cachePath(_ feed: SofaFeed) -> String {
        FakeSystem.defaultCacheDir + "/sofa/\(feed.rawValue)_data_feed.json"
    }

    @Test func parsesListing() {
        let got = parseSoftwareUpdateList(Self.listing)
        #expect(got == [
            PendingUpdate(label: "Safari27.2TahoeAuto-27.2", title: "Safari", version: "27.2"),
            PendingUpdate(label: "macOS Tahoe 26.7.3-25G342", title: "macOS Tahoe 26.7.3", version: "26.7.3", restart: true),
            PendingUpdate(label: "macOS 27.2.1-26B131", title: "macOS 27.2.1", version: "27.2.1", restart: true),
        ])
        #expect(got.map(\.build) == [nil, "25G342", "26B131"])
        #expect(got.map(\.feed) == [.safari, .macOS, .macOS])
    }

    @Test func nothingPending() {
        #expect(parseSoftwareUpdateList("").isEmpty)
        #expect(parseSoftwareUpdateList("Software Update Tool\n\nNo new software available.\n").isEmpty)
        let sys = Self.system("No new software available.\n")
        let scan = Env(sys).missingPatches()
        #expect(scan.patches.isEmpty)
        #expect(scan.feeds.isEmpty)
        #expect(sys.files.isEmpty, "nothing pending, so nothing fetched or cached")
    }

    @Test func labelWithoutTitleLine() {
        #expect(parseSoftwareUpdateList("* Label: Mystery-1.0\n") == [PendingUpdate(label: "Mystery-1.0")])
    }

    // With the feeds, the KB IDs and severities match GP's report for the
    // same three updates, except that GP's database had no article for
    // 27.2.1 yet.
    @Test func matchesGP() {
        let scan = Env(Self.system(Self.listing)).missingPatches()
        #expect(scan.error == nil)
        #expect(scan.patches == [
            MissingPatch(title: "Safari27.2TahoeAuto-27.2", description: "Safari 27.2", product: "Safari",
                         infoURL: "https://support.apple.com/en-us/149527", kbArticleID: "149527", severity: 1),
            MissingPatch(title: "macOS Tahoe 26.7.3-25G342", description: "macOS Tahoe 26.7.3", product: "macOS Tahoe 26.7.3",
                         infoURL: "https://support.apple.com/en-us/149719", kbArticleID: "149719", severity: 2),
            MissingPatch(title: "macOS 27.2.1-26B131", description: "macOS 27.2.1", product: "macOS 27.2.1",
                         infoURL: "https://support.apple.com/en-us/149718", kbArticleID: "149718", severity: 2),
        ])
        #expect(scan.feeds == [
            "macos: fetched \(SofaFeed.macOS.url)",
            "safari: fetched \(SofaFeed.safari.url)",
        ])
    }

    @Test func severityWithoutFeeds() {
        let scan = Env(Self.system(Self.listing + """
            * Label: Command Line Tools for Xcode-27.1
            \tTitle: Command Line Tools for Xcode, Version: 27.1, Size: 900000K, Recommended: YES, Action: restart,
            * Label: XProtectPlistConfigData-5300
            \tTitle: XProtectPlistConfigData, Version: 5300, Size: 100K, Recommended: NO,
            """, feeds: false)).missingPatches()
        #expect(scan.patches.map(\.severity) == [1, 2, 2, 2, 1])
        #expect(scan.patches.allSatisfy { $0.kbArticleID.isEmpty && $0.infoURL.isEmpty })
        #expect(scan.feeds == [
            "macos: could not fetch \(SofaFeed.macOS.url) and nothing cached; kb-article-id left blank",
            "safari: could not fetch \(SofaFeed.safari.url) and nothing cached; kb-article-id left blank",
        ])
    }

    @Test func severityScale() {
        let u = PendingUpdate(label: "x", title: "Safari")
        func adv(_ s: String?, _ e: Bool) -> Advisory { Advisory(number: "1", url: "", severity: severityRank(s), exploited: e) }
        #expect(u.severity(adv("Low", false)) == 0)
        #expect(u.severity(adv("Medium", false)) == 1)
        #expect(u.severity(adv("High", false)) == 2)
        #expect(u.severity(adv("Critical", false)) == 3)
        #expect(u.severity(adv("Critical", true)) == 3)
        #expect(u.severity(adv("High", true)) == 3)
        #expect(u.severity(adv(nil, false)) == 1)
        #expect(u.severity(adv(nil, true)) == 2)
    }

    @Test func parsesFeeds() throws {
        let mac = try #require(parseSofaFeed(Data(Self.macFeed.utf8)))
        #expect(mac.byBuild["26B7131"]?.number == "149718")
        #expect(mac.byVersion["26.7.1"] == Advisory(number: "149228", url: "https://support.apple.com/en-us/149228",
                                                     severity: nil, exploited: false))
        #expect(mac.byVersion["27.0.1"] == nil, "no article")
        #expect(try #require(parseSofaFeed(Data(Self.safariFeed.utf8))).byVersion["27.2"]?.number == "149527")
        #expect(parseSofaFeed(Data("{}".utf8)) == nil)
        #expect(parseSofaFeed(Data("<html>".utf8)) == nil)
        #expect(articleNumber("https://support.apple.com/en-us/149527") == "149527")
        #expect(articleNumber("https://support.apple.com/en-us/HT201222") == nil)
    }

    @Test func freshCacheSkipsFetch() {
        let sys = Self.system(Self.listing, feeds: false)
        for (feed, body) in [(SofaFeed.macOS, Self.macFeed), (.safari, Self.safariFeed)] {
            sys.files.append(.init(path: Self.cachePath(feed), content: body, modified: Self.now - 3600))
        }
        let scan = Env(sys).missingPatches()
        #expect(scan.patches.map(\.kbArticleID) == ["149527", "149719", "149718"])
        #expect(scan.feeds.first == "macos: cached \(Self.cachePath(.macOS)), 60 min old")
    }

    @Test func staleCacheIsRefreshed() {
        let sys = Self.system(Self.listing)
        sys.files.append(.init(path: Self.cachePath(.macOS), content: #"{"OSVersions": []}"#,
                               modified: Self.now - 7 * 3600))
        let scan = Env(sys).missingPatches()
        #expect(scan.patches[1].kbArticleID == "149719")
        #expect(scan.feeds.first == "macos: fetched \(SofaFeed.macOS.url)")
        #expect(sys.readFile(Self.cachePath(.macOS)) == Data(Self.macFeed.utf8))
        #expect(sys.stat(Self.cachePath(.macOS))?.modified == Self.now)
    }

    @Test func staleCacheWhenOffline() {
        let sys = Self.system(Self.listing, feeds: false)
        sys.fetches[SofaFeed.macOS.url] = "<html>rate limited</html>"
        sys.files.append(.init(path: Self.cachePath(.macOS), content: Self.macFeed, modified: Self.now - 7 * 3600))
        let scan = Env(sys).missingPatches()
        #expect(scan.patches[1].kbArticleID == "149719")
        #expect(scan.feeds.first == "macos: could not fetch \(SofaFeed.macOS.url); using stale \(Self.cachePath(.macOS)), 420 min old")
        #expect(sys.readFile(Self.cachePath(.macOS)) == Data(Self.macFeed.utf8), "a bad fetch must not replace the cache")
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
                      <info-url>https://support.apple.com/en-us/149527</info-url>
                      <kb-article-id>149527</kb-article-id>
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
        #expect(patches[1]["kb_article_id"] as? String == "149719")
        #expect(patches[1]["severity"] as? Int == 2)
        let text = runCLI(["facts", "--no-builtin"], system: Self.system(Self.listing)).out
        #expect(text.contains("missing patches: 3  via /usr/sbin/softwareupdate --list --no-scan\n"))
        #expect(text.contains("  sofa macos: fetched \(SofaFeed.macOS.url)\n"))
        #expect(text.contains("  severity 2  macOS Tahoe 26.7.3-25G342  kb 149719\n"))
    }

    @Test func fixtureRoundTrip() throws {
        let sys = Self.system(Self.listing)
        sys.cacheDir = "/Users/x/Library/Caches/Albi"
        let back = try FakeSystem.parse(fixture: sys.fixtureText())
        #expect(back.fetches == sys.fetches)
        #expect(back.cacheDir == sys.cacheDir)
    }
}
