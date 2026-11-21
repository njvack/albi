import AlbiConstants
import Foundation
import Testing

/// The plists in Apps/Helper/launchd are read by launchd, not by Swift, so
/// these keep them and AlbiIDs from drifting apart.
@Suite struct AlbiConstantsTests {
    static let appsDir = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Apps")
    static let launchdDir = appsDir.appendingPathComponent("Helper/launchd")
    /// HelperApp's bundle ID: ALBI_BUNDLE_ID_PREFIX + ".helper" in project.yml.
    static let helperAppID = AlbiIDs.logSubsystem + ".helper"

    static func plist(_ name: String) throws -> [String: Any] {
        let data = try Data(contentsOf: launchdDir.appendingPathComponent(name))
        return try #require(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
    }

    @Test func helperPlistMatches() throws {
        let p = try Self.plist(AlbiIDs.helperPlist)
        #expect(p["Label"] as? String == AlbiIDs.helperLabel)
        let services = try #require(p["MachServices"] as? [String: Any])
        #expect(services.keys.contains(AlbiIDs.helperLabel))
        #expect(p["AssociatedBundleIdentifiers"] as? [String] == [Self.helperAppID])
    }

    @Test func loginAgentPlistMatches() throws {
        let p = try Self.plist(AlbiIDs.helperLoginAgentPlist)
        #expect(p["Label"] as? String == AlbiIDs.helperLoginAgentLabel)
        #expect(p["AssociatedBundleIdentifiers"] as? [String] == [Self.helperAppID])
    }

    /// The plists name the app by bundle ID and by executable path, which
    /// project.yml sets.
    @Test func plistsMatchTheHelperApp() throws {
        let yml = try String(contentsOf: Self.appsDir.appendingPathComponent("project.yml"), encoding: .utf8)
        #expect(yml.contains("PRODUCT_BUNDLE_IDENTIFIER: $(ALBI_BUNDLE_ID_PREFIX).helper\n"))
        #expect(yml.contains("PRODUCT_NAME: Albi\n"))
        #expect(try Self.plist(AlbiIDs.helperLoginAgentPlist)["BundleProgram"] as? String == "Contents/MacOS/Albi")
    }

    @Test func plistNamesAreLabels() {
        #expect(AlbiIDs.helperPlist == AlbiIDs.helperLabel + ".plist")
        #expect(AlbiIDs.helperLoginAgentPlist == AlbiIDs.helperLoginAgentLabel + ".plist")
    }

    @Test func idsShareThePrefix() {
        for id in [
            AlbiIDs.helperLabel, AlbiIDs.helperLoginAgentLabel, AlbiIDs.helperKeychainService,
            AlbiIDs.tunnelKeychainService,
        ] {
            #expect(id.hasPrefix(AlbiIDs.logSubsystem + "."), "\(id)")
        }
    }

    @Test func pathsLiveInTheSupportDirectory() {
        let files = [
            AlbiPaths.checksDirectory, AlbiPaths.diagnosticsDirectory, AlbiPaths.helperJournal,
            AlbiPaths.profiles, AlbiPaths.helperState,
        ]
        for f in files {
            #expect(f.hasPrefix(AlbiPaths.supportDirectory + "/"), "\(f)")
            #expect(!f.dropFirst(AlbiPaths.supportDirectory.count + 1).contains("/"), "\(f)")
        }
    }

    @Test func versionMatchesTheAppProject() throws {
        let yml = try String(contentsOf: Self.appsDir.appendingPathComponent("project.yml"), encoding: .utf8)
        #expect(yml.contains("MARKETING_VERSION: \"\(AlbiVersion.albi)\""))
        #expect(AlbiVersion.userAgent.hasPrefix("Albi/\(AlbiVersion.albi) "))
    }
}
