import AlbiConstants
import Foundation
import Testing

/// The plists in Apps/AlbiHelper are read by launchd, not by Swift, so these
/// keep them and AlbiIDs from drifting apart.
@Suite struct AlbiConstantsTests {
    static let appsDir = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Apps/AlbiHelper")

    static func plist(_ name: String) throws -> [String: Any] {
        let data = try Data(contentsOf: appsDir.appendingPathComponent(name))
        return try #require(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
    }

    @Test func helperPlistMatches() throws {
        let p = try Self.plist(AlbiIDs.helperPlist)
        #expect(p["Label"] as? String == AlbiIDs.helperLabel)
        let services = try #require(p["MachServices"] as? [String: Any])
        #expect(services.keys.contains(AlbiIDs.helperLabel))
    }

    @Test func menuAgentPlistMatches() throws {
        let p = try Self.plist(AlbiIDs.menuAgentPlist)
        #expect(p["Label"] as? String == AlbiIDs.menuAgentLabel)
    }

    @Test func plistNamesAreLabels() {
        #expect(AlbiIDs.helperPlist == AlbiIDs.helperLabel + ".plist")
        #expect(AlbiIDs.menuAgentPlist == AlbiIDs.menuAgentLabel + ".plist")
    }

    @Test func idsShareThePrefix() {
        for id in [AlbiIDs.helperLabel, AlbiIDs.menuAgentLabel, AlbiIDs.helperKeychainService, AlbiIDs.tunnelKeychainService] {
            #expect(id.hasPrefix(AlbiIDs.logSubsystem + "."), "\(id)")
        }
    }

    @Test func pathsLiveInTheSupportDirectory() {
        let files = [AlbiPaths.checksDirectory, AlbiPaths.diagnosticsDirectory, AlbiPaths.helperJournal,
                     AlbiPaths.profiles, AlbiPaths.helperState]
        for f in files {
            #expect(f.hasPrefix(AlbiPaths.supportDirectory + "/"), "\(f)")
            #expect(!f.dropFirst(AlbiPaths.supportDirectory.count + 1).contains("/"), "\(f)")
        }
    }

    @Test func versionMatchesTheAppProject() throws {
        let yml = try String(contentsOf: Self.appsDir.deletingLastPathComponent().appendingPathComponent("project.yml"),
                             encoding: .utf8)
        #expect(yml.contains("MARKETING_VERSION: \"\(AlbiVersion.albi)\""))
        #expect(AlbiVersion.userAgent.hasPrefix("Albi/\(AlbiVersion.albi) "))
    }
}
