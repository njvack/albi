#if os(macOS)
    import Foundation
    import Security

    /// Who signed a piece of code, and the code-signing requirements that the
    /// helper and the app hold each other to.
    ///
    /// A build signed by a team (an Apple Development certificate) is pinned by
    /// team ID and identifier, so it survives rebuilds. An ad-hoc build has no
    /// team, so it can only be pinned by the exact binary (its cdhash): that is
    /// a development fallback, and anything that can rewrite the app bundle
    /// before the helper starts can get past it. Unsigned code gets no
    /// requirement at all, and callers refuse it.
    public struct CodeIdentity: Equatable, Sendable {
        public var identifier: String
        /// nil for an ad-hoc signature.
        public var teamID: String?
        /// The code directory hash, hex.
        public var cdhash: String

        /// The signature on the code at `url` (a bundle or a bare executable),
        /// or nil if it's unsigned or broken.
        public static func of(_ url: URL) -> CodeIdentity? {
            var code: SecStaticCode?
            guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
                SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess
            else { return nil }
            var info: CFDictionary?
            guard
                SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
                    == errSecSuccess,
                let d = info as? [String: Any],
                let id = d[kSecCodeInfoIdentifier as String] as? String, isSafe(id),
                let unique = d[kSecCodeInfoUnique as String] as? Data
            else { return nil }
            let team = (d[kSecCodeInfoTeamIdentifier as String] as? String).flatMap { isSafe($0) ? $0 : nil }
            return CodeIdentity(
                identifier: id, teamID: team, cdhash: unique.map { String(format: "%02x", $0) }.joined())
        }

        /// A requirement for other code. With a team, it holds across
        /// rebuilds: that team and one of `identifiers`. Without one, the
        /// exact binaries in `adHoc`.
        public static func requirement(team: String?, identifiers: [String], adHoc: [CodeIdentity]) -> String? {
            if let team {
                let ids = identifiers.filter(isSafe)
                guard isSafe(team), !ids.isEmpty else { return nil }
                let idClause = ids.map { "identifier \"\($0)\"" }.joined(separator: " or ")
                return "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and (\(idClause))"
            }
            let hashes = adHoc.map(\.cdhash).filter { !$0.isEmpty && $0.allSatisfy(\.isHexDigit) }
            guard !hashes.isEmpty else { return nil }
            return hashes.map { "cdhash H\"\($0)\"" }.joined(separator: " or ")
        }

        /// Whether the code at `url` meets `requirement`, checked on disk just
        /// before it's used.
        public static func check(_ url: URL, requirement: String) -> Bool {
            var code: SecStaticCode?
            var req: SecRequirement?
            guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
                SecRequirementCreateWithString(requirement as CFString, [], &req) == errSecSuccess, let req
            else { return false }
            return SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), req)
                == errSecSuccess
        }

        /// Identifiers and team IDs go into requirement strings: letters,
        /// digits, dots, dashes and underscores only.
        static func isSafe(_ s: String) -> Bool {
            !s.isEmpty
                && s.utf8.allSatisfy { b in
                    (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || b == 0x2e
                        || b == 0x2d || b == 0x5f
                }
        }
    }

    extension AlbiHelper {
        /// The identifiers to pin, read from the code itself: for a team
        /// build, each piece's own identifier as long as it's signed by
        /// `team`, so nothing depends on how Xcode names tools.
        static func identifiers(team: String, of urls: [URL]) -> [String] {
            urls.compactMap { CodeIdentity.of($0) }.filter { $0.teamID == team }.map(\.identifier)
        }

        /// What the helper accepts on its XPC listener: the app it ships in,
        /// or its own binary (`albi-helper status`). `helper` is the helper's
        /// executable, at Contents/MacOS inside the app. nil when the helper
        /// is unsigned, in which case it accepts nobody.
        public static func clientRequirement(helper: URL) -> String? {
            guard let me = CodeIdentity.of(helper) else { return nil }
            let app = helper.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            let appIdentity = app.pathExtension == "app" ? CodeIdentity.of(app) : nil
            if let team = me.teamID {
                let ids = [me.identifier] + identifiers(team: team, of: app.pathExtension == "app" ? [app] : [])
                return CodeIdentity.requirement(team: team, identifiers: ids, adHoc: [])
            }
            // Ad hoc: the app as it is now, at the helper's startup.
            return CodeIdentity.requirement(team: nil, identifiers: [], adHoc: [me] + (appIdentity.map { [$0] } ?? []))
        }

        /// What the app expects of the helper it connects to: the same team,
        /// and the identifier of the helper in its own bundle. nil for an
        /// ad-hoc or unsigned app, which then trusts the Mach service name
        /// alone (only launchd's system domain can publish it, and only for a
        /// registered daemon).
        public static func helperRequirement(app: URL, helper: URL) -> String? {
            guard let me = CodeIdentity.of(app), let team = me.teamID else { return nil }
            return CodeIdentity.requirement(team: team, identifiers: identifiers(team: team, of: [helper]), adHoc: [])
        }
    }
#endif
