import Foundation

/// One pending update, reported under <missing-patches>.
///
/// GlobalProtect gets these from its OPSWAT SDK, which on macOS lists what
/// Software Update has pending and looks each one up in OPSWAT's database.
/// The title is the `softwareupdate --list` label. kb-article-id is the
/// number of Apple's "About the security content of ..." support article,
/// blank when Apple published none; we don't look those up, so it is always
/// blank here. Severity is OPSWAT's rating: 0 low, 1 moderate, 2 important,
/// 3 critical.
public struct MissingPatch: Sendable, Codable, Equatable {
    public var title: String
    public var description: String
    public var product: String
    public var vendor: String
    public var infoURL: String
    public var kbArticleID: String
    public var securityBulletinID: String
    public var severity: Int
    public var category: String

    enum CodingKeys: String, CodingKey {
        case title, description, product, vendor, infoURL = "info_url", kbArticleID = "kb_article_id"
        case securityBulletinID = "security_bulletin_id", severity, category
    }

    public init(title: String, description: String = "", product: String = "", vendor: String = "Apple Inc.",
                infoURL: String = "", kbArticleID: String = "", securityBulletinID: String = "",
                severity: Int, category: String = "") {
        self.title = title
        self.description = description
        self.product = product
        self.vendor = vendor
        self.infoURL = infoURL
        self.kbArticleID = kbArticleID
        self.securityBulletinID = securityBulletinID
        self.severity = severity
        self.category = category
    }

    var xml: Node {
        Node("entry", [
            .text("title", title),
            .text("description", description),
            .text("product", product),
            .text("vendor", vendor),
            .text("info-url", infoURL),
            .text("kb-article-id", kbArticleID),
            .text("security-bulletin-id", securityBulletinID),
            .text("severity", String(severity)),
            .text("category", category),
            .text("is-installed", "no"),
        ])
    }
}

/// What was found pending, and how.
public struct PatchScan: Sendable, Codable, Equatable {
    public var patches: [MissingPatch]
    public var how: String
    public var error: String?
}

/// Lists the updates from Software Update's last background scan. --no-scan
/// keeps this fast and offline: a fresh scan asks Apple's servers and can
/// take minutes or hang softwareupdated.
let softwareUpdateList = ["/usr/sbin/softwareupdate", "--list", "--no-scan"]

extension Env {
    public func missingPatches() -> PatchScan {
        let r = run(softwareUpdateList, timeout: 30)
        let how = softwareUpdateList.joined(separator: " ")
        guard r.succeeded else {
            let why = r.exitCode.map { "exit \($0)" } ?? "did not finish"
            return PatchScan(patches: [], how: how, error: "softwareupdate \(why); reporting none")
        }
        return PatchScan(patches: parseSoftwareUpdateList(r.stdout), how: how, error: nil)
    }
}

/// Parses `softwareupdate --list` (macOS 10.15 and later):
///
///     * Label: macOS Tahoe 26.7.3-25G342
///     	Title: macOS Tahoe 26.7.3, Version: 26.7.3, Size: 1534223KiB, Recommended: YES, Action: restart,
///     * Label: Safari27.2TahoeAuto-27.2
///     	Title: Safari, Version: 27.2, Size: 182451K, Recommended: YES,
func parseSoftwareUpdateList(_ out: String) -> [MissingPatch] {
    var patches: [MissingPatch] = []
    var label: String?
    var attrs: [String: String] = [:]
    func flush() {
        if let l = label, !l.isEmpty { patches.append(patch(label: l, attrs)) }
        label = nil
        attrs = [:]
    }
    for raw in out.split(separator: "\n", omittingEmptySubsequences: true) {
        let line = raw.trimmingCharacters(in: .whitespaces)
        if line.hasPrefix("* Label:") {
            flush()
            label = line.dropFirst("* Label:".count).trimmingCharacters(in: .whitespaces)
        } else if label != nil, line.hasPrefix("Title:") {
            attrs = parseAttributes(line)
        }
    }
    flush()
    return patches
}

/// "Title: Safari, Version: 27.2, Size: 182451K, Recommended: YES," as a
/// map. Titles don't contain ", ", so splitting on it is safe.
private func parseAttributes(_ line: String) -> [String: String] {
    var m: [String: String] = [:]
    for part in line.components(separatedBy: ", ") {
        let kv = part.split(separator: ":", maxSplits: 1)
        guard kv.count == 2 else { continue }
        m[kv[0].trimmingCharacters(in: .whitespaces)] = kv[1].trimmingCharacters(in: CharacterSet(charactersIn: " ,"))
    }
    return m
}

private func patch(label: String, _ attrs: [String: String]) -> MissingPatch {
    let title = attrs["Title"] ?? ""
    let version = attrs["Version"] ?? ""
    var desc = title
    if !version.isEmpty && !title.hasSuffix(version) { desc += (desc.isEmpty ? "" : " ") + version }
    return MissingPatch(title: label, description: desc, product: title, severity: severity(title: title, attrs))
}

/// OPSWAT's rating isn't available to us. GP rated macOS updates 2
/// (important) and Safari 1 (moderate); we rate anything that is the OS or
/// needs a restart 2 and everything else 1.
private func severity(title: String, _ attrs: [String: String]) -> Int {
    let os = title.hasPrefix("macOS") || title.hasPrefix("OS X") || title.hasPrefix("Mac OS")
    return os || attrs["Action"]?.lowercased() == "restart" ? 2 : 1
}
