import Foundation

/// One pending update, reported under <missing-patches>.
///
/// GlobalProtect gets these from its OPSWAT SDK, which on macOS lists what
/// Software Update has pending and looks each one up in OPSWAT's database.
/// The title is the `softwareupdate --list` label. kb-article-id is the
/// number of Apple's "About the security content of ..." support article,
/// blank when Apple published none; we look it up in the SOFA feeds (see
/// Sofa.swift). Severity is OPSWAT's scale: 0 low, 1 moderate, 2 important,
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
    /// One line per SOFA feed consulted: where its data came from, or why
    /// there was none.
    public var feeds: [String] = []
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
        let pending = parseSoftwareUpdateList(r.stdout)
        // Only ask SOFA about products that have something pending, so a
        // Mac that is up to date never touches the network.
        var feeds: [String] = []
        var loaded: [SofaFeed: SofaIndex] = [:]
        for feed in SofaFeed.allCases where pending.contains(where: { $0.feed == feed }) {
            let (index, note) = sofaIndex(feed)
            loaded[feed] = index
            feeds.append("\(feed.rawValue): \(note)")
        }
        let patches = pending.map { u in u.patch(u.feed.flatMap { loaded[$0] }?.advisory(for: u)) }
        return PatchScan(patches: patches, how: how, error: nil, feeds: feeds)
    }
}

/// One entry of `softwareupdate --list`.
struct PendingUpdate: Equatable {
    var label: String
    var title = ""
    var version = ""
    var restart = false

    var isOS: Bool { title.hasPrefix("macOS") || title.hasPrefix("OS X") || title.hasPrefix("Mac OS") }

    /// The build, for an OS update: labels are "macOS Tahoe 26.7.3-25G342".
    var build: String? {
        guard isOS, let dash = label.lastIndex(of: "-") else { return nil }
        let b = label[label.index(after: dash)...]
        return b.isEmpty ? nil : String(b)
    }

    var feed: SofaFeed? {
        if isOS { return .macOS }
        if title == "Safari" || label.hasPrefix("Safari") { return .safari }
        return nil
    }

    func patch(_ adv: Advisory?) -> MissingPatch {
        var desc = title
        if !version.isEmpty && !title.hasSuffix(version) { desc += (desc.isEmpty ? "" : " ") + version }
        return MissingPatch(title: label, description: desc, product: title, infoURL: adv?.url ?? "",
                            kbArticleID: adv?.number ?? "", severity: severity(adv))
    }

    /// OPSWAT's ratings aren't available to us. Apple's advisory severity,
    /// mapped to the same scale, is the base when SOFA has one; otherwise
    /// the OS or anything needing a restart is 2 (important) and the rest 1
    /// (moderate). A fix for an actively exploited CVE rates one higher.
    /// For the updates in GP's own report this gives what GP sent.
    func severity(_ adv: Advisory?) -> Int {
        let base = adv?.severity ?? (isOS || restart ? 2 : 1)
        return min(3, base + (adv?.exploited == true ? 1 : 0))
    }
}

/// Parses `softwareupdate --list` (macOS 10.15 and later):
///
///     * Label: macOS Tahoe 26.7.3-25G342
///     	Title: macOS Tahoe 26.7.3, Version: 26.7.3, Size: 1534223KiB, Recommended: YES, Action: restart,
///     * Label: Safari27.2TahoeAuto-27.2
///     	Title: Safari, Version: 27.2, Size: 182451K, Recommended: YES,
func parseSoftwareUpdateList(_ out: String) -> [PendingUpdate] {
    var updates: [PendingUpdate] = []
    for raw in out.split(separator: "\n", omittingEmptySubsequences: true) {
        let line = raw.trimmingCharacters(in: .whitespaces)
        if line.hasPrefix("* Label:") {
            let label = line.dropFirst("* Label:".count).trimmingCharacters(in: .whitespaces)
            if !label.isEmpty { updates.append(PendingUpdate(label: label)) }
        } else if !updates.isEmpty, line.hasPrefix("Title:") {
            let attrs = parseAttributes(line)
            updates[updates.count - 1].title = attrs["Title"] ?? ""
            updates[updates.count - 1].version = attrs["Version"] ?? ""
            updates[updates.count - 1].restart = attrs["Action"]?.lowercased() == "restart"
        }
    }
    return updates
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
