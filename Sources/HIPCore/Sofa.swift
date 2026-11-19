import Foundation

// SOFA (https://github.com/macadmins/sofa) publishes Apple's security
// releases as JSON, including each release's support article and the
// severity from Apple's advisory. We use it for the kb-article-id, info-url
// and severity of missing patches, which softwareupdate doesn't give.

/// The SOFA feeds we read.
public enum SofaFeed: String, CaseIterable, Sendable {
    case macOS = "macos"
    case safari = "safari"

    public var url: String {
        switch self {
        case .macOS: "https://sofafeed.macadmins.io/v2/macos_data_feed.json"
        case .safari: "https://sofafeed.macadmins.io/v2/safari_data_feed.json"
        }
    }
}

/// How old a cached feed may get before we fetch it again. SOFA rebuilds
/// its feeds a few times a day; Software Update checks every six hours.
let sofaMaxAge: TimeInterval = 6 * 3600
let sofaTimeout: TimeInterval = 5

/// Apple's advisory for one release.
struct Advisory: Equatable {
    var number: String
    var url: String
    /// Apple's rating on OPSWAT's 0-3 scale, if the advisory has one.
    var severity: Int?
    var exploited: Bool
}

/// A feed's releases, keyed for lookup.
struct SofaIndex: Equatable {
    var byBuild: [String: Advisory] = [:]
    var byVersion: [String: Advisory] = [:]

    func advisory(for u: PendingUpdate) -> Advisory? {
        if let b = u.build, let a = byBuild[b] { return a }
        return u.version.isEmpty ? nil : byVersion[u.version]
    }
}

extension Env {
    /// The feed's index, from our cache if it is fresh enough, otherwise
    /// fetched and cached. A failed fetch falls back to a stale cache. The
    /// note says which happened.
    func sofaIndex(_ feed: SofaFeed) -> (SofaIndex?, String) {
        let path = sys.cacheDirectory() + "/sofa/" + feed.rawValue + "_data_feed.json"
        let age = sys.stat(path).map { sys.now().timeIntervalSince($0.modified) }
        if let age, age >= 0, age < sofaMaxAge, let d = sys.readFile(path), let idx = parseSofaFeed(d) {
            return (idx, "cached \(path), \(Int(age / 60)) min old")
        }
        if let d = sys.fetch(feed.url, timeout: sofaTimeout) {
            if let idx = parseSofaFeed(d) {
                let saved = sys.writeFile(path, d)
                return (idx, "fetched \(feed.url)" + (saved ? "" : "; could not cache at \(path)"))
            }
            debug?("sofa: \(feed.url) is not a SOFA feed")
        }
        if let d = sys.readFile(path), let idx = parseSofaFeed(d) {
            let mins = age.map { " \(Int($0 / 60)) min old" } ?? ""
            return (idx, "could not fetch \(feed.url); using stale \(path),\(mins)")
        }
        return (nil, "could not fetch \(feed.url) and nothing cached; kb-article-id left blank")
    }
}

/// Reads a v2 macOS feed (OSVersions[].SecurityReleases[]) or Safari feed
/// (AppVersions[].SecurityReleases[]). nil if it is neither.
func parseSofaFeed(_ data: Data) -> SofaIndex? {
    guard let top = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
    guard let groups = (top["OSVersions"] ?? top["AppVersions"]) as? [[String: Any]] else { return nil }
    var idx = SofaIndex()
    for g in groups {
        for r in g["SecurityReleases"] as? [[String: Any]] ?? [] {
            guard let adv = advisory(r) else { continue }
            if let v = r["ProductVersion"] as? String, !v.isEmpty, idx.byVersion[v] == nil {
                idx.byVersion[v] = adv
            }
            var builds = r["AllBuilds"] as? [String] ?? []
            if let b = r["Build"] as? String { builds.append(b) }
            for b in builds where !b.isEmpty && idx.byBuild[b] == nil { idx.byBuild[b] = adv }
        }
    }
    return idx
}

/// The release's Advisory block, or failing that its SecurityInfo link.
/// nil when the release has no support article ("This update has no
/// published CVE entries.").
private func advisory(_ r: [String: Any]) -> Advisory? {
    let exploited = !(r["ActivelyExploitedCVEs"] as? [Any] ?? []).isEmpty
    if let a = r["Advisory"] as? [String: Any], let n = a["Number"] as? String, !n.isEmpty {
        let url = a["URL"] as? String ?? r["SecurityInfo"] as? String ?? ""
        return Advisory(number: n, url: url, severity: severityRank(a["Severity"] as? String), exploited: exploited)
    }
    guard let info = r["SecurityInfo"] as? String, let n = articleNumber(info) else { return nil }
    return Advisory(number: n, url: info, severity: nil, exploited: exploited)
}

/// 149527 from https://support.apple.com/en-us/149527.
func articleNumber(_ url: String) -> String? {
    guard url.hasPrefix("https://support.apple.com/"),
          let last = url.split(separator: "/").last, !last.isEmpty, last.allSatisfy(\.isNumber) else { return nil }
    return String(last)
}

/// Apple's CSAF severity on OPSWAT's scale.
func severityRank(_ s: String?) -> Int? {
    switch (s ?? "").lowercased() {
    case "low": 0
    case "medium", "moderate": 1
    case "high", "important": 2
    case "critical": 3
    default: nil
    }
}
