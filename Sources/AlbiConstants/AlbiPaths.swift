/// Fixed system paths that Albi's processes share. The app, the root helper,
/// the tunnel extension and hipreport must agree on these byte for byte, so
/// each is a full string literal: grep for a path and you land here.
///
/// No Foundation, so every target can import this, including GPCore and the
/// Linux build of HIPCore. Callers wrap a path in a URL where they need one.
public enum AlbiPaths {
    /// Root-owned state, readable by everyone.
    public static let supportDirectory = "/Library/Application Support/Albi"
    /// Local HIP check files. Must be owned by root and writable by nobody else.
    public static let checksDirectory = "/Library/Application Support/Albi/checks.d"
    /// Where the helper and the extension (root) write diagnostics dumps.
    /// Readable by everyone: dumps are redacted before they are written.
    public static let diagnosticsDirectory = "/Library/Application Support/Albi/Diagnostics"
    /// The routes NetConfig added, so a later run can sweep them after a crash.
    public static let helperJournal = "/Library/Application Support/Albi/helper-journal.json"
    /// The helper's saved VPNs.
    public static let profiles = "/Library/Application Support/Albi/profiles.json"
    /// `{profile, wantConnected}`: what launchd's KeepAlive restart reconnects.
    public static let helperState = "/Library/Application Support/Albi/helper-state.json"

    /// hipreport's cache when it runs as root, so users can't write the root
    /// helper's cache. Other users get their own ~/Library/Caches/Albi.
    public static let rootCacheDirectory = "/Library/Caches/Albi"

    /// PATH for the commands Albi runs, so a user's PATH can't swap them.
    public static let safePATH = "/usr/bin:/bin:/usr/sbin:/sbin"
}
