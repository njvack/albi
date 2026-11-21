/// Identifiers that must match across the apps, the helper, the extension and
/// the plists in Apps/: launchd labels, Mach services, keychain services and
/// the log subsystem. Full string literals, like AlbiPaths.
///
/// The bundle IDs themselves come from ALBI_BUNDLE_ID_PREFIX in
/// Apps/Config/Albi.xcconfig and Apps/project.yml: the extension build is
/// the prefix itself (app) and `.tunnel`; the helper build lives under
/// `.helper` (app), `.helper.daemon` and `.helper.hipreport`. These are the
/// names the code uses at run time.
public enum AlbiIDs {
    /// The os_log subsystem for every Albi process.
    public static let logSubsystem = "com.github.njvack.albi"

    /// The root helper's launchd label and Mach service. Must match Label and
    /// MachServices in Apps/Helper/launchd/com.github.njvack.albi.helper.daemon.plist.
    public static let helperLabel = "com.github.njvack.albi.helper.daemon"
    /// The helper's launchd plist inside Contents/Library/LaunchDaemons.
    public static let helperPlist = "com.github.njvack.albi.helper.daemon.plist"
    /// The helper app's launch-at-login agent, label and plist inside
    /// Contents/Library/LaunchAgents.
    public static let helperLoginAgentLabel = "com.github.njvack.albi.helper.login"
    public static let helperLoginAgentPlist = "com.github.njvack.albi.helper.login.plist"

    /// Keychain service for credentials the root helper keeps. Not a launchd
    /// or bundle ID: renaming it would orphan saved passwords.
    public static let helperKeychainService = "com.github.njvack.albi.helper"
    /// Keychain service for credentials the tunnel extension keeps.
    public static let tunnelKeychainService = "com.github.njvack.albi.tunnel"
}
