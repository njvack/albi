/// Identifiers that must match across the app, the helper, the extension and
/// the plists in Apps/: launchd labels, Mach services, keychain services and
/// the log subsystem. Full string literals, like AlbiPaths.
///
/// The bundle IDs themselves live in Apps/Config/Albi.xcconfig
/// (ALBI_BUNDLE_ID_PREFIX); these are the names the code uses at run time.
public enum AlbiIDs {
    /// The os_log subsystem for every Albi process.
    public static let logSubsystem = "com.github.njvack.albi"

    /// The root helper's launchd label and Mach service. Must match Label and
    /// MachServices in Apps/AlbiHelper/com.github.njvack.albi.helper.plist.
    public static let helperLabel = "com.github.njvack.albi.helper"
    /// The helper's launchd plist inside Contents/Library/LaunchDaemons.
    public static let helperPlist = "com.github.njvack.albi.helper.plist"
    /// The menu-bar app's launch-at-login agent, label and plist inside
    /// Contents/Library/LaunchAgents.
    public static let menuAgentLabel = "com.github.njvack.albi.menu"
    public static let menuAgentPlist = "com.github.njvack.albi.menu.plist"

    /// Keychain service for credentials the root helper keeps.
    public static let helperKeychainService = "com.github.njvack.albi.helper"
    /// Keychain service for credentials the tunnel extension keeps.
    public static let tunnelKeychainService = "com.github.njvack.albi.tunnel"
}
