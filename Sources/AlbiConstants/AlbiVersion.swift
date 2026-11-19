/// Version strings shared by every target. Full string literals, like
/// AlbiPaths, and no Foundation, so GPCore and HIPCore can both use them.
public enum AlbiVersion {
    /// Albi's own version. Keep in step with MARKETING_VERSION in
    /// Apps/project.yml.
    public static let albi = "0.1.0"

    /// The GlobalProtect version we report at login when nothing else says,
    /// as openconnect does. Login replaces it with the portal's version when
    /// the portal gives one; HIP reports get whichever version login used.
    public static let globalProtect = "6.3.0-33"

    /// Sent with our own HTTP requests that aren't to the VPN (the SOFA feed).
    /// SOFA asks custom tools to identify themselves.
    public static let userAgent = "Albi/\(albi) (+https://github.com/njvack/albi)"
}
