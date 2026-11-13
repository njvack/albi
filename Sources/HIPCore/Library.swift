import Foundation
#if os(macOS)
import Security
#endif

/// SwiftPM's name for HIPCore's resource bundle: PACKAGE_TARGET.
let resourceBundleName = "Albi_HIPCore"

/// The directory holding the built-in check files.
///
/// It is looked for, in order:
///
/// 1. In the enclosing app or extension's Resources, as `Library`. This is
///    how the app ships it: the extension that runs hipreport carries the
///    check files, and its code signature seals them.
/// 2. In SwiftPM's resource bundle next to the executable
///    (`Albi_HIPCore.bundle` on macOS, `Albi_HIPCore.resources` on Linux),
///    for command-line builds.
/// 3. In debug builds only, the source tree, so `swift test` finds it.
///
/// When hipreport runs from inside an app or extension, the library is
/// used only if that bundle's code signature is valid. macOS checks
/// executable pages as they load but not sealed resources, so this is what
/// catches an edited check file.
func builtinLibraryURL() -> Result<URL, CheckError> {
    let main = Bundle.main
    if isBundle(main.bundleURL), let res = main.resourceURL {
        let lib = res.appendingPathComponent("Library")
        if isDirectory(lib) {
            if let e = signatureError(main.bundleURL) { return .failure(e) }
            return .success(lib)
        }
    }
    var dirs: [URL] = []
    if let exe = main.executableURL?.resolvingSymlinksInPath().deletingLastPathComponent() { dirs.append(exe) }
    dirs.append(main.bundleURL)
    for dir in dirs {
        for ext in ["bundle", "resources"] {
            let b = dir.appendingPathComponent("\(resourceBundleName).\(ext)")
            for lib in [b.appendingPathComponent("Contents/Resources/Library"), b.appendingPathComponent("Library")]
            where isDirectory(lib) {
                return .success(lib)
            }
        }
    }
    #if DEBUG
    let src = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Library")
    if isDirectory(src) { return .success(src) }
    #endif
    return .failure(CheckError("built-in check library not found (looked for \(resourceBundleName) next to \(dirs.first?.path ?? "the executable"))"))
}

private func isBundle(_ url: URL) -> Bool {
    ["app", "appex", "systemextension"].contains(url.pathExtension)
}

private func isDirectory(_ url: URL) -> Bool {
    var d: ObjCBool = false
    return FileManager.default.fileExists(atPath: url.path, isDirectory: &d) && d.boolValue
}

/// Why the bundle's signature doesn't hold, or nil if it does.
private func signatureError(_ bundle: URL) -> CheckError? {
    #if os(macOS)
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(bundle as CFURL, [], &code) == errSecSuccess, let code else {
        return CheckError("\(bundle.path): cannot read its code signature; not loading the built-in checks")
    }
    let status = SecStaticCodeCheckValidity(code, [], nil)
    guard status == errSecSuccess else {
        let why = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
        return CheckError("\(bundle.lastPathComponent) fails its code signature check (\(why)); not loading the built-in checks")
    }
    return nil
    #else
    return nil
    #endif
}
