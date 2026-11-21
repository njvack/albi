// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Albi",
    // The app and extension require macOS 27; that floor lives in the Xcode
    // project. The package stays lower so GitHub's macOS runners can build it.
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "AlbiConstants", targets: ["AlbiConstants"]),
        .library(name: "HIPCore", targets: ["HIPCore"]),
        .executable(name: "hipreport", targets: ["hipreport"]),
        .library(name: "GPCore", targets: ["GPCore"]),
        .library(name: "GPMac", targets: ["GPMac"]),
        .executable(name: "albi-cli", targets: ["albi-cli"]),
        .executable(name: "gp-capture", targets: ["gp-capture"]),
        .library(name: "Diagnostics", targets: ["Diagnostics"]),
        .executable(name: "albi-diag", targets: ["albi-diag"]),
        .library(name: "AlbiApp", targets: ["AlbiApp"]),
        .library(name: "HelperBackend", targets: ["HelperBackend"]),
        .executable(name: "albi-netprobe", targets: ["albi-netprobe"]),
        .executable(name: "albi-helper", targets: ["albi-helper"]),
    ],
    dependencies: [
        .package(url: "https://github.com/dduan/TOMLDecoder", from: "0.4.5"),
    ],
    targets: [
        // Paths and identifiers every process must agree on: AlbiPaths and
        // AlbiIDs. String literals only, no Foundation, so anything can
        // import it, on Linux too.
        .target(name: "AlbiConstants"),
        .testTarget(name: "AlbiConstantsTests", dependencies: ["AlbiConstants"]),

        // HIP report collection: check files, probes, report XML. Pure Swift
        // with Foundation, so its tests run on Linux too.
        .target(
            name: "HIPCore",
            dependencies: ["AlbiConstants", .product(name: "TOMLDecoder", package: "TOMLDecoder")],
            // The built-in check library ships as a resource bundle; see
            // builtinLibraryURL() in Library.swift.
            resources: [.copy("Library")]
        ),
        .executableTarget(name: "hipreport", dependencies: ["HIPCore"]),
        .testTarget(name: "HIPCoreTests", dependencies: ["HIPCore"], exclude: ["Fixtures"]),

        // The GlobalProtect client core: protocol requests and parsing, GPST
        // framing, the session state machine and its runner. No Apple-only
        // APIs and no Foundation, so it builds and tests on Linux.
        .target(name: "GPCore", dependencies: ["AlbiConstants"]),
        .testTarget(name: "GPCoreTests", dependencies: ["GPCore"], exclude: ["Fixtures"]),

        // The macOS I/O layer: URLSession, NWConnection, NWPathMonitor and
        // NetworkExtension glue. Its files are wrapped in #if canImport so the
        // package still builds on Linux, where the target is empty.
        .target(name: "GPMac", dependencies: ["AlbiConstants", "GPCore", "Diagnostics"]),
        .testTarget(name: "GPMacTests", dependencies: ["GPMac", "GPCore"]),

        // Command-line harness: GPCore plus GPMac, pinging through the tunnel
        // from userspace. Used by e2e/client.sh against gp-fake-gateway.
        .executableTarget(name: "albi-cli", dependencies: ["AlbiConstants", "GPCore", "GPMac"]),

        // Records a real session through openconnect as redacted fixtures:
        // log parsing, redaction and the summary live in GPCapture
        // (Foundation, so it tests on Linux); gp-capture runs openconnect.
        .target(name: "GPCapture", dependencies: ["GPCore"]),
        .executableTarget(name: "gp-capture", dependencies: ["GPCapture"]),
        .testTarget(name: "GPCaptureTests", dependencies: ["GPCapture", "GPCore"]),

        // Diagnostics mode: writes the flight recorder's window (GPCore) as a
        // redacted incident file, using GPCapture's redactor, and reads it
        // back for replay and for drafting gp-fake-gateway scenarios.
        // albi-diag is the command-line side.
        .target(name: "Diagnostics", dependencies: ["AlbiConstants", "GPCore", "GPCapture"]),
        .executableTarget(name: "albi-diag", dependencies: ["Diagnostics", "GPCore"]),
        .testTarget(name: "DiagnosticsTests", dependencies: ["Diagnostics", "GPCore", "GPCapture"]),

        // The menu-bar app's SwiftUI scenes and view models, against the
        // VPNService protocol, plus MockVPNService. Shared by both builds of
        // the app; nothing here knows which backend runs the tunnel. macOS
        // only: wrapped in #if canImport(SwiftUI), so it is empty on Linux.
        .target(name: "AlbiApp", dependencies: ["AlbiConstants", "GPMac", "Diagnostics"]),
        .testTarget(name: "AlbiAppTests", dependencies: ["AlbiApp", "GPMac", "Diagnostics"]),

        // The helper backend: VPNService over XPC to albi-helper, and launch
        // at login as a LaunchAgent. HelperApp in Apps/ uses it. macOS only.
        .target(name: "HelperBackend", dependencies: ["AlbiApp", "AlbiConstants", "GPMac", "Diagnostics"]),
        .testTarget(name: "HelperBackendTests", dependencies: ["HelperBackend", "AlbiApp", "GPMac"]),

        // Root-helper probe: makes a utun, routes and temporary DNS keys
        // and checks they vanish when the process dies; also registers a
        // test daemon with SMAppService. e2e/netprobe.sh and
        // scripts/smappservice-probe.sh drive it. macOS only.
        .executableTarget(name: "albi-netprobe"),

        // The root LaunchDaemon that runs the tunnel in place of the system
        // extension: TunnelController over UtunHost, driven by the app over
        // XPC. The app embeds it and registers it with SMAppService.
        // macOS only.
        .executableTarget(
            name: "albi-helper",
            dependencies: ["AlbiConstants", "GPCore", "GPMac", "Diagnostics"]
        ),
    ]
)
