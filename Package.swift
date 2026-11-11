// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Albi",
    // The app and extension require macOS 27; that floor lives in the Xcode
    // project. The package stays lower so GitHub's macOS runners can build it.
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "HIPCore", targets: ["HIPCore"]),
        .executable(name: "hipreport", targets: ["hipreport"]),
        .library(name: "GPCore", targets: ["GPCore"]),
        .library(name: "GPMac", targets: ["GPMac"]),
        .executable(name: "albi-cli", targets: ["albi-cli"]),
        .library(name: "AlbiApp", targets: ["AlbiApp"]),
    ],
    dependencies: [
        .package(url: "https://github.com/dduan/TOMLDecoder", from: "0.4.5"),
    ],
    targets: [
        // HIP report collection: check files, probes, report XML. Pure Swift
        // with Foundation, so its tests run on Linux too.
        .target(
            name: "HIPCore",
            dependencies: [.product(name: "TOMLDecoder", package: "TOMLDecoder")]
        ),
        .executableTarget(name: "hipreport", dependencies: ["HIPCore"]),
        .testTarget(name: "HIPCoreTests", dependencies: ["HIPCore"]),

        // The GlobalProtect client core: protocol requests and parsing, GPST
        // framing, the session state machine and its runner. No Apple-only
        // APIs and no Foundation, so it builds and tests on Linux.
        .target(name: "GPCore"),
        .testTarget(name: "GPCoreTests", dependencies: ["GPCore"]),

        // The macOS I/O layer: URLSession, NWConnection, NWPathMonitor and
        // NetworkExtension glue. Its files are wrapped in #if canImport so the
        // package still builds on Linux, where the target is empty.
        .target(name: "GPMac", dependencies: ["GPCore"]),
        .testTarget(name: "GPMacTests", dependencies: ["GPMac", "GPCore"]),

        // Command-line harness: GPCore plus GPMac, pinging through the tunnel
        // from userspace. Used by e2e/client.sh against gp-fake-gateway.
        .executableTarget(name: "albi-cli", dependencies: ["GPCore", "GPMac"]),

        // The menu-bar app's SwiftUI scenes and view models, against the
        // VPNService protocol (a mock for now). macOS only: wrapped in
        // #if canImport(SwiftUI), so it is empty on Linux.
        .target(name: "AlbiApp", dependencies: ["GPMac"]),
        .testTarget(name: "AlbiAppTests", dependencies: ["AlbiApp", "GPMac"]),
    ]
)
