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
    ]
)
