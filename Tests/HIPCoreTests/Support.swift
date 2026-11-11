import Foundation
@testable import HIPCore

/// Fixtures live next to this file; tests read them by path.
let fixtures = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures")
let macBasic = fixtures.appendingPathComponent("mac-basic.toml").path

func check(_ toml: String) throws -> Check { try Check.parse(toml) }

func messages(_ errs: [CheckError]) -> String { errs.map(\.description).joined(separator: "\n") }

/// Runs the CLI against a system, collecting output.
func runCLI(_ args: [String], system: System = RealSystem(), environment: [String: String] = [:])
    -> (code: Int32, out: String, err: String)
{
    var out = "", err = ""
    let cli = CLI(system: system, environment: environment, out: { out += $0 }, err: { err += $0 })
    let code = cli.run(args)
    return (code, out, err)
}

func tempDir() -> URL {
    let u = FileManager.default.temporaryDirectory.appendingPathComponent("hiptest-" + UUID().uuidString)
    try! FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
    return u
}

func write(_ dir: URL, _ rel: String, _ text: String) {
    let u = dir.appendingPathComponent(rel)
    try! FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
    try! text.write(to: u, atomically: true, encoding: .utf8)
}
