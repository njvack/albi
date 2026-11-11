// hipreport writes a GlobalProtect HIP report from Albi's check files.
// See `hipreport help`.
import Foundation
import HIPCore

let cli = CLI(
    system: RealSystem(),
    environment: ProcessInfo.processInfo.environment,
    out: { FileHandle.standardOutput.write(Data($0.utf8)) },
    err: { FileHandle.standardError.write(Data($0.utf8)) })
exit(cli.run(Array(CommandLine.arguments.dropFirst())))
