// albi-helper: Albi's root LaunchDaemon. It takes the place of the packet
// tunnel system extension: the app talks to it over XPC on the Mach service
// com.github.njvack.albi.helper, and it runs the tunnel through
// TunnelController with a utun, routes and DNS from UtunHost.
//
// The app registers it with SMAppService from Contents/Library/LaunchDaemons;
// launchd runs it as root and keeps it alive. It sweeps journaled routes at
// startup and reconnects if helper-state.json says the user wants to be
// connected, so a crash or a reboot comes back on its own.
//
//   albi-helper            run as the daemon (launchd does this)
//   albi-helper status     ask the running helper for its status (any user)
//   albi-helper version

#if os(macOS)
import Foundation
import GPMac

let args = Array(CommandLine.arguments.dropFirst())
switch args.first {
case nil, "run":
    guard getuid() == 0 else {
        FileHandle.standardError.write(Data("albi-helper: the daemon runs as root, from launchd\n".utf8))
        exit(1)
    }
    HelperDaemon.main()
case "status":
    HelperStatusCommand.run()
case "version":
    print("albi-helper protocol \(AlbiHelper.protocolVersion) build \(HelperDaemon.build)")
default:
    FileHandle.standardError.write(Data("usage: albi-helper [run | status | version]\n".utf8))
    exit(1)
}
#else
print("albi-helper needs macOS")
#endif
