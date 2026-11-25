// albi-helper: Albi's root LaunchDaemon. It makes the network changes the
// helper build's VPN session needs and an unprivileged process can't: the
// app talks to it over XPC on the Mach service
// com.github.njvack.albi.helper.daemon, and it opens a utun and hands the app
// the descriptor, sets the utun's addresses, routes and DNS from settings it
// checks first, and takes them out again. The session itself (login, TLS,
// cookies, passwords, packets) runs in the app, as the user.
//
// The app registers it with SMAppService from Contents/Library/LaunchDaemons;
// launchd runs it as root and keeps it alive. Whatever it set up for a client
// goes when that client's connection does, and it sweeps journaled routes at
// startup, so a crash on either side leaves nothing behind.
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
        // Nothing secret passes through here any more, but a root core file
        // is still nothing to leave lying around.
        var noCore = rlimit(rlim_cur: 0, rlim_max: 0)
        _ = setrlimit(RLIMIT_CORE, &noCore)
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
