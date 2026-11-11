# Albi

A macOS client for Palo Alto GlobalProtect VPNs.

This repository is one Swift package plus, later, the Xcode project for the app, its packet tunnel extension and helper.

| Target | What |
| --- | --- |
| `HIPCore` | HIP report collection: check files, probes, report XML |
| `hipreport` | command-line HIP reporter, run by the app or the root helper |
| `GPCore` | the GlobalProtect client core: login, getconfig, HIP check, GPST tunnel framing, the session state machine and its runner |
| `GPMac` | the macOS I/O layer: URLSession, NWConnection, NWPathMonitor, NetworkExtension glue, Keychain |
| `albi-cli` | command-line harness: logs in and runs the tunnel in userspace, pinging through it |
| `AlbiApp` | the menu-bar app's SwiftUI scenes and view models, against the `VPNService` protocol (macOS only) |
| `Apps/` | Xcode project (XcodeGen) for the app and its packet tunnel system extension |

## Build and test

```sh
swift build
swift test
```

`HIPCore` and `GPCore` build and test on Linux as well as macOS; CI runs both.

## GPCore

The client core has no Apple-only APIs and no Foundation. The OS plugs in through three protocols in `Runner.swift`: `GatewayConnector` (HTTPS requests and a raw TLS stream), `TunnelHost` (network settings, packets, HIP report, saved credentials) and `SessionClock`.

- `Login` runs prelogin, portal getconfig and gateway login, answering the second-factor challenge, and returns an `AuthCookie`.
- `Session` is a pure state machine with an injectable clock. It reconnects with the same cookie on tunnel loss, dead peer, network change and wake, with capped backoff and no attempt limit; retries a failed HIP check on its own timer without touching the tunnel; rekeys when the gateway asks; and, with saved credentials, logs in again shortly before the cookie's lifetime ends. Only a rejected cookie ends a session.
- `SessionRunner` carries out the session's actions over the protocols above.
- `TunnelSettings` maps getconfig to routes, DNS and MTU, ready to become `NEPacketTunnelNetworkSettings`.

Protocol details follow openconnect's `gpst.c` and `auth-globalprotect.c`, which remain the reference.

## Trying it against the fake gateway

`e2e/client.sh` runs `albi-cli` against [gp-fake-gateway](https://github.com/njvack/gp-fake-gateway) with no root and no extension; CI runs it on macOS. By hand:

```sh
go run ./cmd/fakegp -listen 127.0.0.1:8443 -control 127.0.0.1:8444   # in gp-fake-gateway; prints the pin
printf 'test\n' | swift run albi-cli connect 127.0.0.1:8443 --user test --pin pin-sha256:... --second-factor 1 --ping 10.99.0.1
```

`albi-cli connect` also works against a real portal: drop `--pin` to use the system trust store, and add `--hip-wrapper /path/to/hipreport` if the gateway wants HIP reports. It never touches routes or DNS; it only proves login, HIP and the tunnel.

## The app and extension (Step 1 test build)

Needs macOS 27, Xcode, [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`) and a Developer ID team.

1. In the Apple Developer portal, create App IDs for `com.github.njvack.albi` (System Extension and Network Extensions capabilities) and `com.github.njvack.albi.tunnel` (Network Extensions, plus an app group `<TEAMID>.com.github.njvack.albi`), and a Developer ID provisioning profile for each.
2. `cp Apps/Config/Signing.example.xcconfig Apps/Config/Signing.xcconfig` and fill in your team ID and profile names.
3. `cd Apps && xcodegen generate && open Albi.xcodeproj`, build the Albi scheme, and copy `Albi.app` to `/Applications` (system extensions only load from there). Bump `CURRENT_PROJECT_VERSION` for each rebuild you install, or macOS keeps the old extension.
4. Run it, click Activate and approve the extension in System Settings › General › Login Items & Extensions. Fill in the profile, Save (macOS asks to allow the VPN configuration), enter the password and Connect.

The extension logs under subsystem `com.github.njvack.albi`: `log stream --predicate 'subsystem == "com.github.njvack.albi"' --level info`.

What the test build is meant to settle: whether the extension (root, sandboxed) can keep the password and cookie in the System keychain; that traffic flows; that sleep, wake and Wi-Fi changes reconnect with the same cookie; that killing the extension (`sudo killall -9 com.github.njvack.albi.tunnel`) leaves no routes or DNS behind; and that the gateway accepts a HIP report. For HIP, set "HIP report command" to a csd-wrapper style reporter (the Go `hipreport` or `hipreport.zsh`); the app runs it when the extension asks.

## The menu-bar app (Phase 3, mock tunnel)

`AlbiApp` holds the menu-bar app: a `MenuBarExtra` menu with one icon per tunnel state, the login window (AutoFill username and password, a code step for profiles that ask each time), the setup checklist, the HIP compliance table, and Settings with profiles. It talks only to the `VPNService` protocol; `MockVPNService` implements it until the live one, over `NETunnelProviderManager` and provider messages, replaces it after Step 1.

To run it: `cd Apps && xcodegen generate && open Albi.xcodeproj`, choose the AlbiMenu scheme and Run. It is signed ad hoc, so it needs no team. The Demo submenu drops the connection or fails a HIP check. In the demo, Work has a saved password and sends a push; Lab asks for a password and a code, and rejects the password `wrong` and the code `000000`.

`swift test --filter AlbiAppTests` covers the view models on macOS.
