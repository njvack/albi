# Albi

A macOS client for Palo Alto GlobalProtect VPNs.

This repository is one Swift package plus, later, the Xcode project for the app, its packet tunnel extension and helper.

| Target | What |
| --- | --- |
| `HIPCore` | HIP report collection: check files, probes, report XML, the JSON summary |
| `hipreport` | command-line HIP reporter, run by the app or the root helper |
| `GPCore` | the GlobalProtect client core: login, getconfig, HIP check, GPST tunnel framing, the session state machine and its runner |
| `GPMac` | the macOS I/O layer: URLSession, NWConnection, NWPathMonitor, NetworkExtension glue, Keychain |
| `albi-cli` | command-line harness: logs in and runs the tunnel in userspace, pinging through it |
| `GPCapture`, `gp-capture` | records a real gateway session through openconnect as redacted test fixtures |
| `Diagnostics`, `albi-diag` | diagnostics mode: redacted incident files from the flight recorder, replay, and gp-fake-gateway scenario drafts |
| `AlbiApp` | the menu-bar app's SwiftUI scenes and view models, against the `VPNService` protocol (macOS only) |
| `Apps/` | Xcode project (XcodeGen) for the app and its packet tunnel system extension |

## Build and test

```sh
swift build
swift test
```

`HIPCore` and `GPCore` build and test on Linux as well as macOS; CI runs both.

## hipreport

`hipreport` writes the GlobalProtect HIP report from a library of check files: what is actually installed and running on the Mac. It runs as its own process so the root helper can run it for facts only root can read; run as the user, those report `n/a`. It also works as an openconnect `--csd-wrapper`, which is how it is tested end to end. It is a port of the Go reporter in [njvack/openconnect-hipreports](https://github.com/njvack/openconnect-hipreports), which stays as the parity reference; both produce identical reports from the same fixture.

```sh
hipreport --md5 ... --cookie ... --client-ip ...   # the report, on stdout
hipreport facts [--json]                          # what each check found, and how; --json is the summary the app shows
hipreport check --policy FILE [--json]            # pass or fail per expected condition
hipreport lint [PATH...]                          # validate the library, checks.d, and any files or dirs given
hipreport record [-o FILE]                        # record this Mac's answers as a test fixture
```

Unknown options are warned about and ignored. `--client-version` (or `APP_VERSION`) sets the GlobalProtect version we claim; the default is 6.2.8-1045. `--debug` (or `HIPREPORT_DEBUG=1`) logs every command and its output to stderr.

### Check files

Each `.toml` file describes one product in one HIP category: vendor, name, when to report it, and one probe per field, from a fixed set of probes. Apple's XProtect, Gatekeeper and FileVault are ordinary check files in the built-in library ([`Sources/HIPCore/Library`](Sources/HIPCore/Library)). More come from root-owned files in `/Library/Application Support/Albi/checks.d`, and `--dev-checks DIR` loads untrusted ones for development.

[docs/check-files.md](docs/check-files.md) is the full reference: every key, the categories and their fields, what each probe does and gives on failure, load order and overrides, the trust rule, and how to write and test a check.

### Policies

The gateway never says whether a report passed. Write down what the firewall admins say it requires, and `hipreport check` says whether this Mac meets it, with the value and probe behind each answer. Each requirement passes if any matching product passes; tests are `equals`, `matches` (regexp) and `min_version`, and `field = "drive:All"` tests a disk-encryption drive.

```toml
[[require]]
category = "disk-encryption"
field = "drive:All"
equals = "encrypted"

[[require]]
category = "patch-management"      # some product present
```

### Tests

`swift test` covers probes, validation, trust rules, load order, policies, the CLI, and a golden report from a synthetic Mac (`Tests/HIPCoreTests/Fixtures/mac-basic.toml`, shared with the Go reporter; `UPDATE_GOLDEN=1 swift test` rewrites the golden file). `hipreport record` writes the same kind of fixture from a real Mac; it holds that Mac's host name, MAC and IP addresses, so scrub it before committing one. `--fixture FILE` replays one.

`e2e/hipreport.sh` runs openconnect with `hipreport` as its `--csd-wrapper` against [gp-fake-gateway](https://github.com/njvack/gp-fake-gateway) (Linux, root). `scripts/parity.sh REFERENCE` diffs the report against `hipreport.zsh` or the Go `hipreport` on a Mac. CI runs all of these.

## GPCore

The client core has no Apple-only APIs and no Foundation. The OS plugs in through three protocols in `Runner.swift`: `GatewayConnector` (HTTPS requests and a raw TLS stream), `TunnelHost` (network settings, packets, HIP report, saved credentials) and `SessionClock`.

- `Login` runs prelogin, portal getconfig and gateway login, answering the second-factor challenge, and returns an `AuthCookie`.
- `Session` is a pure state machine with an injectable clock. It reconnects with the same cookie on tunnel loss, dead peer, network change and wake, with capped backoff and no attempt limit; retries a failed HIP check on its own timer without touching the tunnel; rekeys when the gateway asks; and, with saved credentials, logs in again shortly before the cookie's lifetime ends. Only a rejected cookie ends a session.
- `SessionRunner` carries out the session's actions over the protocols above.
- `TunnelSettings` maps getconfig to routes, DNS and MTU, ready to become `NEPacketTunnelNetworkSettings`.

Protocol details follow openconnect's `gpst.c` and `auth-globalprotect.c`, which remain the reference.

## Diagnostics mode

With diagnostics mode on, the client keeps the last 10 minutes (2 to 30, configurable) of its session in memory: every input to and output of the session state machine, every HTTPS exchange, and per-second traffic counts. The setup exchanges (prelogin, login, getconfig) and the session's events are kept beyond the window. Passwords, HIP report bodies and packet contents are never recorded.

When the session has been out of `connected` for 60 s while awake with a usable network (so not during sleep or with Wi-Fi off), or it needs a login before the cookie's lifetime is over, it writes `albi-incident-DATE-N.json`, and rewrites it when the incident ends so it also shows the recovery. At most one file every 10 minutes; the newest 20 are kept. The file is redacted when written, with gp-capture's redactor plus a leak check: names, cookies, hosts and addresses become consistent test values that still parse.

- The app: Diagnostics mode toggle, Save diagnostics now, Show in Finder. The extension writes to `/Library/Application Support/Albi/Diagnostics/`.
- albi-cli: `--diagnostics DIR` (plus `--diag-grace` and `--diag-window` for tests); SIGUSR1 saves a file now.

Then:

```sh
swift build --product albi-diag
albi-diag check FILE --scrub YOUR-ORG   # look for anything the redaction missed; read the file too
albi-diag summary FILE                  # header and timeline
albi-diag replay FILE                   # feed the events into Session; checks the client logic reproduces
albi-diag scenario FILE --name "..."    # draft a gp-fake-gateway scenario
```

A redaction gap is a bug: file it rather than posting the file. Otherwise attach the file to an issue, draft a scenario, trim it to the smallest set of rules that still fails, and commit it to [gp-fake-gateway's scenarios/](https://github.com/njvack/gp-fake-gateway/tree/main/scenarios); `e2e/diagnostics.sh` runs albi-cli against every scenario there in CI.

## Trying it against the fake gateway

`e2e/client.sh` runs `albi-cli` against [gp-fake-gateway](https://github.com/njvack/gp-fake-gateway) with no root and no extension; CI runs it on macOS. By hand:

```sh
go run ./cmd/fakegp -listen 127.0.0.1:8443 -control 127.0.0.1:8444   # in gp-fake-gateway; prints the pin
printf 'test\n' | swift run albi-cli connect 127.0.0.1:8443 --user test --pin pin-sha256:... --second-factor 1 --ping 10.99.0.1
```

`albi-cli connect` also works against a real portal: drop `--pin` to use the system trust store, and add `--hip-wrapper /path/to/hipreport` if the gateway wants HIP reports. It never touches routes or DNS; it only proves login, HIP and the tunnel.

## Capturing a real gateway as fixtures

`gp-capture` records one session with your real portal and gateway, so tests can use what the gateway actually sends and we can read its timers (lifetime, rekey, idle), whether ESP works, and how it handles HIP. It runs openconnect, which already works against the gateway, so no albi code talks to it:

```sh
brew install openconnect     # if you don't have it
swift build --product gp-capture
.build/debug/gp-capture --hip-wrapper /path/to/hipreport --scrub "Your Org Name" vpn.example.edu
```

Disconnect any other VPN first. It asks for your user name, password and second-factor answer (`1` for a Duo push), runs `sudo openconnect --protocol=gp -v --dump-http-traffic` with a do-nothing `--script` (so routes, DNS and interface addresses are never touched), keeps the tunnel up for `--duration` seconds (default 120), then stops openconnect, which logs out. Ctrl-C ends it early the same way. If the portal lists several gateways, name one with `--gateway`. Options after `--` go to openconnect.

It writes `gp-capture-DATE/`:

- `raw/`: the unredacted log and `redactions.tsv`, the real-to-fake mapping. Keep these on your Mac; `gp-capture-*/` is in `.gitignore`.
- `fixtures/`: one `.request.form` and `.response.xml` per exchange, `index.tsv`, the rest of openconnect's log, and `summary.txt`.

In `fixtures/`, cookies, ESP keys and SPIs, HIP tokens, user, computer, domain, portal and gateway names, host names under your domains, e-mail addresses, IPv4 and IPv6 addresses, MAC addresses, certificates and phone numbers are replaced by consistent test values: the same cookie is the same fake everywhere, addresses keep their subnets (10.x stays 10.x, public networks move to 198.18.0.0/15 and up, IPv6 to 2001:db8::/32), and keys keep their length. The first label of your domain (`acme` in `vpn.acme.edu`), your Mac account name and its host name and every `--scrub` word are replaced wherever they appear. Afterwards it checks the fixtures for every value it learned and exits 2 if any remain. Free text it does not know about, such as a portal welcome page, is only scrubbed for those patterns, so read `fixtures/` before sharing it.

`summary.txt` holds only timers, counts and yes/no answers; it is safe to paste. To add a capture to the tests, copy `fixtures/` to `Tests/GPCoreTests/Fixtures/NAME/`: `FixtureTests` parses every exchange with GPCore and checks that albi's getconfig, HIP check and logout requests carry the same fields openconnect sent. `--from-log raw/openconnect.log` redoes the redaction without connecting again. `e2e/capture.sh` runs the whole thing against gp-fake-gateway; CI runs it on macOS.

## The app and extension (Step 1 test build)

Needs macOS 27, Xcode, [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`) and a Developer ID team.

1. In the Apple Developer portal, create App IDs for `com.github.njvack.albi` (System Extension and Network Extensions capabilities) and `com.github.njvack.albi.tunnel` (Network Extensions, plus an app group `<TEAMID>.com.github.njvack.albi`), and a Developer ID provisioning profile for each.
2. `cp Apps/Config/Signing.example.xcconfig Apps/Config/Signing.xcconfig` and fill in your team ID and profile names.
3. `cd Apps && xcodegen generate && open Albi.xcodeproj`, build the Albi scheme, and copy `Albi.app` to `/Applications` (system extensions only load from there). Bump `CURRENT_PROJECT_VERSION` for each rebuild you install, or macOS keeps the old extension.
4. Run it, click Activate and approve the extension in System Settings › General › Login Items & Extensions. Fill in the profile, Save (macOS asks to allow the VPN configuration), enter the password and Connect.

The extension logs under subsystem `com.github.njvack.albi`: `log stream --predicate 'subsystem == "com.github.njvack.albi"' --level info`.

What the test build is meant to settle: whether the extension (root, sandboxed) can keep the password and cookie in the System keychain; that traffic flows; that sleep, wake and Wi-Fi changes reconnect with the same cookie; that killing the extension (`sudo killall -9 com.github.njvack.albi.tunnel`) leaves no routes or DNS behind; and that the gateway accepts a HIP report. For HIP, set "HIP report command" to a csd-wrapper style reporter (this package's `hipreport`, the Go one, or `hipreport.zsh`); the app runs it when the extension asks.

## The menu-bar app (Phase 3, mock tunnel)

`AlbiApp` holds the menu-bar app: a `MenuBarExtra` menu with one icon per tunnel state, the login window (AutoFill username and password, a code step for profiles that ask each time), the setup checklist, the HIP compliance table, and Settings with profiles. Settings › General has "At launch": Connect, Don't connect, or Restore last state (the default), which reconnects unless the user's last choice was Disconnect. Diagnostics mode (Settings › General) turns on the extension's incident files; the app notifies when one is written and has Save Diagnostics Now and Show in Finder. It talks only to the `VPNService` protocol; `MockVPNService` implements it until the live one, over `NETunnelProviderManager` and provider messages, replaces it after Step 1.

To run it: `cd Apps && xcodegen generate && open Albi.xcodeproj`, choose the AlbiMenu scheme and Run. It is signed ad hoc, so it needs no team. The Demo submenu drops the connection or fails a HIP check. In the demo, Work has a saved password and sends a push; Lab asks for a password and a code, and rejects the password `wrong` and the code `000000`.

`swift test --filter AlbiAppTests` covers the view models on macOS.
