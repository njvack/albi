# Albi

A macOS client for Palo Alto GlobalProtect VPNs.

This repository is one Swift package plus the Xcode project for the app. The app comes in two builds that share one menu-bar UI and differ in where the tunnel runs:

- **Extension**: `ExtensionApp` with `ExtensionTunnel`, a packet tunnel system extension. Needs a paid Developer ID team. Installs as `Albi Extension.app`, bundle ID `com.github.njvack.albi`.
- **Helper**: `HelperApp` with `albi-helper`, a root LaunchDaemon. No paid team needed. Installs as `Albi.app`, bundle ID `com.github.njvack.albi.helper`.

| Target | What |
| --- | --- |
| `HIPCore` | HIP report collection: check files, probes, report XML, the JSON summary |
| `hipreport` | command-line HIP reporter, run by the app or the root helper |
| `GPCore` | the GlobalProtect client core: login, getconfig, HIP check, GPST tunnel framing, the session state machine and its runner |
| `GPMac` | the macOS I/O layer: URLSession, NWConnection, NWPathMonitor, NetworkExtension glue, Keychain |
| `albi-cli` | command-line harness: logs in and runs the tunnel in userspace, pinging through it |
| `GPCapture`, `gp-capture` | records a real gateway session through openconnect as redacted test fixtures |
| `Diagnostics`, `albi-diag` | diagnostics mode: redacted incident files from the flight recorder, replay, and gp-fake-gateway scenario drafts |
| `AlbiApp` | the menu-bar app's SwiftUI scenes and view models, against the `VPNService` protocol, shared by both builds (macOS only) |
| `HelperBackend` | the helper build's `VPNService` over XPC to albi-helper, and its launch-at-login agent (macOS only) |
| `ExtensionBackend` | the extension build's `VPNService` over NETunnelProviderManager and provider messages (macOS only) |
| `albi-helper` | the root LaunchDaemon that runs the tunnel for the helper build, over XPC |
| `Apps/` | Xcode project (XcodeGen): `Apps/Extension/` (app and tunnel extension), `Apps/Helper/` (app and launchd plists), `Apps/Shared/` (icon and glyphs) |

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

Each `.toml` file describes one product in one HIP category: vendor, name, when to report it, and one probe per field, from a fixed set of probes. The built-in library ([`Sources/HIPCore/Library`](Sources/HIPCore/Library)) covers what ships with macOS, such as XProtect, Gatekeeper and FileVault, as ordinary check files. Sites add checks for their other products as root-owned files in `/Library/Application Support/Albi/checks.d`; [`contrib/`](contrib) has examples to start from. `--dev-checks DIR` loads untrusted checks for development.

[docs/check-files.md](docs/check-files.md) is the full reference: every key, the categories and their fields, what each probe does and gives on failure, load order and overrides, the trust rule, and how to write and test a check.

### Missing patches

The patch-management category's `<missing-patches>` lists what Software Update has pending, from `softwareupdate --list --no-scan` (the last background scan, so it is fast and needs no network). This is what GlobalProtect reports too: its OPSWAT SDK lists Software Update's pending updates, which is why the same list appears under every patch-management product on the firewall. Each entry's title is the `softwareupdate` label.

GP fills in `kb-article-id` with the number of Apple's security-content support article for the update (support.apple.com/149527 is Safari 27.2). We get it, and `info-url`, from the [SOFA](https://github.com/macadmins/sofa) v2 feeds for macOS and Safari, matching macOS updates by build and Safari by version. Feeds are fetched only when something is pending, cached under `/Library/Caches/Albi/sofa` (root) or `~/Library/Caches/Albi/sofa`, and refetched when over six hours old; if a fetch fails, a stale copy is used, and with none the IDs are left blank.

Severity uses OPSWAT's scale (0 low, 1 moderate, 2 important, 3 critical). The base is the severity in Apple's advisory (Low, Medium, High, Critical) when SOFA has one; otherwise macOS updates and anything needing a restart are 2 and the rest 1. A fix for an actively exploited CVE rates one higher. For the updates in a real GP report this gives the same numbers GP sent. `hipreport facts` shows the list, the feeds used, and why anything is missing.

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

`e2e/hipreport.sh` runs openconnect with `hipreport` as its `--csd-wrapper` against [gp-fake-gateway](https://github.com/njvack/gp-fake-gateway) (Linux, root). `scripts/parity.sh REFERENCE` compares the report with `hipreport.zsh` or the Go `hipreport` on a Mac, section by section (top-level fields, each category, custom checks), and prints a diff for each section that differs. CI runs all of these.

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

`albi-cli connect` also works against a real portal: drop `--pin` to use the system trust store, and add `--hip-wrapper /path/to/hipreport` if the gateway wants HIP reports. It never touches routes or DNS; it only proves login, HIP and the tunnel. If the portal and the gateway both ask for a second factor, `--gateway-only` logs in straight to the gateway (SERVER, or the `--gateway` address) so you answer once.

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

## Root helper probe

Albi may run its tunnel in a root LaunchDaemon instead of a Network Extension, which needs no paid Apple Developer account. Its rule: nothing it changes may outlive the process. `albi-netprobe` checks the assumptions behind that before the helper is built.

```sh
swift build --product albi-netprobe
e2e/netprobe.sh "$(swift build --show-bin-path)/albi-netprobe"                       # sudo; cuts the network for a few seconds
scripts/smappservice-probe.sh "$(swift build --show-bin-path)/albi-netprobe"          # ad-hoc signed
scripts/smappservice-probe.sh "$(swift build --show-bin-path)/albi-netprobe" "Apple Development"
```

`e2e/netprobe.sh` has `albi-netprobe up` make a utun, give it routes (full tunnel: 0/1 and 128/1; split: 10.99.0.0/16) and publish DNS as temporary dynamic-store keys, then answer DNS for the tunnel itself. While it's up the script checks that lookups reach the tunnel's DNS (every name for full tunnel, only `albi-probe.test` for split) and that a socket pinned to the physical interface still gets out. Then it stops the probe with SIGTERM or kill -9, and checks that the utun, its routes, the DNS servers, the dynamic-store keys and the default route are back as they were. The probe has no cleanup code. CI runs it.

`scripts/smappservice-probe.sh` wraps the probe in a tiny app, signs it ad-hoc or with the given identity, and registers a LaunchDaemon with `SMAppService`. It checks that the daemon ran as root, then unregisters it.

## The extension build

Needs macOS 27, Xcode, [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`) and a Developer ID team.

1. In the Apple Developer portal, create App IDs for `com.github.njvack.albi` (System Extension and Network Extensions capabilities) and `com.github.njvack.albi.tunnel` (Network Extensions, plus an app group `<TEAMID>.com.github.njvack.albi`), and a Developer ID provisioning profile for each.
2. `cp Apps/Config/Signing.example.xcconfig Apps/Config/Signing.xcconfig` and fill in your team ID and profile names.
3. `cd Apps && xcodegen generate && open Albi.xcodeproj`, build the ExtensionApp scheme, and copy `Albi Extension.app` to `/Applications` (system extensions only load from there). Bump `CURRENT_PROJECT_VERSION` for each rebuild you install, or macOS keeps the old extension.
4. Run it. The setup window has Install (approve the extension in System Settings › General › Login Items & Extensions) and Allow (macOS asks once to allow VPN configurations). Then add a profile in Settings and Connect from the menu.

It is the same menu-bar app as the helper build (below), over `ExtensionVPNService` in `ExtensionBackend`. Each profile is its own VPN configuration in System Settings › VPN, named after the profile. While a tunnel runs, the app polls the extension with provider messages for status, and answers its HIP requests (with the `albi-hipreport` in the app's `Contents/MacOS`, run as you, so root-only checks report n/a) and second-factor prompts. The extension keeps passwords and cookies in the System keychain; the app can't read them, so it remembers which profiles it handed a saved password to, and forgets when the extension says a login is needed. Configurations saved by the Step 1 test build are picked up as profiles.

The extension logs under subsystem `com.github.njvack.albi`: `log stream --predicate 'subsystem == "com.github.njvack.albi"' --level info`.

Still to settle on a real Mac: whether the extension (root, sandboxed) can keep the password and cookie in the System keychain; that traffic flows; that sleep, wake and Wi-Fi changes reconnect with the same cookie; that killing the extension (`sudo killall -9 com.github.njvack.albi.tunnel`) leaves no routes or DNS behind; and that the gateway accepts a HIP report.

The extension also carries its own sandboxed `hipreport` in `Contents/MacOS`, signed with it, so the report can come from a binary the user can't swap. A profile with `bundledHIP` set uses it instead of asking the app; the shared UI has no switch for that yet, and the Step 1 window's "Bundled hipreport" probe went away with that window (the `probeBundledHIP` provider message is still there).

## The menu-bar app and the helper build

`AlbiApp` holds the menu-bar app: a `MenuBarExtra` menu with one icon per tunnel state, the login window (AutoFill username and password, a code step for profiles that ask each time), the setup checklist, the HIP compliance table, and Settings with profiles. Settings › General has "At launch": Connect, Don't connect, or Restore last state (the default), which reconnects unless the user's last choice was Disconnect. Diagnostics mode (Settings › General) turns on incident files; the app notifies when one is written and has Save Diagnostics Now and Show in Finder. It talks only to the `VPNService` protocol, so both builds share it.

The HelperApp scheme builds the app with its tunnel in `albi-helper`, a root LaunchDaemon in `Contents/MacOS`, so it needs no paid Apple Developer account. The app registers it with `SMAppService` (setup item "Approve the Albi helper") and talks to it over XPC (`HelperVPNService` in `HelperBackend`, Mach service `com.github.njvack.albi.helper.daemon`). The helper keeps the profiles in `/Library/Application Support/Albi/profiles.json`, passwords and cookies in the System keychain, and runs the tunnel through `TunnelController` (shared with the packet tunnel extension) over `UtunHost`. It sweeps journaled routes when it starts, and `helper-state.json` records whether you want to be connected, so after a crash or a reboot launchd's KeepAlive brings it back connected. Quitting the app disconnects (the app is the VPN's only UI), but unlike Disconnect it leaves Restore last state to reconnect at the next launch. Launch at Login is a LaunchAgent in the app's bundle, so launchd also restarts the app if it crashes; when the app goes away without quitting, the helper keeps the tunnel up for 60 seconds for it to come back, then disconnects. The helper makes HIP reports with the `albi-hipreport` in the app's bundle, as root, so root-only checks work.

Upgrading from `Albi Menu.app` (before the helper build moved under `com.github.njvack.albi.helper`): in the old app, turn off Launch at Login, then quit it and run `sudo launchctl bootout system/com.github.njvack.albi.helper` so the old daemon lets go of the utun. Delete `/Applications/Albi Menu.app`, and remove any leftover "Albi Menu" entries under System Settings › General › Login Items & Extensions (`sfltool resetbtm` clears them all, for every app, if they won't go). Profiles in `/Library/Application Support/Albi` carry over. Saved passwords should too (same keychain service); if the new helper can't read one, the login window asks for it again. App settings such as "At launch" start from their defaults, since they belonged to the old bundle ID.

To run it:

```sh
cd Apps && xcodegen generate
xcodebuild -project Albi.xcodeproj -scheme HelperApp -configuration Debug -derivedDataPath build build
rm -rf /Applications/Albi.app && cp -R build/Build/Products/Debug/Albi.app /Applications/
open /Applications/Albi.app
```

Then click Approve… in the setup window, turn Albi on under System Settings › General › Login Items & Extensions › Allow in the Background, and add a profile in Settings. The app signs ad hoc by default; launchd records the helper's signature when it's registered, so after a rebuild the setup window says the helper needs reinstalling (one click, and possibly the System Settings toggle again). Signing with a free Apple Development certificate avoids that: see `Apps/Config/Signing.example.xcconfig`.

- `/Applications/Albi.app/Contents/MacOS/albi-helper status` prints the running helper's build and status.
- Logs: `log stream --predicate 'subsystem == "com.github.njvack.albi"' --level info`.
- `sudo launchctl print system/com.github.njvack.albi.helper.daemon` shows launchd's view of it.

Launched with `-demo YES` (`open Albi.app --args -demo YES`), the app runs against `MockVPNService` instead, with a Demo submenu that drops the connection or fails a HIP check. In the demo, Work has a saved password and sends a push; Lab asks for a password and a code, and rejects the password `wrong` and the code `000000`.

`swift test --filter 'AlbiAppTests|HelperBackendTests'` covers the view models and the helper mapping on macOS.
