# Albi

A macOS client for Palo Alto GlobalProtect VPNs.

This repository is one Swift package plus, later, the Xcode project for the app, its packet tunnel extension and helper.

| Target | What |
| --- | --- |
| `HIPCore` | HIP report collection: check files, probes, report XML, the JSON summary |
| `hipreport` | command-line HIP reporter, run by the app or the root helper |

## Build and test

```sh
swift build
swift test
```

`HIPCore` builds and tests on Linux as well as macOS; CI runs both.

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

Each `.toml` file describes one product in one HIP category. The built-in library in [`Sources/HIPCore/Library`](Sources/HIPCore/Library) is compiled into the binary (`scripts/gen-library.sh` regenerates `BuiltinLibrary.swift`; a test fails if they drift), so the binary's code signature covers it. Apple's XProtect, Gatekeeper and FileVault are ordinary check files there.

```toml
# anti-malware/10-apple-xprotect.toml
category = "anti-malware"
vendor = "Apple Inc."
name = "Xprotect"
when.exists = "/Library/Apple/System/Library/CoreServices/XProtect.bundle"   # report only if installed

[fields]
version = { probe = "bundle_version", path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle" }
defver = { probe = "bundle_version", path = "/Library/Apple/System/Library/CoreServices/XProtect.app" }
updated = { probe = "mtime", path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist" }
real-time-protection = { value = "yes" }
```

Checks load from the built-in library, then each `--checks-dir DIR` (default `/Library/Application Support/Albi/checks.d`), then each `--dev-checks DIR`. A file replaces one with the same relative path in an earlier source, and `disabled = true` removes one. Within a category, products are listed by file name.

Files in a `--checks-dir` are refused unless the file and every directory above it are owned by root and writable by nobody else (group-writable only for group wheel), the way `sudo` treats `sudoers`. Symlinks are followed and held to the same rule. `--dev-checks` skips that, for writing new checks, and marks the result untrusted.

| Category | Fields (* required) |
| --- | --- |
| `anti-malware` | `version`*, `real-time-protection`*, `defver`, `engver`, `updated` (Unix time), `last-full-scan-time` (default `n/a`) |
| `disk-backup` | `version`*, `last-backup-time` (default `n/a`) |
| `disk-encryption` | `version`*, `drives`* (the `volumes` probe) |
| `firewall` | `version`*, `is-enabled`* |
| `patch-management` | `version`*, `is-enabled`* |
| `data-loss-prevention` | `version`* |
| `custom-plist` | no fields; `path` and `keys` for a custom plist check configured on the gateway |

Each field is either `{ value = "..." }` or one probe. Check files cannot run code except through `command`.

| Probe | Parameters | Gives |
| --- | --- | --- |
| `bundle_version` | `path` | `CFBundleShortVersionString` of an app or bundle, or empty |
| `plist` | `path`, `key` (dotted for nested keys) | one value from a plist, XML or binary |
| `mtime` | `path` | modification time, as a Unix time |
| `exists` | `path` | `yes` or `no` |
| `process` | `path` | `yes` if that executable is running |
| `launchd` | `label` such as `system/com.example.d` or `gui/com.example.agent` | `yes` if loaded; `gui/` means the current user's session |
| `command` | `argv` (absolute path), `map` (list of `{ match = "regexp", value = "..." }`), optional `default` and `timeout` (seconds) | the value of the first `map` entry matching stdout, else `default` (`n/a`). Runs with `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, no stdin, stderr discarded, 10 s timeout |
| `volumes` | | FileVault state of the boot volume, its Data volume and browsable internal disks, plus `All` |
| `os_version` | | `sw_vers -productVersion` |
| `privileged` | `fact`: `pf.enabled` | a fact only root can read; `n/a` otherwise |
| `all` | `all`: a list of probes | `yes` if every one is `yes`, `no` if any is `no`, else `n/a` |

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
