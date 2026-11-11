# Check files

`hipreport` builds the HIP report from check files. Each check file is a TOML file describing one product in one HIP category: who makes it, when to report it, and how to find each value the gateway expects for that category. This page is the full reference for the format. The code that defines it is [`Check.swift`](../Sources/HIPCore/Check.swift) (parsing and validation), [`Category.swift`](../Sources/HIPCore/Category.swift) (categories and their fields) and [`Eval.swift`](../Sources/HIPCore/Eval.swift) (what each probe does).

## An example

```toml
# anti-malware/10-apple-xprotect.toml
category = "anti-malware"
vendor = "Apple Inc."
name = "Xprotect"
when.exists = "/Library/Apple/System/Library/CoreServices/XProtect.bundle"

[fields]
version = { probe = "bundle_version", path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle" }
defver = { probe = "bundle_version", path = "/Library/Apple/System/Library/CoreServices/XProtect.app" }
updated = { probe = "mtime", path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist" }
real-time-protection = { value = "yes" }
```

This reports XProtect under anti-malware if its bundle exists. It reads two version strings from Info.plist files, uses a file's modification time as the update date, and always reports real-time protection as on.

## Top-level keys

| Key | Type | Meaning |
| --- | --- | --- |
| `category` | string, required | One of the categories below, or `custom-plist`. |
| `vendor` | string, required except for `custom-plist` | Sent as the product's `vendor` attribute. Match what the official client sends, since gateway policies match on it. |
| `name` | string, required except for `custom-plist` | Sent as the product's `name` attribute. Same caveat. |
| `when.exists` | string or array of strings | Absolute paths. The product is reported only if every one exists. Leave it out to always report the product. |
| `disabled` | boolean | `true` removes the check. Used to switch off a check from an earlier source (see Loading). A disabled file is not validated. |
| `[fields]` | table | One entry per field, keyed by field name. Not used by `custom-plist`. |
| `path` | string | `custom-plist` only: the plist to read. |
| `keys` | array of strings | `custom-plist` only: the keys to report. |

Any other key is an error, as is a value of the wrong type. `hipreport lint` reports these.

## Categories and fields

Categories, their fields, and the order they appear in the report are fixed in code, because the gateway expects exactly these. A field marked required must be in `[fields]`; an optional field that is left out gets the default shown, or is empty.

| Category | Field | Required | Notes |
| --- | --- | --- | --- |
| `anti-malware` | `version` | yes | |
| | `real-time-protection` | yes | `yes` or `no` |
| | `defver` | | definitions version |
| | `engver` | | engine version |
| | `updated` | | a Unix time (as `mtime` gives); reported as month, day and year in the `<Prod>` attributes |
| | `last-full-scan-time` | | default `n/a` |
| `disk-backup` | `version` | yes | |
| | `last-backup-time` | | default `n/a` |
| `disk-encryption` | `version` | yes | |
| | `drives` | yes | must use the `volumes` probe, and only this field may |
| `firewall` | `version` | yes | |
| | `is-enabled` | yes | `yes`, `no` or `n/a` |
| `patch-management` | `version` | yes | |
| | `is-enabled` | yes | `yes`, `no` or `n/a` |
| `data-loss-prevention` | `version` | yes | |

A field the category does not have is an error. Within a category, products are reported in file-name order, which is why library files start with a number.

### custom-plist

The gateway can be configured to ask for keys from a plist ("custom checks"). A `custom-plist` check answers one of those:

```toml
category = "custom-plist"
path = "/Applications/QualysCloudAgent.app/Contents/MacOS/com.qualys.cloud.agent-restart.plist"
keys = ["Label"]
```

The report says whether the file exists, and for each key whether it exists and its value. `path` must be absolute. `vendor`, `name` and `[fields]` are not used.

## Fields

Each entry in `[fields]` is a table that is either a constant or one probe:

```toml
real-time-protection = { value = "yes" }
version = { probe = "os_version" }
```

Giving both `value` and `probe` is an error, as is giving a parameter the probe does not take.

## Probes

Probes are a fixed set. A check file cannot run code except through `command`, which only runs an absolute path, with a fixed environment and a timeout. Every path a probe takes must be absolute.

When a probe cannot find its value it still gives a result: an empty string, `n/a`, or `unknown` as noted. It also records why, which `hipreport facts` shows.

| Probe | Parameters | Gives | On failure |
| --- | --- | --- | --- |
| `bundle_version` | `path` to an app or bundle | `CFBundleShortVersionString` from `path/Contents/Info.plist` | empty |
| `plist` | `path`, `key` | the value at `key`, from an XML or binary plist. Dots in `key` step into nested dictionaries (`a.b.c`). Strings and numbers are given as text, booleans as `true` or `false`, and dates in ISO 8601 UTC. | empty if the file, the key, or a scalar value is missing |
| `mtime` | `path` | the file's modification time, as a Unix time in seconds | empty |
| `exists` | `path` | `yes` if the path exists, else `no` | |
| `process` | `path` | `yes` if a running process has exactly that executable path (from libproc's `proc_pidpath`), else `no` | |
| `launchd` | `label` with a domain: `system/com.example.daemon` or `gui/com.example.agent` | `yes` if `launchctl print` finds it loaded, else `no`. `gui/` is the session of the user hipreport runs as. | |
| `command` | `argv` (array; the first element an absolute path), `map`, optional `default`, optional `timeout` | runs the command and gives the `value` of the first `map` entry whose `match` regular expression matches anywhere in stdout | `default`, or `n/a` if no default |
| `volumes` | none | FileVault state per volume; see below. Only for `disk-encryption`'s `drives`. | an `All` entry of `unknown` |
| `os_version` | none | the macOS version from `ProcessInfo`, formatted like `sw_vers -productVersion`, such as `27.1` | empty |
| `privileged` | `fact` | a fact only root can read. The only fact so far is `pf.enabled` (`pfctl -s info`). | `n/a` when not running as root |
| `all` | `all`: an array of probe tables | `yes` if every probe gives `yes`, `no` if any gives `no`, otherwise `n/a`. Can't contain `all` or `volumes`. | |

### command

```toml
real-time-protection = { probe = "command", argv = ["/usr/sbin/spctl", "--status"], map = [
  { match = "assessments enabled", value = "yes" },
  { match = "assessments disabled", value = "no" },
] }
```

- The command runs with `PATH=/usr/bin:/bin:/usr/sbin:/sbin` and no other environment, with no stdin. Its stderr is thrown away.
- `timeout` is in seconds and defaults to 10. A command that times out or can't start gives `default`.
- The exit status is ignored, except in the reason `facts` gives. Only stdout is matched.
- `map` entries are tried in order, so put the more specific pattern first. The firewall check matches `disabled` before `enabled|blocking` for this reason.
- `match` is an ICU regular expression (`NSRegularExpression`). It is case-sensitive unless it starts with `(?i)`.
- Each distinct `argv` runs once per report, even if several checks use it.

### volumes

`volumes` reads the mount table with `getfsstat`, keeps the local volumes, and asks Foundation for each one's name, internal flag and encryption:

- `/` is named after its volume name, such as `Macintosh HD`.
- `/System/Volumes/Data` is named `Data`.
- Under `/Volumes`, it includes internal disks that aren't marked `nobrowse`, named by mount point. External disks are skipped.

Each one is `encrypted` or `unencrypted` according to the volume's `volumeIsEncrypted` resource value, or `unknown` if the system doesn't say. A final `All` entry is `unencrypted` if any volume is, else `unknown` if any is or no volume was found, else `encrypted`. Policies usually test `All`.

### Native APIs and shell commands

hipreport uses public frameworks where they exist, and runs a command only where macOS has no public API for the answer.

| What | How |
| --- | --- |
| files, plists, bundle versions, modification times | Foundation (`FileManager`, `PropertyListSerialization`) |
| `os_version` | `ProcessInfo.operatingSystemVersion` |
| `process` | libproc: `proc_listallpids`, `proc_pidpath` |
| `volumes` | `getfsstat` for the mount table (`FileManager.mountedVolumeURLs` skips the hidden Data volume), then the volume name, internal and encrypted URL resource values |
| network interfaces in the report's host info | SystemConfiguration (`SCNetworkInterfaceCopyAll`, burned-in MACs), `getifaddrs` for addresses |
| `launchd` | `launchctl print`: `SMJobCopyDictionary` is deprecated, and `SMAppService` only covers the app's own jobs |
| `pf.enabled` | `pfctl -s info`: the `/dev/pf` ioctl structures aren't in the SDK |
| Gatekeeper, application firewall, automatic updates (built-in check files) | `command` probes running `spctl --status`, `socketfilterfw --getglobalstate` and `softwareupdate --schedule`; none has a public status API |

Fixtures from `hipreport record` store the native answers. Older fixtures, and ones shared with the Go reporter, store the commands the reporters used to run (`sw_vers`, `ps`, `mount` and `diskutil`, `networksetup` and `ifconfig`). When a fixture has no native answer, hipreport works it out from those commands.

## Where checks come from

Checks are loaded from these sources, in order:

1. The built-in library, which ships with hipreport. It covers only what comes with macOS: XProtect, Gatekeeper, Time Machine, FileVault, the application firewall, Packet Filter and Software Update. It lives in [`Sources/HIPCore/Library`](../Sources/HIPCore/Library), with one directory per category.
2. Each `--checks-dir DIR`, by default `/Library/Application Support/Albi/checks.d`.
3. Each `--dev-checks DIR`.

Checks for third-party products belong to each site, installed into `checks.d` with the rest of its Mac management. [`contrib/`](../contrib) holds examples that sites can copy or adapt: Cisco Secure Endpoint, Google Drive, Workspace ONE, Qualys and Microsoft AutoUpdate. hipreport doesn't load them unless they're installed.

A check's ID is its path relative to its source, such as `firewall/20-openbsd-pf.toml`. A file in a later source replaces the earlier file with the same ID. To switch off a built-in check on one Mac, put a file containing only `disabled = true` at the same relative path in `checks.d`. To add a product, add a new file.

Files in a `--checks-dir` are refused unless the file and every directory above it are owned by root and writable only by root. Group write is allowed only for group wheel (gid 0). This is the same rule `sudo` applies to `sudoers`. Symlinks are followed and the target has to meet the same rule. One bad file is reported and skipped, and the rest still load. If the directory itself fails the rule, all of it is skipped.

`--dev-checks` skips the ownership rule, so you can work on checks as a normal user. A report built with it is marked untrusted, and hipreport warns about that on stderr.

## Writing and testing a check

1. Put the new file in a scratch directory with the same layout, such as `~/checks/firewall/30-example.toml`.
2. `hipreport lint ~/checks/firewall/30-example.toml` checks the syntax, keys, category, fields and probe parameters.
3. `hipreport facts --dev-checks ~/checks` shows every product with each field's value and the probe behind it. When a probe falls back, it also shows why. Add `--json` for the same thing as JSON.
4. `hipreport --dev-checks ~/checks --cookie 'user=me&domain=x&computer=y' --md5 x` prints the XML report.
5. To deploy it, install it root-owned into `checks.d`, for example in a package pushed by MDM. If other sites could use it, add it to `contrib/`.

`hipreport record > mac.toml` captures everything the probes read on this Mac. `--fixture mac.toml` replays that capture, so you can run checks against another Mac's state. A capture contains that Mac's host name and MAC and IP addresses.
