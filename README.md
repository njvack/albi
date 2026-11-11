# Albi

A macOS client for Palo Alto GlobalProtect VPNs.

This repository is one Swift package plus, later, the Xcode project for the app, its packet tunnel extension and helper.

| Target | What |
| --- | --- |
| `HIPCore` | HIP report collection: check files, probes, report XML |
| `hipreport` | command-line HIP reporter, run by the app or the root helper |

## Build and test

```sh
swift build
swift test
```

`HIPCore` builds and tests on Linux as well as macOS; CI runs both.
