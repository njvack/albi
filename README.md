# Albi

A macOS client for Palo Alto GlobalProtect VPNs.

This repository is one Swift package plus, later, the Xcode project for the app, its packet tunnel extension and helper.

| Target | What |
| --- | --- |
| `HIPCore` | HIP report collection: check files, probes, report XML |
| `hipreport` | command-line HIP reporter, run by the app or the root helper |
| `GPCore` | the GlobalProtect client core: login, getconfig, HIP check, GPST tunnel framing, the session state machine and its runner |

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
