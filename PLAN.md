# go-openvpn3 daemon — implementation plan

## Goal

Replace the openvpn3-linux system daemon (OpenVPN Inc, C++) with a pure Go
daemon built on go-openvpn3. The GUI (`openlawsvpn/gui-gtk`) talks D-Bus to this
daemon instead of the C++ libopenlawsvpn FFI. Zero C/C++ dependency in the
final stack.

## Architecture

```
[gui-gtk  Rust + GTK4]  ←── D-Bus ──→  [openlawsvpn-daemon  Go]
                                              │
                                        [go-openvpn3 client.go]
                                              │
                                        [Linux TUN / netlink / DNS]
```

The daemon runs as a **systemd user service** with `AmbientCapabilities=CAP_NET_ADMIN`.
The GUI is an unprivileged user process. No Polkit, no setuid, no root required.

## D-Bus interface

Bus:      session bus  
Service:  `com.openlawsvpn.Daemon`  
Object:   `/com/openlawsvpn/Daemon`  
Interface: `com.openlawsvpn.Daemon`

### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `Connect` | `(profile_path: s) → ()` | Start connection for the given .ovpn path |
| `Disconnect` | `() → ()` | Graceful disconnect |
| `Status` | `() → (state: s, server_ip: s, assigned_ip: s)` | Current state snapshot |

### Signals

| Signal | Signature | Description |
|--------|-----------|-------------|
| `StateChanged` | `(state: s, server_ip: s, assigned_ip: s)` | Emitted on every state transition |
| `LogLine` | `(line: s)` | One log line forwarded from the VPN client |
| `StatsUpdate` | `(bytes_sent: t, bytes_recv: t, uptime_secs: t)` | Periodic traffic stats (every 5 s while connected) |
| `SAMLRequired` | `(url: s)` | Browser URL for the SAML flow; GUI opens it |

### State strings

`idle` · `connecting` · `waiting_saml` · `connected` · `disconnecting` · `error`

## Repository layout (new files)

```
go-openvpn3/
  PLAN.md                    ← this file
  event.go                   ← EventType, Event, EventFn (new)
  client.go                  ← add EventFn field + emit calls (modified)
  cmd/
    ovpn3/                   ← unchanged
    daemon/
      main.go                ← D-Bus daemon entry point
      service.go             ← DaemonService struct, D-Bus interface impl
      service_test.go        ← unit tests with mock client
      openlawsvpn-daemon.service  ← systemd user unit
  packaging/
    openlawsvpn.spec         ← RPM spec (daemon + gui subpackages)
```

## Task checklist

- [x] Write PLAN.md
- [x] `event.go` — add `EventType`, `Event`, `EventFn` types
- [x] `client.go` — add `EventFn` field, emit events from state transitions
- [x] `cmd/daemon/service.go` — `DaemonService`, D-Bus methods/signals
- [x] `cmd/daemon/main.go` — entry point, godbus registration, signal loop
- [x] `cmd/daemon/service_test.go` — unit tests with mock client
- [x] `cmd/daemon/openlawsvpn-daemon.service` — systemd user unit
- [x] `packaging/openlawsvpn.spec` — RPM spec
- [x] `openlawsvpn/gui-gtk` — replace `vpn_service.rs` FFI with D-Bus proxy
- [x] `openlawsvpn/gui-gtk` — update `Cargo.toml` / `build.rs`

## GUI migration (openlawsvpn/gui-gtk)

Only `vpn_service.rs` changes. Everything else — `main.rs`, `connection/`,
`log_view.rs`, `tray.rs`, `profile_store.rs`, `saml_server.rs` — is untouched.

`VpnEvent`, `VpnState`, `VpnCommand` types are preserved exactly; the internal
implementation switches from C FFI (`spawn_blocking` + unsafe FFI calls) to
zbus D-Bus proxy calls and signal subscriptions.

`saml_server.rs` moves to the daemon side; the GUI no longer needs to run the
ACS server on :35001. The daemon runs it and emits `SAMLRequired` when the URL
is ready. (The ACS server in `auth/saml` is reused directly.)

`build.rs` loses the bindgen dependency entirely. `Cargo.toml` drops `bindgen`
from `[build-dependencies]`.

## Privilege model

```
/usr/libexec/openlawsvpn-daemon   owned root:root, mode 0755
~/.config/systemd/user/openlawsvpn-daemon.service
  AmbientCapabilities=CAP_NET_ADMIN
  CapabilityBoundingSet=CAP_NET_ADMIN
```

No setuid. No Polkit. The user enables the service once at install:
```
systemctl --user enable --now openlawsvpn-daemon
```

## RPM packaging

Two subpackages built from a single spec:

- `openlawsvpn-daemon` — Go binary + systemd unit + D-Bus service activation file
- `openlawsvpn-gui` — Rust binary + .desktop + icon

`%post` for `openlawsvpn-daemon` runs `systemctl --user daemon-reload` (best-effort).

## Notes

- The SAML ACS server (:35001) runs inside the daemon, not the GUI.
- Stats polling: daemon emits `StatsUpdate` every 5 s while connected.
- The daemon accepts only one active connection at a time; a second `Connect`
  call while connected is rejected with a D-Bus error.
- godbus/dbus/v5 is added as a Go dependency.
