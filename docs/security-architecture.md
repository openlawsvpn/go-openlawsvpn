# Security Architecture: openlawsvpn

Version: 1.0  
Applies to: `go-openlawsvpn` — the Linux daemon/GUI stack  
License: LGPL-2.1-or-later

---

## Overview

openlawsvpn splits VPN management into two cooperating processes:

- **openlawsvpn-daemon** — a privileged Go binary that owns all network operations (TUN, routing, DNS, SAML ACS server). It runs as the logged-in user with a narrow set of Linux capabilities granted by the systemd user unit.
- **openlawsvpn-gui** — an unprivileged GTK4/Rust desktop application. It communicates with the daemon exclusively over the D-Bus session bus and holds zero extra privileges.

This document explains why the architecture is structured this way, what the privilege boundaries are, and what the design does and does not protect against.

---

## 1. Privilege Model

### 1.1 Why daemon + GUI instead of a single binary

A single-binary approach is technically possible on Linux: install the binary with `setcap cap_net_admin+ep` or add a polkit rule. Both approaches fail the least-privilege test.

**Attack surface of a monolithic privileged binary:**

A GTK4 GUI binary links, directly or transitively, against:
- GTK4, GLib, Pango, Cairo, GDK-Pixbuf
- libadwaita
- All Rust/Cargo crates in the GUI layer (image loading, SVG rendering, notification libraries, etc.)
- D-Bus client libraries

If `CAP_NET_ADMIN` is granted to that binary, every one of those code paths runs with the capability to open raw sockets, create TUN/TAP devices, manipulate routing tables, and configure network interfaces. A memory-safety bug anywhere in the UI rendering stack — an image parser, a font renderer, a CSS property — becomes a direct path to network-level access.

**The daemon boundary:**

The daemon is a small, auditable Go binary with no UI code. Its only external dependencies are:

- `github.com/godbus/dbus/v5` — D-Bus session bus client
- `github.com/openlawsvpn/go-openlawsvpn` — the VPN protocol engine

The VPN engine itself uses only the Go standard library and has `CGO_ENABLED=0`. There is no C runtime, no dynamic linking, and no image-processing or rendering code.

`CAP_NET_ADMIN` is confined to this binary. If the GUI is compromised — through a malicious plugin, a crafted profile icon, or a bug in the notification subsystem — the attacker gains the privileges of the logged-in user, not network administrator privileges.

**Analogy:** This mirrors how NetworkManager (privileged daemon) and nm-applet (unprivileged tray widget) are separated. nm-applet carries no capabilities; all netlink and D-Bus system bus operations are done by the daemon.

### 1.2 Capability scope

The daemon holds exactly one capability:

```
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
```

`CAP_NET_ADMIN` allows:
- Opening `/dev/net/tun` to create a TUN device
- `TUNSETIFF` ioctl to configure the device
- `RTM_NEWROUTE` / `RTM_DELROUTE` netlink calls to install and remove routes
- `RTM_NEWADDR` / `RTM_DELADDR` to assign the VPN-assigned IP to the TUN interface

No other capabilities are held or can be acquired. `NoNewPrivileges=true` prevents the daemon from exec-ing a setuid binary or gaining capabilities through any other mechanism.

### 1.3 DNS: a separate privilege boundary

DNS configuration (calling `resolvectl`) requires authorization from the system policy bus — this is a system-wide resource managed by `systemd-resolved`, not a per-user resource. The daemon calls `org.freedesktop.resolve1` D-Bus methods:

- `SetLinkDNS` — installs VPN-pushed DNS servers on the TUN interface
- `SetLinkDomains` — installs split-DNS search domains
- `RevertLink` — removes VPN DNS config on disconnect

These methods are guarded by polkit. The installed rule at `/etc/polkit-1/rules.d/10-openlawsvpn-dns.rules` grants these actions unconditionally to active (logged-in, seat-attached) sessions:

```javascript
polkit.addRule(function(action, subject) {
    var dns_actions = [
        "org.freedesktop.resolve1.set-dns-servers",
        "org.freedesktop.resolve1.set-domains",
        "org.freedesktop.resolve1.set-default-route",
        "org.freedesktop.resolve1.revert",
    ];
    if (dns_actions.indexOf(action.id) >= 0 && subject.active) {
        return polkit.Result.YES;
    }
});
```

The `subject.active` check ensures the rule only applies to a user with an active desktop session. Remote logins (SSH, headless systemd services) do not satisfy `is_active == true` and are therefore not authorized by this rule.

---

## 2. Why Not Polkit for Everything

A common alternative design is to use polkit for every privileged operation: each `connect()` call triggers a polkit challenge, the user approves, and a helper binary performs the operation. This is the approach used by `pkexec`.

### Reasons this design rejects that approach:

**Prompt fatigue and UX failure:**

polkit's `auth_admin_keep` caches authorization per-session, but only for actions performed by the logged-in user interactively. For a VPN client that reconnects automatically (e.g. after sleep/wake), every reconnect would prompt the user unless a persistent agent is already running. `auth_keep` caches only within a short window, not across sleep/wake or session re-login.

A systemd user unit holding capabilities requires zero user interaction after the unit is started. The unit starts at login via `WantedBy=default.target` and is already running when the user opens the GUI.

**Coarser granularity:**

polkit authorization is per-action. A VPN connection requires TUN creation, interface configuration, multiple route installs, and DNS setup — these are not a single polkit action; they happen inline during `connect()` as the PUSH_REPLY is parsed. Splitting these into polkit-authorized helper invocations would require a custom polkit action XML file and a setuid/pkexec helper binary, which is more code and a larger trusted-code surface than the daemon approach.

**What polkit IS used for:**

DNS configuration via `resolvectl` touches the system-resolved database, which is shared across all users and all network interfaces. Using polkit for this is correct: it is a system-wide resource, and the polkit rule enforces that only active sessions (i.e. the user sitting at the keyboard) can configure it. `CAP_NET_ADMIN` does not cover D-Bus calls to `org.freedesktop.resolve1`; those go through the system bus and are independently authorized.

---

## 3. Threat Model

### 3.1 Assets

| Asset | Location | Sensitivity |
|---|---|---|
| VPN profile (.ovpn) | `~/.local/share/openlawsvpn/*.ovpn` | High — contains CA cert, server endpoint |
| SAML token | In-memory only (daemon goroutine) | High — short-lived credential for VPN server |
| TUN device + routes | Kernel — destroyed on daemon exit | Medium — active session only |
| D-Bus session | Session bus | Low — same-UID access only |

### 3.2 Threat model table

| Threat | Attacker | Mitigated? | Mitigation |
|---|---|---|---|
| GUI compromise leading to network admin escalation | Local process that pwns the GUI | Yes | GUI holds no capabilities; `CAP_NET_ADMIN` lives only in the daemon |
| Profile file exfiltration | Local process running as the same UID | Partial | Profiles are mode 0600, owned by the user. Same-UID attacker can still read them. |
| SAML token theft | Local process running as the same UID | Yes | Token is never written to disk; lives only in the daemon goroutine's stack |
| SAML token theft via port 35001 race | Process that binds 35001 before the daemon | Mitigated by design | `NewACSServer()` binds 35001 before emitting `SAMLRequired`; if bind fails, connect is aborted |
| Malicious .ovpn profile routing traffic through attacker server | Attacker who can place a profile in the profile directory | No | Same as any VPN client; the user is responsible for profile provenance |
| D-Bus method call from another UID | Process running as a different user | Yes | Session bus enforces same-UID restriction at the kernel/dbus-daemon level |
| DNS hijacking via forged `SetLinkDNS` call | Local process running as the same UID | Partial | polkit `subject.active` check; a background process with the same UID but no active session cannot pass the polkit rule |
| Privilege escalation via daemon exec | Any local process | Yes | `NoNewPrivileges=true`; daemon cannot exec setuid or cap-bearing binaries |
| VPN server injecting malicious routes | Compromised VPN server | No | Daemon applies all PUSH_REPLY routes; route injection is a fundamental property of trusted VPN design |
| SAML token replay | Attacker who captures the SAML POST | Partial | AWS tokens are short-lived (minutes); the ACS server shuts down immediately after receiving the first valid response |
| GUI reading profile files directly | Same-UID local process | Yes | GUI never accesses profile files; it passes profile paths to the daemon via D-Bus; the daemon validates paths |

### 3.3 Explicit non-protections

The following are out of scope by design:

- **Same-UID process isolation.** The daemon trusts any process on the session bus that shares the user's UID. If the attacker already runs as the logged-in user (e.g. a malicious Flatpak with host D-Bus access), they can call `Connect()`, `Disconnect()`, and read `Status()`. This is the same trust model that NetworkManager, PulseAudio, and every other session D-Bus service uses.

- **Profile content validation.** The daemon parses profiles using the `profile` package (see `profile/profile.go`), which validates syntax but cannot determine whether a server endpoint is malicious. A profile that points to an attacker-controlled server will connect successfully. Profile management and provenance is outside the daemon's responsibility.

- **Kernel network namespace isolation.** The daemon does not use network namespaces or seccomp-BPF filtering. These could be added in a future hardening pass but are not part of v1.

---

## 4. Systemd Unit Hardening

The daemon runs as a systemd user service. The unit file is at `cmd/daemon/openlawsvpn-daemon.service`.

### 4.1 Capability directives

```ini
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
```

`AmbientCapabilities` causes the kernel to add `CAP_NET_ADMIN` to the ambient capability set of the daemon process. Because the daemon runs as a non-root user, ambient capabilities are the correct mechanism: file capabilities (setcap) on the binary would work too but require the binary to be installed with `cap_net_admin+ep`, which is a per-installation operation that is error-prone and complicates upgrades.

`CapabilityBoundingSet=CAP_NET_ADMIN` removes all other capabilities from the bounding set. This is the hard ceiling: even if the daemon calls `capset(2)` or exec-s another binary, it cannot acquire capabilities outside the bounding set. Combined with `NoNewPrivileges=true`, this makes the capability set immutable for the process lifetime.

### 4.2 Privilege drop directives

```ini
NoNewPrivileges=true
```

The process cannot gain new privileges via `execve`. This prevents the daemon from running a setuid helper or a binary with file capabilities.

### 4.3 Filesystem access restrictions

```ini
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=%h/.config/openlawsvpn
ConfigurationDirectory=openlawsvpn
```

- `ProtectSystem=strict` — mounts `/usr`, `/boot`, and `/etc` as read-only inside the daemon's mount namespace. The daemon cannot modify system files even if a bug allows arbitrary write.
- `ProtectHome=read-only` — the home directory tree is read-only. The only writable path is explicitly listed below.
- `PrivateTmp=true` — the daemon gets a private `/tmp` that is not shared with other processes.
- `ReadWritePaths=%h/.config/openlawsvpn` — the sole writable location is the daemon's own config directory (`~/.config/openlawsvpn`). Profile files are stored here.
- `ConfigurationDirectory=openlawsvpn` — systemd auto-creates `~/.config/openlawsvpn` with mode 0700 before the daemon starts. No code in the daemon needs to `mkdir` the config directory.

### 4.4 Effect on the daemon's syscall surface

The combination of `ProtectSystem=strict` and `ProtectHome=read-only` limits what a compromised daemon can do with its filesystem access. The daemon cannot:
- Overwrite shell rc files or `.bashrc` / `.profile`
- Write to `/etc/cron.d`, `/etc/sudoers.d`, or system service files
- Write to `/tmp` shared with other processes (private tmp)

It can write only to `~/.config/openlawsvpn`, which contains only its own profile data.

---

## 5. Port 35001: The SAML ACS Server

### 5.1 Why 35001 is fixed

AWS Client VPN hardcodes `AssertionConsumerServiceURL = http://127.0.0.1:35001` in the SAML SP metadata for every endpoint across all AWS regions and all supported IdPs (Okta, Azure AD, Google Workspace). This is not configurable. When the IdP posts the SAML assertion, it always posts to `http://127.0.0.1:35001/`.

### 5.2 Why the daemon owns port 35001, not the GUI

If the GUI owned port 35001:

1. The GUI process must be alive and listening during the SAML authentication flow — a GUI that is minimized, suspended by the compositor, or killed between `Connect()` and the browser callback would cause the SAML flow to fail silently.
2. The GUI would need to relay the SAML token to the daemon (an extra IPC round-trip with its own serialization and error handling).
3. The token would transit from the GUI process to the daemon process — two hop instead of one, with an additional window for interception.

By keeping the ACS server inside the daemon, the SAML token is received directly by the privileged process and passed as an in-memory string to the Phase 2 TLS session. It never crosses a process boundary and is never written to disk.

### 5.3 Port availability check and bind order

`saml.NewACSServer()` calls `net.Listen("tcp", "127.0.0.1:35001")` before emitting the `SAMLRequired` D-Bus signal. This means:

1. If port 35001 is already occupied (by another process or a previous connection that did not clean up), the connect attempt fails immediately with a `saml: ACS listen: bind: address already in use` error — before the browser is opened and before the user has started the SAML flow.
2. The early bind also closes the window for a race where a malicious process attempts to steal port 35001 between the moment the daemon decides to connect and the moment it actually listens. The listen call and the `SAMLRequired` signal emission are sequential in the same goroutine.

Since only one VPN connection is allowed at a time (a second `Connect()` call returns `com.openlawsvpn.Daemon.Busy`), port 35001 is held only for the duration of the SAML flow. It is released by `srv.Close()` immediately after the first valid `SAMLResponse` POST is received.

### 5.4 Residual risk: SAML token interception at the ACS port

A process that binds port 35001 before the daemon can intercept the browser POST and steal the SAML token. Mitigations:

- The daemon binds the port at the start of every connect attempt, minimizing the window between "connection starts" and "port is owned."
- Only one connection is allowed at a time. A previously failed connection releases the port before the next attempt begins.
- The token is a short-lived assertion: AWS IdP tokens typically expire within 5–10 minutes. An intercepted token is useful only for establishing a VPN session to the same AWS endpoint, not for broader account access.

This attack requires the attacker to already be running code as the logged-in user. At that point, the session is already compromised at a level that makes VPN token theft a secondary concern.

---

## 6. D-Bus Interface Security

### 6.1 Interface definition

The daemon exports the following interface on the session bus at `com.openlawsvpn.Daemon` / `/com/openlawsvpn/Daemon`:

**Methods:**

| Method | Signature | Description |
|---|---|---|
| `Connect` | `(profile_path: s) → ()` | Start a VPN connection for the given profile |
| `Disconnect` | `() → ()` | Cancel the active connection; no-op if idle |
| `Status` | `() → (state: s, server_ip: s, assigned_ip: s, profile_path: s)` | Read current state |

**Signals:**

| Signal | Signature | Description |
|---|---|---|
| `StateChanged` | `(state: s, server_ip: s, assigned_ip: s)` | Emitted on each state transition |
| `LogLine` | `(line: s)` | Daemon log messages forwarded to GUI |
| `StatsUpdate` | `(bytes_sent: t, bytes_recv: t, uptime_secs: t)` | Periodic traffic statistics (every 5 seconds while connected) |
| `SAMLRequired` | `(url: s)` | Emitted when the SAML browser flow must start; GUI opens URL in default browser |

### 6.2 Session bus access control

The D-Bus session bus enforces same-UID access by default. The dbus-daemon will not deliver messages between connections owned by different UIDs. No additional D-Bus policy file is required for this restriction — it is the default policy for the session bus.

Callers that share the logged-in user's UID (e.g. the GUI, a terminal, or any other desktop process) can call all methods. There is no per-caller authentication within the D-Bus interface; the daemon trusts all same-UID callers equally.

### 6.3 Path validation in Connect()

`Connect(profile_path)` calls `profile.ParsePath(profile_path)`, which calls `os.Open(profile_path)`. This opens whatever path the caller supplies, subject to the filesystem restrictions described in Section 4.3.

The daemon's mount namespace has `ProtectHome=read-only` with `ReadWritePaths=%h/.config/openlawsvpn`. Profile files are expected to live in `~/.local/share/openlawsvpn/` (managed by the GUI) or `~/.config/openlawsvpn/`. Paths outside the home directory are readable only if they are in world-readable locations (e.g. `/usr/share/`), which is intentional for shared corporate profiles.

A same-UID caller can pass an arbitrary path and cause the daemon to attempt to parse it as an `.ovpn` file. If the file is not a valid profile, `profile.ParsePath` returns an error and the connect is rejected. The daemon does not execute any content from the profile file; it only parses directives.

### 6.4 Single-connection enforcement

The daemon serializes all connection state behind a `sync.Mutex`. The check at the top of `Connect()`:

```go
d.mu.Lock()
if d.client != nil {
    d.mu.Unlock()
    return dbus.NewError(dbusInterface+".Busy", ...)
}
```

This prevents a race between two simultaneous `Connect()` calls. Because the session bus delivers method calls sequentially to a single goroutine (godbus dispatches to the registered handler on the connection's receive goroutine), the lock protects against both concurrent callers and a caller that calls `Connect` twice before the first goroutine has updated `d.client`.

---

## 7. Secret Handling

### 7.1 SAML tokens

SAML tokens (the `SAMLResponse` POST body) are handled as follows:

1. Received by the ACS HTTP handler in the daemon process.
2. Passed as a Go `string` return value from `ACSServer.Wait()` to `client.SAMLTokenFn`.
3. Passed to `connectPhase2()` which constructs the Phase 2 TLS username string in memory.
4. The username string is written to the TLS session and then goes out of scope. No explicit zeroization is performed (the Go GC is not guaranteed to zero memory).
5. The token is never logged (the daemon logs only `"saml: token received (len=%d)"`), never emitted as a D-Bus signal, and never written to disk.

The `SAMLRequired` signal emits only the SAML URL (from the server's CRV1 challenge), not the token. The token flows only: ACS handler → daemon goroutine → TLS session.

### 7.2 Profile private keys

Some .ovpn profiles include an inline `<key>` block (client private key for mutual TLS). The `profile.ParsePath()` function reads this into a `[]byte` field in the `Profile` struct in memory. It is:
- Never written to a file by the daemon
- Never emitted over D-Bus
- Passed directly to the Go `crypto/tls` stack as a `tls.Certificate`

The in-memory key material is subject to GC; Go does not provide a standard mechanism to zero-on-free for heap allocations.

### 7.3 Profile files on disk

Profile files are written by the GUI to `~/.local/share/openlawsvpn/`. The GUI is responsible for setting the file mode to 0600 (owner read/write only) on creation. The daemon reads profile files but does not set or check their mode — this is a known gap; a future version of `profile.ParsePath` should reject profiles with mode bits that allow group or world read.

---

## 8. Build and Dependency Security

### 8.1 Daemon binary: Go, no CGo

The daemon is built with `CGO_ENABLED=0`:

```bash
CGO_ENABLED=0 go build -o openlawsvpn-daemon ./cmd/daemon
```

This produces a fully static binary with no shared library dependencies. There is no C runtime, no `libc`, no `libssl`, and no dynamic linker. The attack surface from shared library substitution (e.g. `LD_PRELOAD`, `LD_LIBRARY_PATH` injection) is zero.

### 8.2 GUI binary: Rust + Cargo

The GUI is a Rust binary linking against GTK4/libadwaita via C FFI. It carries the full complexity of a GTK application. The GUI holds no Linux capabilities, so a supply-chain compromise of a Cargo crate affects only the unprivileged GUI process, not the daemon.

### 8.3 RPM packaging: no setcap in %post

The RPM `%post` scriptlet does not use `setcap` on the daemon binary. Capabilities are granted exclusively through the systemd unit's `AmbientCapabilities` directive. This means:

- The binary on disk has no file capability xattrs.
- Executing the binary outside of systemd (e.g. directly from a shell) will not grant it `CAP_NET_ADMIN` — it will simply fail when it tries to open `/dev/net/tun`.
- The capability grant is auditable through the systemd unit file rather than being encoded in a binary xattr that is invisible to `ls -la`.

---

## 9. Future Hardening Opportunities

The following mitigations are not currently implemented but are identified for future work:

- **Seccomp-BPF filter** — restrict the daemon to the syscall subset it actually uses (socket, ioctl, read, write, sendmsg, recvmsg, futex, clone). Would prevent exploitation of kernel vulnerabilities via unexpected syscalls.
- **Profile mode check** — `profile.ParsePath` should `os.Stat` the file and return an error if mode bits grant group or world read.
- **D-Bus policy file** — add a session bus policy file under `/usr/share/dbus-1/session.d/` that restricts `Connect()` to the binary at `/usr/libexec/openlawsvpn-gui` and explicit allowlist callers. This is defense-in-depth against other same-UID processes calling the daemon.
- **Token zeroization** — use a `sync.Pool`-backed byte slice for the SAML token and explicit `bytes.Fill` after use. The current `string` type makes zeroization impossible in standard Go.
- **Network namespace** — run the daemon in a restricted network namespace that only contains the loopback interface and the TUN device, preventing it from directly accessing host network interfaces beyond what it needs.
