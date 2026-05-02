# go-openvpn3

Pure-Go OpenVPN3 client protocol implementation — AWS Client VPN + SAML/CRV1 flow.

Zero C dependencies. `CGO_ENABLED=0` builds a fully static binary.
`gomobile bind` produces an `.aar` for Android without NDK or CMake.

## Status

Working end-to-end on Linux (CLI + GTK4 GUI). Android gomobile API complete; `.aar` build
pipeline in `.github/workflows/aar.yml`.

### Components

| Component | Description |
|---|---|
| `cmd/daemon` | `openlawsvpn-daemon` — D-Bus session service; manages the VPN tunnel with CAP\_NET\_ADMIN (no root) |
| `cmd/ovpn3` | CLI client with SAML flow and reconnect loop |
| `gui-gtk/` | GTK4 + libadwaita desktop GUI; communicates with the daemon over D-Bus |

## Build

```bash
# Daemon
CGO_ENABLED=0 go build -o openlawsvpn-daemon ./cmd/daemon
# Grant CAP_NET_ADMIN so the daemon can open TUN devices without root:
sudo setcap cap_net_admin+eip ./openlawsvpn-daemon
./openlawsvpn-daemon &

# GTK4 GUI (requires gtk4-devel, libadwaita-devel, dbus-devel)
cd gui-gtk && cargo build --release
./target/release/openlawsvpn-gui

# Linux CLI (direct, no daemon)
CGO_ENABLED=0 go build -o ovpn3 ./cmd/cli
sudo ./ovpn3 -config your.ovpn

# Android .aar (requires gomobile + Android NDK)
gomobile bind -o go-openlawsvpn.aar -target android -androidapi 31 \
    github.com/openlawsvpn/go-openlawsvpn
```

### RPM packages (Fedora / RHEL)

```bash
make srpm    # builds openlawsvpn-*.src.rpm
make rpm     # builds binary RPMs via mock
```

Produces three sub-packages: `openlawsvpn-daemon`, `openlawsvpn-gui`, and
`openlawsvpn` (meta).

### Daemon D-Bus interface

The daemon exposes `com.openlawsvpn.Daemon` on the **session** bus:

| Method / Signal | Signature | Description |
|---|---|---|
| `Connect(path)` | `(s)` | Start VPN using the given `.ovpn` config |
| `Disconnect()` | `()` | Tear down the active tunnel |
| `Status()` | `→ (s,s,s,s)` | state, server\_ip, assigned\_ip, profile\_path |
| `StateChanged` | `(s,s,s)` | state, server\_ip, assigned\_ip |
| `LogLine` | `(s)` | Log message |
| `StatsUpdate` | `(t,t,t)` | bytes\_sent, bytes\_recv, uptime\_secs |
| `SAMLRequired` | `(s)` | SAML browser URL |

### DNS / polkit

The daemon sets per-interface DNS via `systemd-resolved`. The polkit rule in
`packaging/10-openlawsvpn-dns.rules` grants the daemon permission to call
`org.freedesktop.resolve1` methods without a password prompt.

## Test

```bash
# Unit tests (no network):
go test -race ./...

# Integration tests (runs local mock server — no Docker required):
go test -v -tags=integration -timeout 120s .
```

## CI / CD

| Workflow | Trigger | What it does |
|---|---|---|
| **CI** (`ci.yml`) | push / PR to `main` | `go build`, `go test -race`, `go vet` |
| **Build AAR** (`aar.yml`) | push tag `v*` or manual | builds `go-openlawsvpn.aar` via `gomobile bind`, publishes GitHub Release, notifies `openlawsvpn-android-go` to open a version-bump PR |

### Publishing a new release

```bash
git tag v0.2.0
git push origin v0.2.0
```

The `aar.yml` workflow builds the AAR, attaches it (with SHA-256) to the GitHub Release, then fires a `repository_dispatch` to `openlawsvpn-android-go` — which opens a PR bumping `goOpenvpn3Version` automatically.

**Required secret** in this repo: `ANDROID_GO_PAT` — a GitHub PAT with `repo` scope on `openlawsvpn/openlawsvpn-android-go`.

## Known limitations

### OpenVPN-PRF key derivation (plain OpenVPN 2.x)

AWS Client VPN always negotiates TLS-EKM (`key-derivation tls-ekm` in
PUSH_REPLY), so key derivation is fully correct for that use case.

Plain OpenVPN 2.x servers that do **not** push `key-derivation tls-ekm` use
the OpenVPN-PRF method, which requires the TLS `ServerRandom` (the 32-byte
random from the server's `ServerHello`). Go's `crypto/tls` does not expose
this value in `ConnectionState`, so the fallback path substitutes zeros. The
TLS handshake and authentication succeed, but the derived data-channel keys
will be wrong — packets fail to decrypt and no traffic flows.

No fix is possible without forking `crypto/tls`. Track the upstream Go
proposal if plain OpenVPN 2.x support without EKM becomes a requirement.

### SAML assertion is single-use

AWS Client VPN SAML assertions are cryptographically bound to the original
`AuthnRequest` ID. The server marks the assertion consumed on first use.
Retrying Phase 2 with the same token returns `AUTH_FAILED,Invalid username
or password` even within the token's TTL.

For reconnects: if the server's CRV1 session is still alive the client can
reconnect with the cached token. If the session has expired (`AUTH_FAILED`),
the user must complete the browser SAML flow again.

## License

Business Source License 1.1. Converts to MIT on 2031-01-01.
See [LICENSE](LICENSE) for details. Commercial use requires a separate license —
contact contact@openlawsvpn.com.
