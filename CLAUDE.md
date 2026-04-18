# Claude context for go-openvpn3

## What this repo is

A pure Go implementation of the OpenVPN3 client protocol — the same protocol
used by openvpn3-core (C++). The goal is to replace the C++/JNI/NDK dependency
in `openlawsvpn-android` and `openlawsvpn` (Linux CLI) with a fully static Go
library that `go build` / `gomobile bind` can produce without any C toolchain.

This is a long-term foundational project. It is NOT a fork or wrapper of
openvpn3-core — it is a clean-room Go implementation based on the OpenVPN
protocol specification and openvpn3-core source as a reference.

## Parent project context

**openlawsvpn** is an open-source AWS Client VPN client with SAML/SSO support.
- Linux CLI: https://github.com/openlawsvpn/openlawsvpn (C++, LGPL-2.1)
- Android app: https://github.com/openlawsvpn/openlawsvpn-android (Kotlin+JNI)
- Website: https://openlawsvpn.com

The current C++ stack: openvpn3-core (AGPL-3.0) + libopenlawsvpn (LGPL-2.1).
This repo replaces the openvpn3-core dependency.

## Why Go

- `CGO_ENABLED=0` — fully static binary, zero native dependencies
- `gomobile bind` — produces `.aar` for Android without NDK/CMake
- Single codebase covers Linux CLI, Android, future iOS
- F-Droid compatible — no prebuilt blobs, `./gradlew assembleRelease` is self-contained
- Easier auditing, fuzzing (`go test -fuzz`), and contribution

## Goals (in priority order)

1. **Correctness over completeness** — every packet exchange must be byte-exact
   with what openvpn3-core expects. The mock server (Phase 1) is the oracle.
2. **Replace libopenlawsvpn** — the public API must match the existing C API
   surface (`clientNew`, `clientConnectPhase1`, `clientConnectPhase2`,
   `clientDisconnect`, `clientFree`, callbacks for tun/protect/log).
3. **Android via gomobile** — `gomobile bind` produces an `.aar` that drops into
   `openlawsvpn-android` with no NDK changes.
4. **Linux static binary** — `CGO_ENABLED=0 go build` produces a binary with
   zero runtime dependencies.
5. **F-Droid compatibility** — no download-at-build-time, no prebuilt blobs.

## Non-goals

- OpenVPN server implementation
- OpenVPN 2.x legacy static-key mode
- Windows support
- WireGuard or other protocols

## SAML / CRV1 flow (the AWS-specific part)

AWS Client VPN uses a non-standard SAML challenge called CRV1:

```
Phase 1:
  Client → Server: TLS ClientHello + OpenVPN HARD_RESET
  Server → Client: AUTH_FAILED,CRV1:R,<state_id>::<saml_url>
  (connection pauses)

  App opens saml_url in browser.
  Browser → http://127.0.0.1:35001 : POST SAMLResponse=<base64>
  (AWS hardcodes ACS URL to 127.0.0.1:35001)

Phase 2:
  Client → Server: new TLS session with username="CRV1::<state_id>::<saml_token>"
  Server → Client: PUSH_REPLY with ifconfig, route, etc.
  Tunnel is up.
```

Key detail: AWS hardcodes AssertionConsumerServiceURL = http://127.0.0.1:35001.
This is true across all AWS regions and IdPs (Okta, Azure AD, Google Workspace).

The current Kotlin implementation of the ACS server is in
`openlawsvpn-android/app/src/main/java/com/openlawsvpn/android/SamlCallbackServer.kt`
— use it as the reference for the Go `auth/saml` package.

## OpenVPN3 protocol reference

Key concepts an AI agent must know:

**Control channel (reliable transport)**
- Runs over TLS, but TLS runs inside OpenVPN's own reliable layer (not raw TCP TLS)
- Packet structure: [opcode (1 byte)][key_id (3 bits)][peer_id (24 bits)][packet_id (32 bits)][ack_array][payload]
- Opcodes: P_CONTROL_HARD_RESET_CLIENT_V2=0x38, P_ACK_V1=0x28, P_CONTROL_V1=0x20, P_DATA_V2=0x09
- Reliable layer: sequence numbers + sliding window + retransmit (matches reliable.hpp in openvpn3-core)
- TLS bytes are fragmented across P_CONTROL_V1 packets, reassembled in order

**Key derivation**
- After TLS handshake, both sides derive data channel keys using OpenVPN PRF:
  `key_material = PRF(master_secret, "OpenVPN master secret", client_random + server_random)`
- PRF is HMAC-SHA256-based, NOT the standard TLS PRF
- Produces 64 bytes: first 32 = cipher key, last 32 = HMAC key (for CBC mode)
- For GCM modes: only cipher key used, HMAC key unused

**Data channel**
- P_DATA_V2: [0x09 | key_id][peer_id (3 bytes)][iv (12 bytes for GCM)][ciphertext+tag]
- AES-256-GCM: IV = packet_id (32-bit counter, big-endian, zero-padded to 12 bytes) XOR implicit IV
- Replay protection: sliding window on packet_id (32-bit counter per session key)
- Key renegotiation: every 3600s or 100MB (configurable via reneg-sec/reneg-bytes in .ovpn)

**PUSH_REPLY parsing**
- After auth: server sends PUSH_REPLY with comma-separated options
- Critical options: `ifconfig`, `route`, `dhcp-option DNS`, `redirect-gateway`, `cipher`, `compress`
- Example: `PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5,route 10.0.0.0 255.255.0.0,dhcp-option DNS 10.0.0.2`

## Existing C++ reference files

All in openvpn3-core (https://github.com/OpenVPN/openvpn3):

| File | What to learn from it |
|---|---|
| `client/ovpncli.cpp` | Full client state machine — Phase 1, Phase 2, CRV1 parsing |
| `ssl/sslctx.hpp` | TLS setup, cert loading, SNI |
| `reliable/reliable.hpp` | Reliable control channel — seq numbers, ACK, window |
| `crypto/cipher.hpp` + `data_epoch.cpp` | Data channel crypto, IV construction |
| `transport/tcplink.hpp` + `udplink.hpp` | Framing: 2-byte length prefix (TCP), raw (UDP) |
| `openvpn/prf/prfplus.hpp` | Key derivation PRF |
| `tun/builder/base.hpp` | TUN callback interface (what gomobile must expose) |

## Current libopenlawsvpn C API (what Go must replace)

```c
// Allocate a new VPN client for the given .ovpn config file path.
// Returns a handle (opaque integer) or -1 on error.
long clientNew(const char* config_path, void* callbacks);

// Phase 1: connect and get the SAML challenge.
// Returns JSON: {"saml_url": "...", "state_id": "...", "remote_ip": "..."}
// Blocks on the calling thread until Phase 1 completes or fails.
const char* clientConnectPhase1(long handle);

// Phase 2: complete connection with the SAML token.
// Returns NULL on success, error string on failure.
// Blocks until the tunnel is established.
const char* clientConnectPhase2(long handle, const char* saml_token);

// Signal disconnect. Non-blocking — clientWaitForDisconnect() waits for teardown.
void clientDisconnect(long handle);

// Block until the client has fully torn down. Call before clientFree().
void clientWaitForDisconnect(long handle);

// Free all resources. Must only be called after clientWaitForDisconnect() returns.
void clientFree(long handle);

// Callbacks (set before clientNew):
typedef void (*tun_establish_fn)(int fd, const char* ifconfig_json);
typedef int  (*socket_protect_fn)(int fd);
typedef void (*log_fn)(const char* message);
```

The Go `Client` struct exposes equivalent semantics via `Connect(ctx)`,
`Disconnect()`, `Stats()`, and the `SAMLTokenFn` / `MobileCallbacks` hooks.

## Repository layout

```
go-openvpn3/
  CLAUDE.md         — this file (AI/contributor context)
  README.md         — user-facing docs, build instructions, known limitations
  client.go         — top-level Client: Connect, Disconnect, Stats, rekey loop
  client_tun_linux.go   — Linux TUN setup (openNativeTUN)
  client_tun_android.go — Android TUN setup (VpnService fd)
  client_mobile.go  — gomobile API: MobileClient, MobileCallbacks
  profile/          — .ovpn parser
  auth/saml/        — CRV1 SAML challenge handling, ACS server, token TTL
  tun/              — TUN device (Linux + Android via gomobile)
  routing/          — PUSH_REPLY parser, netlink route management (IPv4+IPv6)
  dns/              — DNS push: resolv.conf / systemd-resolved
  internal/
    framing/        — wire format, opcodes, 2-byte length prefix
    reliable/       — control channel reliable transport (sliding window)
    ctls/           — TLS over control channel (crypto/tls via net.Pipe)
    prf/            — OpenVPN key derivation PRF (HMAC-SHA256) + TLS-EKM
    crypto/         — data channel cipher suite (AES-256-GCM / CBC)
    datachannel/    — encrypt/decrypt pipeline, replay window, key rotation
    compress/       — lz4-v2 / comp-lzo uncompressed stub framing
    mssfix/         — software TCP MSS clamping (SYN/SYN-ACK rewrite)
  mock/mockserver/  — pure-Go mock OpenVPN3 server (no openvpn3-core dependency)
  testenv/          — integration test harness (starts mock server in-process)
  testdata/         — test .ovpn profile
  cmd/ovpn3/        — Linux CLI with SAML flow and reconnect loop
```

## Development rules

- Every exported function and type must have a doc comment.
- Integration tests must be tagged `//go:build integration` and must pass against the mock server.
- Unit tests (`go test ./...`) must pass with no network access.
- No CGo anywhere — `CGO_ENABLED=0` must build cleanly.
- Protocol constants go in `internal/framing/opcodes.go` with comments citing the openvpn3-core source line.
- When in doubt about protocol behaviour: read openvpn3-core source first, then write a test against the mock server.

## Where to start

The protocol is fully implemented and tested against a real AWS Client VPN
endpoint. Start by reading:

1. `client.go` — top-level state machine; `Connect`, `connectPhase1`,
   `connectPhase2`, `rekeyLoop`, `tunToWire`, `wireToTun`
2. `internal/framing/opcodes.go` — all wire-format opcodes with openvpn3-core
   source references
3. `mock/mockserver/main.go` — the in-process mock server used by integration
   tests; run with `go run ./mock/mockserver` to observe the full handshake

To run integration tests against the local mock:
```bash
go test -v -tags=integration -timeout 120s .
```
