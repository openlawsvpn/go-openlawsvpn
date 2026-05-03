# go-openlawsvpn — Implementation Status

> All tasks in the original daemon plan are complete. This file now serves as
> a living status reference. See `openlawsvpn-private/ROADMAP.md` for the
> cross-repo roadmap.

---

## Components  (2026-05-03)

| Component | Version | Status |
|-----------|---------|--------|
| VPN protocol engine (`client.go`) | v0.2.8 | ✅ Working — full CRV1/SAML, AES-256-GCM, rekey |
| CLI (`cmd/cli`) | v0.2.8 | ✅ Working — standalone + relay + daemon mode |
| Daemon (`cmd/daemon`) | v0.2.8 | ✅ Working — D-Bus service, CAP\_NET\_ADMIN via systemd |
| GTK4 GUI (`gui-gtk/`) | v0.2.8 | ✅ Working — Rust/libadwaita, relay screen, D-Bus proxy |
| Relay server (`cmd/relay-server`) | v0.2.8 | ✅ Working — local dev/test relay |
| Android `.aar` (gomobile) | v0.2.8 | ✅ Built by CI via `aar.yml` |
| RPM packaging | 0.2.8-1 | ✅ Built by COPR |

---

## Architecture

```
[gui-gtk  Rust + GTK4]  ←── D-Bus ──→  [openlawsvpn-daemon  Go]
                                              │
                                        [go-openlawsvpn client.go]
                                              │
                                        [Linux TUN / netlink / DNS]

[openlawsvpn-cli -relay <token>  Go]  ←── WebSocket ──→  [relay.openlawsvpn.com]
                                                                   │
                                                    [Android/Desktop App  REST]
```

### Daemon D-Bus interface

Bus: session · Service: `com.openlawsvpn.Daemon` · Object: `/com/openlawsvpn/Daemon`

**Methods:** `Connect(profile_path)`, `Disconnect()`, `Status()`, `ConnectRelay(config_path, config_content, agent_id, org_token, relay_url)`

**Signals:** `StateChanged(state, server_ip, assigned_ip)`, `LogLine(line)`, `StatsUpdate(bytes_sent, bytes_recv, uptime_secs)`, `SAMLRequired(url)`

**States:** `idle` · `connecting` · `waiting_saml` · `relay_delivering` · `relay_connected` · `connected` · `disconnecting` · `error`

---

## Relay mode

```
openlawsvpn-cli -relay <token> -daemon -logfile /tmp/vpn.log -pidfile /tmp/vpn.pid
```

- Agent registers via WebSocket to `wss://ws.relay.openlawsvpn.com`
- Stands by as `standby`; mobile/desktop app selects it and runs full Phase 1 + SAML
- App posts credentials to relay; relay pushes `phase2` action to agent over WS
- Agent executes Phase 2, tunnel up; sends `status=connected` back via WS
- On server-requested disconnect: tunnel tears down, agent sends `status=standby`, process exits cleanly (v0.2.8)

See `docs/ci-relay.md` for GitHub Actions integration example.

---

## Known limitations / future work

- Seccomp-BPF filter for daemon (see `docs/security-architecture.md` §9)
- Profile mode check — reject world-readable `.ovpn` files
- SAML token zeroization (Go string type makes this hard)
- iOS support via gomobile (not started)
