# Using openlawsvpn-cli relay mode in CI/CD pipelines

`openlawsvpn-cli` relay mode lets a CI runner connect to an internal VPN network
**without storing credentials in the pipeline**. The SAML auth flow runs once
on the operator's machine; the runner just receives the tunnel credentials via
the relay.

---

## How it works

```
CI runner                    Relay server              Operator's machine
──────────                   ─────────────             ──────────────────
openlawsvpn-cli -relay <token>  ──WS──▶  ws.relay.…  ◀──REST──  app: POST /connect
       │  waits...                                           POST /session/…/execute
       │                                                     (delivers SAML creds)
       ▼
  ConnectPhase2()
  tunnel up
  prints: OVPN3_TUNNEL_UP ...
       │
  pipeline continues
```

The runner never handles Phase 1 or the browser SSO flow. The operator (or an
automated tool) triggers the connection from the app or API.

---

## CI detection

When the `CI` environment variable is set to any non-empty value other than
`0` or `false`, `openlawsvpn-cli` enters CI mode:

- Stays connected after Phase 2 (does not exit — keeps the tunnel alive for
  the rest of the job).
- Prints a machine-readable line to **stdout** when the tunnel is up:

```
OVPN3_TUNNEL_UP local=<outbound-ip> vpn=<assigned-ip> endpoint=<server-ip>
```

This lets the pipeline detect readiness by tailing stdout or the log.

GitHub Actions, GitLab CI, CircleCI, Jenkins, and most other CI systems set
`CI=true` automatically. No extra configuration is needed.

---

## GitHub Actions example

```yaml
- name: Build openlawsvpn-cli
  run: CGO_ENABLED=0 go build -o /usr/local/bin/openlawsvpn-cli ./cmd/cli

- name: Start relay agent
  env:
    RELAY_TOKEN: ${{ secrets.RELAY_TOKEN }}
  run: |
    sudo -E CI=true openlawsvpn-cli -relay "$RELAY_TOKEN" &>/tmp/openlawsvpn-cli.log &
    echo $! > /tmp/openlawsvpn-cli.pid

- name: Wait for tunnel up
  run: |
    for i in $(seq 1 120); do
      grep -q "OVPN3_TUNNEL_UP" /tmp/ovpn3.log && break
      [ $i -eq 120 ] && { cat /tmp/ovpn3.log; exit 1; }
      sleep 5
    done

- name: Run integration tests
  run: curl -sf http://10.130.32.32:5080/healthz

- name: Disconnect
  if: always()
  run: sudo kill "$(cat /tmp/openlawsvpn-cli.pid)" 2>/dev/null || true
```

---

## Required secret

| Secret | Value |
|---|---|
| `RELAY_TOKEN` | Org token from the `relay-organisations` DynamoDB table |

---

## Relay endpoints

| Use | URL |
|---|---|
| Agent WebSocket | `wss://ws.relay.openlawsvpn.com/ws` |
| App REST API | `https://api.relay.openlawsvpn.com/api/v1` |

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `-relay <token>` | — | Org token; enables relay mode |
| `-relay-endpoint <url>` | `wss://ws.relay.openlawsvpn.com/ws` | Override WS endpoint (e.g. for local testing) |
| `-agent-id <uuid>` | random | Stable ID across reconnects; persist across runs for a fixed agent label |
| `-hostname <name>` | `os.Hostname()` | Label shown in the app agent list |
| `-config <path>` | — | Fallback .ovpn profile (optional — app always sends config in payload) |

---

## Local testing

Use the in-process relay server to test the pipeline without hitting production:

```bash
# Terminal 1 — local relay server
go run ./cmd/relay-server -addr :18080

# Terminal 2 — CI agent
CI=true sudo openlawsvpn-cli -relay testtoken \
  -relay-endpoint ws://localhost:18080/ws \
  -config tunnel.ovpn

# Terminal 3 — simulate the app delivering credentials
curl -s http://localhost:18080/api/v1/agents?token=testtoken
# pick agent_id from output, then:
curl -s -X POST http://localhost:18080/api/v1/connect \
  -d '{"token":"testtoken","agent_id":"<id>"}'
# use session_id to call /execute with real credentials
```
