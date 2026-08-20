# Using openlawsvpn-cli relay mode in CI/CD pipelines

`openlawsvpn-cli` relay mode lets a CI runner connect to an internal VPN network
without exposing its relay token in process arguments. The SAML auth flow runs on
the operator's phone or desktop; the runner receives the completed tunnel
credentials via the relay and brings the VPN up as a background daemon. The relay
token is held in a mode-0600 temporary file and removed during job cleanup.
The compatible `-relay <token>` form remains supported, including with
`-daemon`. The public demo selector `-relay default` is intentionally safe to
show; private organisation tokens should use the file form on shared systems.

---

## How it works

```
CI runner                       Relay (AWS)              Operator (phone/desktop)
─────────                       ───────────              ───────────────────────
openlawsvpn-cli -relay-token-file <mode-0600-file>
  -daemon                ──WS──▶  relay.openlawsvpn.com  ◀──REST──  app lists agents
  prints: daemon started (pid N)                                      taps Connect
  pipeline continues immediately                                      SAML browser flow
                                                                      POST /session/…/execute
       │  (background)
       ▼
  ConnectPhase2()  ◀──── WS push: phase2 payload ─────────────────────────────────┘
  tunnel up
  agent sends status=connected
```

The runner never handles Phase 1 or the browser SSO flow.
After `daemon started`, the foreground step exits 0 immediately — the pipeline continues.
The background daemon keeps the tunnel alive for the rest of the job.

---

## GitHub Actions example

```yaml
- name: Build openlawsvpn-cli
  run: CGO_ENABLED=0 go build -o /usr/local/bin/openlawsvpn-cli ./cmd/cli

- name: Start relay agent (daemon)
  timeout-minutes: 5
  env:
    RELAY_TOKEN: ${{ secrets.RELAY_TOKEN }}
  run: |
    install -m 600 /dev/null /tmp/openlawsvpn-relay-token
    printf '%s\n' "$RELAY_TOKEN" > /tmp/openlawsvpn-relay-token
    sudo openlawsvpn-cli \
      -relay-token-file /tmp/openlawsvpn-relay-token \
      -daemon \
      -pidfile /tmp/openlawsvpn.pid \
      -logfile /tmp/openlawsvpn.log
    # blocks until the app approves (tunnel up), then exits 0
    # the daemon continues running in the background

- name: Check internal service health
  env:
    HEALTH_URL: ${{ secrets.INTERNAL_HEALTH_URL }}
  run: curl -sf "$HEALTH_URL"

- name: Disconnect VPN and remove token file
  if: always()
  run: |
    sudo kill "$(cat /tmp/openlawsvpn.pid)" 2>/dev/null || true
    rm -f /tmp/openlawsvpn-relay-token

- name: Upload relay agent log
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: vpn-log
    path: /tmp/openlawsvpn.log
```

The `-daemon` flag forks the process to the background once the tunnel is up.
The foreground step exits 0 as soon as the daemon prints `daemon started (pid N)`,
so the pipeline sees a clean exit and moves on.

If the app never approves, the foreground step hangs until `timeout-minutes` is
reached — always set a step-level timeout to get a clean failure.

---

## Required secret

| Secret | Value |
|---|---|
| `RELAY_TOKEN` | Org token — obtain from the relay app Settings screen |

---

## Relay endpoints

| Use | URL |
|---|---|
| Agent WebSocket | `wss://ws.relay.openlawsvpn.com` |
| App REST API | `https://api.relay.openlawsvpn.com/api/v1` |

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `-relay <token>` | — | Organisation identifier/token; `default` is the public demo selector |
| `-relay-token-file <path>` | — | Read the org token from a mode-0600 file; enables relay mode |
| `-relay-token-fd <fd>` | — | Read the org token from a descriptor; foreground mode only |
| `-daemon` | false | Fork to background after tunnel up; foreground exits 0 |
| `-pidfile <path>` | — | Write daemon PID here (for `kill` in cleanup step) |
| `-logfile <path>` | /dev/null | Redirect daemon output here |
| `-relay-endpoint <url>` | `wss://ws.relay.openlawsvpn.com` | Override WS endpoint (e.g. local testing) |
| `-agent-id <uuid>` | random | Stable ID across reconnects; persist for a fixed label in the app |
| `-hostname <name>` | `os.Hostname()` | Label shown in the app agent list |

---

## Remote disconnect

The app (Android or GTK4 GUI) can disconnect the agent at any time via the
**Disconnect** button on the Relay screen. The daemon exits cleanly (v0.2.8+).

The REST API also supports this directly:

```bash
curl -X DELETE https://api.relay.openlawsvpn.com/api/v1/session/<session_id>/release \
  -H "Content-Type: application/json" \
  -d '{"token":"<org_token>"}'
```

---

## Local testing

Use the in-process relay server to test without hitting production:

```bash
# Terminal 1 — local relay server
go run ./cmd/relay-server -addr :18080

# Terminal 2 — CI agent (foreground for easier debugging; omit -daemon)
sudo openlawsvpn-cli -relay testtoken \
  -relay-endpoint ws://localhost:18080/ws \
  -config tunnel.ovpn

# Terminal 3 — simulate the app delivering credentials
AGENT=$(curl -s 'http://localhost:18080/api/v1/agents?token=testtoken' | jq -r '.[0].agent_id')
SESSION=$(curl -s -X POST http://localhost:18080/api/v1/connect \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"testtoken\",\"agent_id\":\"$AGENT\"}" | jq -r .session_id)
curl -s -X POST http://localhost:18080/api/v1/session/$SESSION/execute \
  -H "Content-Type: application/json" \
  -d '{"ovpn_config":"...","state_id":"...","saml_response":"...","remote_ip":"..."}'
```
