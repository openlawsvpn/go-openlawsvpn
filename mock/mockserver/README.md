# mockserver

Pure-Go mock OpenVPN3 server used by integration tests and as a **lightweight demo VPN server**.

Implements the full control-channel handshake: HARD_RESET → TLS → key-method-2 auth →
PUSH_REQUEST → PUSH_REPLY. Supports both TCP and UDP. No openvpn3-core or C dependencies.

## Modes

### Normal mode (default)

Accepts any client, completes the handshake, and sends a PUSH_REPLY with a dummy
`10.8.0.x` network config. Used by unit and integration tests.

```bash
go run ./mock/mockserver
```

### CRV1 / SAML mode (`MOCK_CRV1=1`)

Mimics AWS Client VPN behaviour:

- **Phase 1** — sends `AUTH_FAILED,CRV1:R:<state_id>::<idp_url>` after the auth exchange.
  The client opens `<idp_url>` in a browser.
- **Phase 2** — client reconnects with `CRV1::<state_id>::<token>` as the password.
  Server validates the token and sends PUSH_REPLY.

```bash
MOCK_CRV1=1 go run ./mock/mockserver
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `MOCK_CRV1` | `""` | Set to `1` to enable CRV1/SAML mode |
| `MOCK_TCP_PORT` | `4433` | TCP listen port |
| `MOCK_UDP_PORT` | `1194` | UDP listen port |
| `CERT_DIR` | `""` | Directory with `ca.crt`, `server.crt`, `server.key`. When empty, ephemeral in-memory certs are generated and the CA PEM is printed to stderr |
| `IDP_URL` | `https://openlawsvpn.com/demo/login.html` | Base URL for the CRV1 login page. `?state=<id>` is appended |
| `DEMO_TOKEN` | `DEMO2026OPENLAWS` | Fixed token the login page must POST to `127.0.0.1:35001`. Phase 2 rejects anything else |

## Demo VPN server (no AWS required)

The mockserver is the backend for the public demo at `demo.openlawsvpn.com`.
This lets app reviewers (e.g. Google Play) try the full SAML login flow without
needing an AWS Client VPN endpoint.

**How it works:**

```
Reviewer imports demo-client.ovpn  (CA cert only, no private key)
         ↓
App connects → mockserver sends CRV1 challenge with login page URL
         ↓
Custom Tab opens https://openlawsvpn.com/demo/login.html?state=<id>
         ↓
Reviewer enters  username: reviewer  /  password: Demo2026!
         ↓
Page POSTs SAMLResponse=DEMO2026OPENLAWS to http://127.0.0.1:35001
         ↓
App captures token, sends Phase 2 → mockserver validates → PUSH_REPLY → tunnel up
```

The login page (`openlawsvpn-website/demo/login.html`) is **pure static HTML** —
no server, no Lambda, no database. Credentials are validated client-side and the
fixed token is hardcoded in both the page and the server.

### Deploying on EC2

1. **Generate server certs** (one-time):

```bash
cd mock
bash gencerts.sh          # produces ca.crt, server.crt, server.key in ./certs/
```

2. **Run the server:**

```bash
MOCK_CRV1=1 \
CERT_DIR=/etc/demo-vpn/certs \
MOCK_UDP_PORT=1194 \
go run ./mock/mockserver
```

Or build a static binary and run as a systemd service:

```bash
CGO_ENABLED=0 go build -o demo-vpn-server ./mock/mockserver
```

3. **Point DNS** — add an A record: `demo.openlawsvpn.com → <EC2 public IP>`

4. **Firewall** — open UDP 1194 inbound.

5. **Distribute** `openlawsvpn-website/demo/demo-client.ovpn` — it contains only
   the CA cert, no client private key, safe to publish.

### Security note

The demo token is fixed and public. This server grants tunnel access to **anyone**
who knows the credentials shown on the login page. It should be used only as a
demo environment, not to protect real resources. Shut it down or rotate
`DEMO_TOKEN` between review windows if needed.
