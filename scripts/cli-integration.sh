#!/usr/bin/env bash
# scripts/cli-integration.sh — CLI binary integration test against the mock server.
#
# Builds (if needed), starts the mock OpenVPN server, connects the CLI binary
# in daemon mode, asserts the tunnel comes up, then cleans up.
#
# Environment overrides:
#   CLI_BIN   — path to openlawsvpn-cli (default: bin/openlawsvpn-cli)
#   MOCK_BIN  — path to mock-server     (default: bin/mock-server)
#   SUDO      — sudo command prefix      (default: sudo; set to "" to disable)
#
# Prerequisites:
#   - sudo or root access (TUN device creation requires CAP_NET_ADMIN)
#   - openssl in PATH (for TLS; the mock server generates its own cert)
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
CLI_BIN=${CLI_BIN:-"$REPO_ROOT/bin/openlawsvpn-cli"}
MOCK_BIN=${MOCK_BIN:-"$REPO_ROOT/bin/mock-server"}
SUDO=${SUDO:-sudo}

MOCK_LOG=$(mktemp /tmp/mock-server.XXXXXX.log)
MOCK_CA=$(mktemp /tmp/mock-server-ca.XXXXXX.pem)
CLI_LOG=$(mktemp /tmp/openlawsvpn-cli.XXXXXX.log)
CLI_PID_FILE=$(mktemp /tmp/openlawsvpn-cli.XXXXXX.pid)
TEST_OVPN=$(mktemp /tmp/test.XXXXXX.ovpn)
MOCK_PID=

cleanup() {
    echo "--- cleanup ---"
    if [[ -n "$MOCK_PID" ]]; then
        kill "$MOCK_PID" 2>/dev/null || true
    fi
    if [[ -f "$CLI_PID_FILE" ]] && [[ -s "$CLI_PID_FILE" ]]; then
        $SUDO kill "$(cat "$CLI_PID_FILE")" 2>/dev/null || true
    fi
    echo "--- mock server log ---"
    cat "$MOCK_LOG" || true
    echo "--- cli log ---"
    cat "$CLI_LOG" || true
    rm -f "$MOCK_LOG" "$MOCK_CA" "$CLI_LOG" "$CLI_PID_FILE" "$TEST_OVPN"
}
trap cleanup EXIT

# ── Build binaries if missing ──────────────────────────────────────────────────

if [[ ! -x "$MOCK_BIN" ]]; then
    echo "Building mock-server..."
    cd "$REPO_ROOT"
    go build -o "$MOCK_BIN" ./mock/mockserver
fi

if [[ ! -x "$CLI_BIN" ]]; then
    echo "Building openlawsvpn-cli..."
    cd "$REPO_ROOT"
    CGO_ENABLED=0 go build -o "$CLI_BIN" ./cmd/cli
fi

# ── Start mock server ──────────────────────────────────────────────────────────
# MOCK_TCP_PORT=0 tells the server to bind on a random free port.
# stdout → structured JSON event log; stderr → CA PEM (when no CERT_DIR).

echo "Starting mock server..."
MOCK_TCP_PORT=0 "$MOCK_BIN" > "$MOCK_LOG" 2>"$MOCK_CA" &
MOCK_PID=$!

# Wait up to 10 s for the server to emit the "ready" event.
echo "Waiting for mock server to be ready..."
for i in $(seq 1 50); do
    if grep -q '"event":"ready"' "$MOCK_LOG" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$MOCK_PID" 2>/dev/null; then
        echo "ERROR: mock server exited before ready"
        exit 1
    fi
    sleep 0.2
done
if ! grep -q '"event":"ready"' "$MOCK_LOG"; then
    echo "ERROR: mock server did not emit ready event within 10 s"
    exit 1
fi

# Extract the TCP port from the ready event detail: "tcp=0.0.0.0:PORT"
PORT=$(grep -o '"event":"ready".*"detail":"tcp=0\.0\.0\.0:[0-9]*' "$MOCK_LOG" \
      | grep -o '[0-9]*$')
if [[ -z "$PORT" ]]; then
    echo "ERROR: could not parse TCP port from mock server ready event"
    cat "$MOCK_LOG"
    exit 1
fi
echo "Mock server ready on port $PORT"

# ── Build test .ovpn profile ───────────────────────────────────────────────────
# The mock server's CA PEM is on stderr. When client.go cannot parse the CA it
# falls back to InsecureSkipVerify, which is fine for local testing.
# We embed the real CA so the TLS verification path is exercised too.

cat > "$TEST_OVPN" << OVPN
client
dev tun
proto tcp-client
remote 127.0.0.1 $PORT
nobind
tls-client
verb 3
<ca>
$(cat "$MOCK_CA")
</ca>
OVPN

echo "Test profile written to $TEST_OVPN"

# ── Connect CLI in daemon mode ─────────────────────────────────────────────────
# The foreground process blocks until the tunnel is up, then exits 0.
# Exit code 1 means the tunnel failed to come up → the test fails.

echo "Starting CLI in daemon mode (requires sudo for TUN)..."
$SUDO "$CLI_BIN" \
    -config "$TEST_OVPN" \
    -daemon \
    -pidfile "$CLI_PID_FILE" \
    -logfile "$CLI_LOG"

echo "Tunnel is up (daemon PID: $(cat "$CLI_PID_FILE"))"

# ── Assertions ────────────────────────────────────────────────────────────────

echo "Checking mock server emitted push_reply event..."
if ! grep -q '"event":"push_reply"' "$MOCK_LOG"; then
    echo "FAIL: mock server log missing push_reply event"
    exit 1
fi

echo "PASS: CLI connected and daemonized; mock server sent push_reply"
