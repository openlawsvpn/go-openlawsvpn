// Package relay implements the CLI agent side of the openlawsvpn SAML relay protocol.
//
// An agent opens a persistent outbound WebSocket to the relay server, registers with
// its organisation token, then stands by. When the mobile/desktop app completes the
// full SAML auth flow (Phase 1 + browser), it sends the credentials to the relay which
// pushes them here via the WebSocket. The agent executes Phase 2 and brings up the tunnel.
//
// The relay server is only ever a delivery channel. This package never handles Phase 1
// or the SAML browser flow — those run entirely on the user's app.
//
// Usage:
//
//	agent, err := relay.New(relay.Config{
//	    Token:    "kjewoijo23823",
//	    Hostname: "build-runner-42",
//	    Endpoint: "wss://relay.openlawsvpn.com/ws",
//	    OnPhase2: func(ctx context.Context, p relay.Phase2Payload) error {
//	        // p contains everything needed to call connectPhase2
//	        return runVPN(ctx, p)
//	    },
//	})
//	err = agent.Run(ctx) // blocks; reconnects on transient failures
package relay

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Phase2Payload is the credential bundle delivered by the relay server.
// It contains everything the agent needs to execute OpenVPN Phase 2.
type Phase2Payload struct {
	SessionID    string `json:"session_id"`
	StateID      string `json:"state_id"`
	SAMLResponse string `json:"saml_response"`
	RemoteIP     string `json:"remote_ip"`
	OvpnConfig   string `json:"ovpn_config"`
}

// Config holds agent registration parameters.
type Config struct {
	// Token is the organisation token (--relay= flag value).
	Token string
	// Hostname is a human-readable label for this agent (defaults to os.Hostname).
	Hostname string
	// AgentID is a stable UUID identifying this agent across reconnects.
	// If empty, a random one is generated and retained for the lifetime of this Agent.
	AgentID string
	// Endpoint is the relay WebSocket URL, e.g. "wss://relay.openlawsvpn.com/ws".
	Endpoint string
	// OnPhase2 is called with the credential payload when the relay delivers one.
	// It should block until the VPN tunnel is established (or fails).
	// It must be safe to call concurrently with Run.
	OnPhase2 func(ctx context.Context, p Phase2Payload) error
	// Log receives diagnostic messages. Defaults to no-op if nil.
	Log func(msg string)
}

// Agent is a running relay agent.
type Agent struct {
	cfg     Config
	agentID string

	mu     sync.Mutex
	connWS *wsConn // current WebSocket connection (nil when disconnected)
}

// New creates a new Agent. It does not connect; call Run to start.
func New(cfg Config) (*Agent, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("relay: token is required")
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("relay: endpoint is required")
	}
	if cfg.OnPhase2 == nil {
		return nil, fmt.Errorf("relay: OnPhase2 callback is required")
	}

	id := cfg.AgentID
	if id == "" {
		id = newUUID()
	}
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	return &Agent{cfg: cfg, agentID: id}, nil
}

// Run connects to the relay server and keeps the connection alive until ctx is
// cancelled. It reconnects automatically on transient failures with exponential
// backoff (1s → 2s → 4s … capped at 60s).
func (a *Agent) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		a.cfg.Log(fmt.Sprintf("relay: connecting to %s", a.cfg.Endpoint))
		if err := a.runOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			a.cfg.Log(fmt.Sprintf("relay: disconnected (%v), retrying in %s", err, backoff))
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
			if backoff < 60*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second // reset on clean disconnect
	}
}

// runOnce connects, registers, and reads messages until the connection breaks.
func (a *Agent) runOnce(ctx context.Context) error {
	u, err := buildWSURL(a.cfg.Endpoint, a.cfg.Token, a.cfg.Hostname, a.agentID)
	if err != nil {
		return fmt.Errorf("relay: build URL: %w", err)
	}

	ws, err := dialWS(ctx, u)
	if err != nil {
		return fmt.Errorf("relay: dial: %w", err)
	}
	defer ws.close()

	a.mu.Lock()
	a.connWS = ws
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.connWS = nil
		a.mu.Unlock()
	}()

	a.cfg.Log(fmt.Sprintf("relay: registered — agent_id=%s hostname=%s", a.agentID, a.cfg.Hostname))

	// Ping loop keeps the WS alive through NAT/firewall idle timeouts.
	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := ws.sendPing(ctx); err != nil {
					return
				}
			case <-ctx.Done():
				return
			case <-ws.closed:
				return
			}
		}
	}()

	for {
		msg, err := ws.readMessage(ctx)
		if err != nil {
			ws.close() // unblock the ping goroutine immediately
			<-pingDone
			return err
		}
		if err := a.handleMessage(ctx, msg); err != nil {
			a.cfg.Log(fmt.Sprintf("relay: message handler error: %v", err))
		}
	}
}

func (a *Agent) handleMessage(ctx context.Context, msg []byte) error {
	var envelope struct {
		Action    string          `json:"action"`
		SessionID string          `json:"session_id"`
		Payload   json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(msg, &envelope); err != nil {
		return fmt.Errorf("relay: unmarshal envelope: %w", err)
	}

	switch envelope.Action {
	case "phase2":
		var p Phase2Payload
		if err := json.Unmarshal(envelope.Payload, &p); err != nil {
			return fmt.Errorf("relay: unmarshal phase2 payload: %w", err)
		}
		p.SessionID = envelope.SessionID
		a.cfg.Log(fmt.Sprintf("relay: received phase2 for session %s", p.SessionID))
		go func() {
			if err := a.cfg.OnPhase2(ctx, p); err != nil {
				a.cfg.Log(fmt.Sprintf("relay: phase2 error: %v", err))
				a.sendStatus(ctx, p.SessionID, "error", "")
			}
		}()

	case "disconnect":
		a.cfg.Log("relay: server requested disconnect")

	default:
		a.cfg.Log(fmt.Sprintf("relay: unknown action %q", envelope.Action))
	}
	return nil
}

// SendStatus sends a status heartbeat to the relay server.
// status is one of: "connecting", "connected", "error".
func (a *Agent) SendStatus(ctx context.Context, sessionID, status, assignedIP string) {
	a.sendStatus(ctx, sessionID, status, assignedIP)
}

func (a *Agent) sendStatus(ctx context.Context, sessionID, status, assignedIP string) {
	a.mu.Lock()
	ws := a.connWS
	a.mu.Unlock()
	if ws == nil {
		return
	}
	msg := map[string]any{
		"action":      "status",
		"session_id":  sessionID,
		"org":         a.cfg.Token,
		"agent_id":    a.agentID,
		"status":      status,
		"assigned_ip": assignedIP,
	}
	b, _ := json.Marshal(msg)
	_ = ws.sendText(ctx, b)
}

// AgentID returns the stable agent identifier used for registration.
func (a *Agent) AgentID() string { return a.agentID }

// ---------------------------------------------------------------------------
// Minimal RFC 6455 WebSocket client (no external dependency)
// ---------------------------------------------------------------------------

// wsConn wraps a raw TCP connection and speaks RFC 6455 WebSocket framing.
// Only text frames and ping/pong are supported — sufficient for the relay protocol.
type wsConn struct {
	conn   net.Conn
	rdr    *bufio.Reader
	mu     sync.Mutex // guards writes
	closed chan struct{}
	once   sync.Once
}

func dialWS(ctx context.Context, rawURL string) (*wsConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	host := u.Hostname()
	port := u.Port()
	scheme := u.Scheme

	var tlsEnabled bool
	switch scheme {
	case "wss":
		tlsEnabled = true
		if port == "" {
			port = "443"
		}
	case "ws":
		if port == "" {
			port = "80"
		}
	default:
		return nil, fmt.Errorf("relay: unsupported scheme %q", scheme)
	}

	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{}
	var rawConn net.Conn
	if tlsEnabled {
		rawConn, err = dialTLS(ctx, addr, host)
		if err != nil {
			return nil, err
		}
	} else {
		rawConn, err = dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
	}

	// WebSocket handshake.
	key := wsKey()
	path := u.RequestURI()
	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, u.Host, key,
	)
	if _, err := io.WriteString(rawConn, req); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("relay: WS handshake write: %w", err)
	}

	rdr := bufio.NewReaderSize(rawConn, 64*1024)
	status, err := rdr.ReadString('\n')
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("relay: WS handshake read: %w", err)
	}
	if !strings.Contains(status, "101") {
		rawConn.Close()
		return nil, fmt.Errorf("relay: WS handshake rejected: %s", strings.TrimSpace(status))
	}
	// Drain remaining headers.
	for {
		line, err := rdr.ReadString('\n')
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("relay: WS headers: %w", err)
		}
		if line == "\r\n" {
			break
		}
	}

	return &wsConn{conn: rawConn, rdr: rdr, closed: make(chan struct{})}, nil
}

func (w *wsConn) close() {
	w.once.Do(func() {
		close(w.closed)
		w.conn.Close()
	})
}

// readMessage reads one WebSocket frame and returns its payload.
// Handles fragmentation, pong replies, and close frames.
func (w *wsConn) readMessage(ctx context.Context) ([]byte, error) {
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Use a 2s polling deadline so ctx cancellation is noticed promptly.
		w.conn.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck

		header := make([]byte, 2)
		if _, err := io.ReadFull(w.rdr, header); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// Timeout just means no data yet — loop and check ctx again.
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return nil, fmt.Errorf("relay: read frame header: %w", err)
		}

		opcode := header[0] & 0x0F
		payloadLen := int(header[1] & 0x7F)

		switch payloadLen {
		case 126:
			ext := make([]byte, 2)
			if _, err := io.ReadFull(w.rdr, ext); err != nil {
				return nil, fmt.Errorf("relay: read 16-bit length: %w", err)
			}
			payloadLen = int(ext[0])<<8 | int(ext[1])
		case 127:
			ext := make([]byte, 8)
			if _, err := io.ReadFull(w.rdr, ext); err != nil {
				return nil, fmt.Errorf("relay: read 64-bit length: %w", err)
			}
			payloadLen = int(ext[4])<<24 | int(ext[5])<<16 | int(ext[6])<<8 | int(ext[7])
		}

		masked := header[1]&0x80 != 0
		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(w.rdr, maskKey[:]); err != nil {
				return nil, fmt.Errorf("relay: read mask key: %w", err)
			}
		}

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(w.rdr, payload); err != nil {
			return nil, fmt.Errorf("relay: read payload: %w", err)
		}
		if masked {
			for i, b := range payload {
				payload[i] = b ^ maskKey[i%4]
			}
		}

		switch opcode {
		case 0x1, 0x2: // text, binary
			return payload, nil
		case 0x8: // close
			return nil, fmt.Errorf("relay: server closed connection")
		case 0x9: // ping — reply with pong
			_ = w.sendFrame(ctx, 0xA, payload)
		case 0xA: // pong — ignore
		}
	}
}

func (w *wsConn) sendText(ctx context.Context, payload []byte) error {
	return w.sendFrame(ctx, 0x1, payload)
}

func (w *wsConn) sendPing(ctx context.Context) error {
	return w.sendFrame(ctx, 0x9, nil)
}

func (w *wsConn) sendFrame(ctx context.Context, opcode byte, payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Client frames must be masked (RFC 6455 §5.3).
	var maskKey [4]byte
	for i := range maskKey {
		maskKey[i] = byte(rand.IntN(256))
	}

	n := len(payload)
	var header []byte
	header = append(header, 0x80|opcode) // FIN + opcode

	switch {
	case n < 126:
		header = append(header, 0x80|byte(n))
	case n < 65536:
		header = append(header, 0x80|126, byte(n>>8), byte(n))
	default:
		header = append(header, 0x80|127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	header = append(header, maskKey[:]...)

	masked := make([]byte, n)
	for i, b := range payload {
		masked[i] = b ^ maskKey[i%4]
	}

	w.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	if _, err := w.conn.Write(append(header, masked...)); err != nil {
		return fmt.Errorf("relay: write frame: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildWSURL(endpoint, token, hostname, agentID string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("token", token)
	q.Set("hostname", hostname)
	q.Set("agent_id", agentID)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// newUUID returns a random UUID v4 string.
func newUUID() string {
	var b [16]byte
	for i := range b {
		b[i] = byte(rand.IntN(256))
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// wsKey returns a random base64 Sec-WebSocket-Key value (RFC 6455 §4.1).
func wsKey() string {
	var b [16]byte
	for i := range b {
		b[i] = byte(rand.IntN(256))
	}
	return base64.StdEncoding.EncodeToString(b[:])
}
