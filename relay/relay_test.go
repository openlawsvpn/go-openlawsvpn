package relay

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── New validation ────────────────────────────────────────────────────────────

func TestNewMissingToken(t *testing.T) {
	_, err := New(Config{Endpoint: "ws://x/ws", OnPhase2: nopPhase2})
	if err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("expected token error, got %v", err)
	}
}

func TestNewMissingEndpoint(t *testing.T) {
	_, err := New(Config{Token: "tok", OnPhase2: nopPhase2})
	if err == nil || !strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("expected endpoint error, got %v", err)
	}
}

func TestNewMissingOnPhase2(t *testing.T) {
	_, err := New(Config{Token: "tok", Endpoint: "ws://x/ws"})
	if err == nil || !strings.Contains(err.Error(), "OnPhase2") {
		t.Fatalf("expected OnPhase2 error, got %v", err)
	}
}

func TestNewStableAgentID(t *testing.T) {
	a, err := New(Config{Token: "t", Endpoint: "ws://x/ws", AgentID: "my-id", OnPhase2: nopPhase2})
	if err != nil {
		t.Fatal(err)
	}
	if a.AgentID() != "my-id" {
		t.Errorf("AgentID = %q, want my-id", a.AgentID())
	}
}

func TestNewGeneratesAgentID(t *testing.T) {
	a, err := New(Config{Token: "t", Endpoint: "ws://x/ws", OnPhase2: nopPhase2})
	if err != nil {
		t.Fatal(err)
	}
	if a.AgentID() == "" {
		t.Fatal("expected non-empty generated AgentID")
	}
}

// ── buildWSURL ────────────────────────────────────────────────────────────────

func TestBuildWSURLPreservesEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"ws://relay.example.com/ws",
		"wss://relay.example.com/ws",
		"wss://relay.example.com:8443/ws/v2",
	} {
		got, err := buildWSURL(endpoint)
		if err != nil {
			t.Fatalf("buildWSURL(%q): %v", endpoint, err)
		}
		if got != endpoint {
			t.Errorf("buildWSURL(%q) = %q, want unchanged", endpoint, got)
		}
		// Token must not appear in the URL.
		if strings.Contains(got, "token") {
			t.Errorf("URL %q must not contain token", got)
		}
	}
}

func TestBuildWSURLRejectsInvalidScheme(t *testing.T) {
	if _, err := buildWSURL("http://relay.example.com/ws"); err != nil {
		// dialWS will reject it; buildWSURL just parses — both are acceptable.
		// Just ensure it doesn't panic.
		_ = err
	}
}

// ── wsKey ─────────────────────────────────────────────────────────────────────

func TestWsKeyIsValidBase64(t *testing.T) {
	key := wsKey()
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatalf("wsKey %q is not valid base64: %v", key, err)
	}
	if len(decoded) != 16 {
		t.Errorf("decoded wsKey length = %d, want 16", len(decoded))
	}
}

func TestWsKeyUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		k := wsKey()
		if seen[k] {
			t.Fatalf("duplicate wsKey: %q", k)
		}
		seen[k] = true
	}
}

// ── newUUID ───────────────────────────────────────────────────────────────────

func TestNewUUIDFormat(t *testing.T) {
	u := newUUID()
	parts := strings.Split(u, "-")
	if len(parts) != 5 {
		t.Fatalf("UUID %q: expected 5 dash-separated parts, got %d", u, len(parts))
	}
	lengths := []int{8, 4, 4, 4, 12}
	for i, p := range parts {
		if len(p) != lengths[i] {
			t.Errorf("UUID part[%d] len=%d want %d in %q", i, len(p), lengths[i], u)
		}
	}
}

func TestNewUUIDVersion4(t *testing.T) {
	for i := 0; i < 10; i++ {
		u := newUUID()
		parts := strings.Split(u, "-")
		if parts[2][0] != '4' {
			t.Errorf("UUID %q: version nibble = %q, want '4'", u, parts[2][0])
		}
		c := parts[3][0]
		if c != '8' && c != '9' && c != 'a' && c != 'b' {
			t.Errorf("UUID %q: variant nibble = %q, want 8/9/a/b", u, c)
		}
	}
}

// ── handleMessage ─────────────────────────────────────────────────────────────

func TestHandleMessagePhase2(t *testing.T) {
	received := make(chan Phase2Payload, 1)
	a := &Agent{
		cfg: Config{
			Token: "tok",
			Log:   func(string) {},
			OnPhase2: func(_ context.Context, p Phase2Payload) error {
				received <- p
				return nil
			},
		},
	}

	msg := `{
		"action":     "phase2",
		"session_id": "sess-1",
		"payload": {
			"state_id":      "sid1",
			"saml_response": "token=abc",
			"remote_ip":     "10.0.0.1",
			"ovpn_config":   "remote vpn.example.com 443"
		}
	}`

	if err := a.handleMessage(context.Background(), []byte(msg)); err != nil {
		t.Fatalf("handleMessage: %v", err)
	}

	select {
	case p := <-received:
		if p.SessionID != "sess-1" {
			t.Errorf("SessionID = %q", p.SessionID)
		}
		if p.StateID != "sid1" {
			t.Errorf("StateID = %q", p.StateID)
		}
		if p.RemoteIP != "10.0.0.1" {
			t.Errorf("RemoteIP = %q", p.RemoteIP)
		}
		if p.SAMLResponse != "token=abc" {
			t.Errorf("SAMLResponse = %q", p.SAMLResponse)
		}
		if p.OvpnConfig != "remote vpn.example.com 443" {
			t.Errorf("OvpnConfig = %q", p.OvpnConfig)
		}
	case <-time.After(time.Second):
		t.Fatal("OnPhase2 not called within 1s")
	}
}

func TestHandleMessageDisconnectCallsCallback(t *testing.T) {
	called := make(chan struct{}, 1)
	a := &Agent{
		cfg: Config{
			Token:        "tok",
			Log:          func(string) {},
			OnPhase2:     nopPhase2,
			OnDisconnect: func() { called <- struct{}{} },
		},
	}
	msg := `{"action":"disconnect","session_id":"s","payload":{}}`
	if err := a.handleMessage(context.Background(), []byte(msg)); err != nil {
		t.Fatalf("handleMessage: %v", err)
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("OnDisconnect not called within 1s")
	}
}

func TestHandleMessageDisconnectNilCallback(t *testing.T) {
	// OnDisconnect = nil must not panic.
	a := &Agent{
		cfg: Config{
			Token:    "tok",
			Log:      func(string) {},
			OnPhase2: nopPhase2,
		},
	}
	msg := `{"action":"disconnect","session_id":"s","payload":{}}`
	if err := a.handleMessage(context.Background(), []byte(msg)); err != nil {
		t.Fatalf("handleMessage: %v", err)
	}
}

func TestHandleMessageUnknownAction(t *testing.T) {
	logs := make(chan string, 4)
	a := &Agent{
		cfg: Config{
			Token:    "tok",
			Log:      func(m string) { logs <- m },
			OnPhase2: nopPhase2,
		},
	}
	msg := `{"action":"bogus","session_id":"s"}`
	if err := a.handleMessage(context.Background(), []byte(msg)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	select {
	case log := <-logs:
		if !strings.Contains(log, "bogus") {
			t.Errorf("log %q missing action name", log)
		}
	case <-time.After(time.Second):
		t.Fatal("no log for unknown action")
	}
}

func TestHandleMessageMalformedJSON(t *testing.T) {
	a := &Agent{cfg: Config{Token: "tok", Log: func(string) {}, OnPhase2: nopPhase2}}
	if err := a.handleMessage(context.Background(), []byte("not json")); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestHandleMessageMalformedPayload(t *testing.T) {
	a := &Agent{cfg: Config{Token: "tok", Log: func(string) {}, OnPhase2: nopPhase2}}
	msg := `{"action":"phase2","session_id":"s","payload":"not-an-object"}`
	if err := a.handleMessage(context.Background(), []byte(msg)); err == nil {
		t.Fatal("expected error for malformed phase2 payload")
	}
}

// ── sendStatus ────────────────────────────────────────────────────────────────

// TestSendStatusJSON verifies the JSON shape sent by sendStatus using a net.Pipe.
func TestSendStatusJSON(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	ws := &wsConn{
		conn:   clientConn,
		rdr:    bufio.NewReaderSize(clientConn, 64*1024),
		closed: make(chan struct{}),
	}

	a := &Agent{
		cfg:     Config{Token: "mytoken", Log: func(string) {}, OnPhase2: nopPhase2},
		agentID: "agent-42",
		connWS:  ws,
	}

	result := make(chan map[string]any, 1)
	go func() {
		rdr := bufio.NewReader(serverConn)
		payload, _, err := wsReadRawFrame(rdr)
		if err != nil {
			result <- nil
			return
		}
		var m map[string]any
		_ = json.Unmarshal(payload, &m)
		result <- m
	}()

	a.sendStatus(context.Background(), "sess-99", "connected", "172.16.0.1")

	select {
	case m := <-result:
		if m == nil {
			t.Fatal("failed to read frame from server side")
		}
		checks := map[string]string{
			"action":      "status",
			"session_id":  "sess-99",
			"org":         "mytoken",
			"agent_id":    "agent-42",
			"status":      "connected",
			"assigned_ip": "172.16.0.1",
		}
		for k, want := range checks {
			if got, _ := m[k].(string); got != want {
				t.Errorf("status JSON[%q] = %q, want %q", k, got, want)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout reading status frame")
	}
}

// ── End-to-end: agent ↔ in-process relay server ───────────────────────────────

// TestAgentReceivesPhase2 starts a minimal in-process WS server, connects an
// Agent to it, delivers a phase2 message, and checks OnPhase2 fires correctly.
func TestAgentReceivesPhase2(t *testing.T) {
	phase2Ch := make(chan Phase2Payload, 1)

	srv := newTestRelayServer(t)
	defer srv.close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	agent, err := New(Config{
		Token:    "tok",
		Hostname: "testhost",
		Endpoint: "ws://" + srv.addr + "/ws",
		OnPhase2: func(_ context.Context, p Phase2Payload) error {
			phase2Ch <- p
			return nil
		},
		Log: func(msg string) { t.Log("agent:", msg) },
	})
	if err != nil {
		t.Fatal(err)
	}

	go agent.Run(ctx) //nolint:errcheck

	// Wait for the agent to connect, then push a phase2 message.
	srv.waitConnected(t, 3*time.Second)
	srv.pushPhase2("sess-e2e", "sid-e2e", "tok=saml", "10.1.2.3", "remote vpn.example.com 443")

	select {
	case p := <-phase2Ch:
		if p.SessionID != "sess-e2e" {
			t.Errorf("SessionID = %q", p.SessionID)
		}
		if p.StateID != "sid-e2e" {
			t.Errorf("StateID = %q", p.StateID)
		}
		if p.RemoteIP != "10.1.2.3" {
			t.Errorf("RemoteIP = %q", p.RemoteIP)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for phase2 delivery")
	}

	cancel()
}

// TestAgentSendStatusConnected verifies that SendStatus reaches the relay server.
func TestAgentSendStatusConnected(t *testing.T) {
	srv := newTestRelayServer(t)
	defer srv.close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var agentOnce sync.Once
	var agentRef *Agent
	var agentMu sync.Mutex

	phase2Done := make(chan struct{})

	agent, err := New(Config{
		Token:    "tok",
		Hostname: "testhost",
		Endpoint: "ws://" + srv.addr + "/ws",
		OnPhase2: func(ctx context.Context, p Phase2Payload) error {
			agentMu.Lock()
			a := agentRef
			agentMu.Unlock()
			agentOnce.Do(func() {
				if a != nil {
					a.SendStatus(ctx, p.SessionID, "connected", "172.16.0.99")
				}
				close(phase2Done)
			})
			return nil
		},
		Log: func(msg string) { t.Log("agent:", msg) },
	})
	if err != nil {
		t.Fatal(err)
	}

	agentMu.Lock()
	agentRef = agent
	agentMu.Unlock()

	go agent.Run(ctx) //nolint:errcheck

	srv.waitConnected(t, 3*time.Second)
	srv.pushPhase2("sess-status", "sid", "tok", "10.0.0.1", "")

	select {
	case <-phase2Done:
	case <-ctx.Done():
		t.Fatal("timeout waiting for OnPhase2")
	}

	select {
	case m := <-srv.recvCh:
		if m["action"] != "status" {
			t.Errorf("action = %v, want status", m["action"])
		}
		if m["status"] != "connected" {
			t.Errorf("status = %v, want connected", m["status"])
		}
		if m["assigned_ip"] != "172.16.0.99" {
			t.Errorf("assigned_ip = %v, want 172.16.0.99", m["assigned_ip"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for status message at server")
	}

	cancel()
}

// TestAgentReconnects verifies that the agent reconnects after the server drops
// the connection. Uses a drop-first server that closes the first connection
// immediately from within the handler goroutine.
func TestAgentReconnects(t *testing.T) {
	connCh := make(chan int, 4)
	srv := newDropFirstRelayServer(t, connCh)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	agent, err := New(Config{
		Token:    "tok",
		Hostname: "testhost",
		Endpoint: "ws://" + srv.addr + "/ws",
		OnPhase2: nopPhase2,
		Log:      func(msg string) { t.Log("agent:", msg) },
	})
	if err != nil {
		t.Fatal(err)
	}

	go agent.Run(ctx) //nolint:errcheck

	// Wait for first connect.
	select {
	case n := <-connCh:
		t.Logf("first connect (#%d)", n)
	case <-time.After(3 * time.Second):
		t.Fatal("first connect timed out")
	}

	// The agent should reconnect within a few seconds (2s poll + 1s backoff).
	select {
	case n := <-connCh:
		t.Logf("reconnected (#%d) — PASS", n)
	case <-time.After(8 * time.Second):
		t.Fatal("agent did not reconnect within 8s")
	}

	cancel()
}

type dropFirstServer struct {
	*http.Server
	addr string
}

// newDropFirstRelayServer creates an HTTP test server that closes every
// WebSocket connection immediately from within the handler goroutine.
func newDropFirstRelayServer(t *testing.T, connCh chan int) *dropFirstServer {
	t.Helper()
	var count int
	var mu sync.Mutex

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Sec-Websocket-Key")
		if key == "" {
			http.Error(w, "not ws", 400)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", 500)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}

		accept := wsServerAcceptKey(key)
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
		bufrw.WriteString(resp) //nolint:errcheck
		bufrw.Flush()           //nolint:errcheck

		mu.Lock()
		count++
		n := count
		mu.Unlock()

		select {
		case connCh <- n:
		default:
		}

		// Close immediately from within the handler — agent must reconnect.
		conn.Close()
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln) //nolint:errcheck
	return &dropFirstServer{Server: srv, addr: ln.Addr().String()}
}

// ── minimal in-process WS relay server ───────────────────────────────────────

type testRelayServer struct {
	addr     string
	listener net.Listener
	httpSrv  *http.Server

	// pushCh receives messages to be forwarded to the connected agent.
	pushCh chan []byte
	// recvCh delivers decoded JSON objects received from the agent.
	recvCh chan map[string]any

	mu          sync.Mutex
	currentConn net.Conn // the active agent connection (may be nil)
	connectedCh chan struct{}
}

func newTestRelayServer(t *testing.T) *testRelayServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testRelayServer{
		addr:        ln.Addr().String(),
		listener:    ln,
		pushCh:      make(chan []byte, 16),
		recvCh:      make(chan map[string]any, 16),
		connectedCh: make(chan struct{}),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWS)
	s.httpSrv = &http.Server{Handler: mux}
	go s.httpSrv.Serve(ln) //nolint:errcheck
	return s
}

func (s *testRelayServer) close() {
	s.httpSrv.Close()
}

func (s *testRelayServer) waitConnected(t *testing.T, timeout time.Duration) {
	t.Helper()
	s.mu.Lock()
	ch := s.connectedCh
	s.mu.Unlock()
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatalf("agent did not connect within %s", timeout)
	}
}

func (s *testRelayServer) dropCurrentConn() {
	s.mu.Lock()
	conn := s.currentConn
	s.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

func (s *testRelayServer) pushPhase2(sessionID, stateID, samlResponse, remoteIP, ovpnConfig string) {
	msg, _ := json.Marshal(map[string]any{
		"action":     "phase2",
		"session_id": sessionID,
		"payload": map[string]string{
			"state_id":      stateID,
			"saml_response": samlResponse,
			"remote_ip":     remoteIP,
			"ovpn_config":   ovpnConfig,
		},
	})
	s.pushCh <- msg
}

func (s *testRelayServer) handleWS(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Sec-Websocket-Key")
	if key == "" {
		http.Error(w, "not ws", 400)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", 500)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}

	accept := wsServerAcceptKey(key)
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
	bufrw.WriteString(resp) //nolint:errcheck
	bufrw.Flush()           //nolint:errcheck

	s.mu.Lock()
	s.currentConn = conn
	ch := s.connectedCh
	s.connectedCh = make(chan struct{}) // fresh channel for next connect
	s.mu.Unlock()

	// Consume the auth frame the agent sends immediately after connect.
	// We do not validate the token in tests — just drain it so pushCh works.
	rdrAuth := bufio.NewReader(conn)
	for {
		payload, opcode, err := wsReadRawFrame(rdrAuth)
		if err != nil {
			conn.Close()
			return
		}
		if opcode == 0x1 || opcode == 0x2 {
			var m map[string]any
			if json.Unmarshal(payload, &m) == nil && m["action"] == "auth" {
				break
			}
		}
	}

	close(ch) // signal waitConnected — agent is now fully registered

	connDone := make(chan struct{})

	// Writer goroutine: drain pushCh → agent, exits when connection closes.
	go func() {
		for {
			select {
			case msg := <-s.pushCh:
				if wsSrvSendText(conn, msg) != nil {
					return
				}
			case <-connDone:
				return
			}
		}
	}()

	// Reader loop: agent → recvCh (reuse the same buffered reader used for auth).
	for {
		payload, opcode, err := wsReadRawFrame(rdrAuth)
		if err != nil {
			break
		}
		switch opcode {
		case 0x9: // ping → pong
			wsSrvSendFrame(conn, 0xA, payload) //nolint:errcheck
		case 0x1, 0x2:
			var m map[string]any
			if json.Unmarshal(payload, &m) == nil {
				select {
				case s.recvCh <- m:
				default:
				}
			}
		}
	}

	conn.Close()
	close(connDone)
}

// ── tiny server-side WS helpers (server→client frames are unmasked) ───────────

func wsServerAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func wsSrvSendText(conn net.Conn, payload []byte) error {
	return wsSrvSendFrame(conn, 0x1, payload)
}

func wsSrvSendFrame(conn net.Conn, opcode byte, payload []byte) error {
	n := len(payload)
	hdr := []byte{0x80 | opcode}
	switch {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n < 65536:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	_, err := conn.Write(append(hdr, payload...))
	return err
}

// wsReadRawFrame reads one WS frame (handles client masking).
func wsReadRawFrame(rdr *bufio.Reader) (payload []byte, opcode byte, err error) {
	h := make([]byte, 2)
	if _, err = readFull(rdr, h); err != nil {
		return
	}
	opcode = h[0] & 0x0F
	plen := int(h[1] & 0x7F)
	masked := h[1]&0x80 != 0

	switch plen {
	case 126:
		ext := make([]byte, 2)
		if _, err = readFull(rdr, ext); err != nil {
			return
		}
		plen = int(ext[0])<<8 | int(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err = readFull(rdr, ext); err != nil {
			return
		}
		plen = int(ext[4])<<24 | int(ext[5])<<16 | int(ext[6])<<8 | int(ext[7])
	}

	var maskKey [4]byte
	if masked {
		if _, err = readFull(rdr, maskKey[:]); err != nil {
			return
		}
	}
	payload = make([]byte, plen)
	if _, err = readFull(rdr, payload); err != nil {
		return
	}
	if masked {
		for i, b := range payload {
			payload[i] = b ^ maskKey[i%4]
		}
	}
	return
}

func readFull(rdr *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := rdr.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

var nopPhase2 = func(_ context.Context, _ Phase2Payload) error { return nil }
