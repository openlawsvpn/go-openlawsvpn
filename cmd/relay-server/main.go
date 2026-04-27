// Command relay-server is a zero-dependency, in-memory relay server for local testing.
//
// It implements the same wire protocol as the production AWS relay (API GW WebSocket +
// HTTP REST) but runs as a single process with no storage, no token validation, and no
// TLS — suitable for LAN testing with the CLI agent and the Android app.
//
// Usage:
//
//	relay-server [-addr :18080]
//
//	# CLI agent (same machine or LAN):
//	ovpn3 -config tunnel.ovpn -relay mytoken -relay-endpoint ws://192.168.1.12:18080/ws
//
//	# Android app: set relay endpoint to http://192.168.1.12:18080/api/v1
//	#              and org token to  mytoken
//
// Endpoints:
//
//	WS  /ws                          Agent connects here
//	GET /api/v1/agents?token=        List registered agents
//	POST /api/v1/connect             Reserve an agent, create session
//	POST /api/v1/session/:id/execute Deliver Phase 2 credentials to agent
//
// Everything is kept in memory. Restart clears all state.
// Zero-trust mode: any token is accepted, no validation.
package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ── In-memory store ──────────────────────────────────────────────────────────

type agentRecord struct {
	Token      string
	AgentID    string
	Hostname   string
	Status     string // standby | connecting | connected | offline
	AssignedIP string
	ConnID     string // opaque key for the active WS connection
}

type sessionRecord struct {
	SessionID string
	Token     string
	AgentID   string
	State     string // initiated | phase2 | connected | failed
}

type store struct {
	mu       sync.RWMutex
	agents   map[string]*agentRecord   // agentID → record
	sessions map[string]*sessionRecord // sessionID → record
	// connID → write channel (relay → agent)
	conns map[string]chan []byte
}

func newStore() *store {
	return &store{
		agents:   make(map[string]*agentRecord),
		sessions: make(map[string]*sessionRecord),
		conns:    make(map[string]chan []byte),
	}
}

func (s *store) registerAgent(token, agentID, hostname, connID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[agentID] = &agentRecord{
		Token:    token,
		AgentID:  agentID,
		Hostname: hostname,
		Status:   "standby",
		ConnID:   connID,
	}
	s.conns[connID] = make(chan []byte, 16)
	log.Printf("agent registered: id=%s hostname=%s token=%s", agentID, hostname, token)
}

func (s *store) unregisterConn(connID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.agents {
		if a.ConnID == connID {
			a.Status = "offline"
			a.ConnID = ""
			log.Printf("agent offline: id=%s", a.AgentID)
		}
	}
	if ch, ok := s.conns[connID]; ok {
		close(ch)
		delete(s.conns, connID)
	}
}

func (s *store) listAgents(token string) []agentRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []agentRecord
	for _, a := range s.agents {
		if a.Token == token && a.Status != "offline" {
			out = append(out, *a)
		}
	}
	return out
}

func (s *store) getAgent(agentID string) *agentRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a := s.agents[agentID]
	if a == nil {
		return nil
	}
	cp := *a
	return &cp
}

func (s *store) setAgentStatus(agentID, status, assignedIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.agents[agentID]; ok {
		a.Status = status
		if assignedIP != "" {
			a.AssignedIP = assignedIP
		}
	}
}

func (s *store) createSession(token, agentID string) string {
	sid := newID()
	s.mu.Lock()
	s.sessions[sid] = &sessionRecord{
		SessionID: sid,
		Token:     token,
		AgentID:   agentID,
		State:     "initiated",
	}
	if a, ok := s.agents[agentID]; ok {
		a.Status = "connecting"
	}
	s.mu.Unlock()
	return sid
}

func (s *store) getSession(sid string) *sessionRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.sessions[sid]
	if r == nil {
		return nil
	}
	cp := *r
	return &cp
}

func (s *store) pushToAgent(agentID string, msg []byte) bool {
	s.mu.RLock()
	a := s.agents[agentID]
	var ch chan []byte
	if a != nil && a.ConnID != "" {
		ch = s.conns[a.ConnID]
	}
	s.mu.RUnlock()
	if ch == nil {
		return false
	}
	select {
	case ch <- msg:
		return true
	default:
		return false
	}
}

func (s *store) connChan(connID string) chan []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.conns[connID]
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

type server struct {
	st *store
}

func (srv *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/ws":
		srv.handleWS(w, r)
	case path == "/api/v1/agents" && r.Method == http.MethodGet:
		srv.handleListAgents(w, r)
	case path == "/api/v1/connect" && r.Method == http.MethodPost:
		srv.handleConnect(w, r)
	case strings.HasPrefix(path, "/api/v1/session/") && strings.HasSuffix(path, "/execute") && r.Method == http.MethodPost:
		parts := strings.Split(strings.TrimPrefix(path, "/api/v1/session/"), "/")
		if len(parts) == 2 {
			srv.handleExecute(w, r, parts[0])
		} else {
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}

func (srv *server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	agents := srv.st.listAgents(token)
	type agentJSON struct {
		AgentID    string `json:"agent_id"`
		Hostname   string `json:"hostname"`
		Status     string `json:"status"`
		AssignedIP string `json:"assigned_ip,omitempty"`
	}
	out := make([]agentJSON, 0, len(agents))
	for _, a := range agents {
		out = append(out, agentJSON{a.AgentID, a.Hostname, a.Status, a.AssignedIP})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out) //nolint:errcheck
}

func (srv *server) handleConnect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token   string `json:"token"`
		AgentID string `json:"agent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	a := srv.st.getAgent(body.AgentID)
	if a == nil {
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}
	if a.Status != "standby" {
		http.Error(w, "agent not standby", http.StatusConflict)
		return
	}
	sid := srv.st.createSession(body.Token, body.AgentID)
	log.Printf("session created: id=%s agent=%s", sid, body.AgentID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"session_id": sid}) //nolint:errcheck
}

func (srv *server) handleExecute(w http.ResponseWriter, r *http.Request, sessionID string) {
	sess := srv.st.getSession(sessionID)
	if sess == nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	var body struct {
		OvpnConfig   string `json:"ovpn_config"`
		StateID      string `json:"state_id"`
		SAMLResponse string `json:"saml_response"`
		RemoteIP     string `json:"remote_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	a := srv.st.getAgent(sess.AgentID)
	if a == nil || a.ConnID == "" {
		http.Error(w, "agent_gone", http.StatusConflict)
		return
	}

	push, _ := json.Marshal(map[string]any{
		"action":     "phase2",
		"session_id": sessionID,
		"payload": map[string]string{
			"state_id":      body.StateID,
			"saml_response": body.SAMLResponse,
			"remote_ip":     body.RemoteIP,
			"ovpn_config":   body.OvpnConfig,
		},
	})

	if !srv.st.pushToAgent(sess.AgentID, push) {
		http.Error(w, "push failed", http.StatusInternalServerError)
		return
	}
	log.Printf("phase2 delivered: session=%s agent=%s", sessionID, sess.AgentID)
	w.WriteHeader(http.StatusOK)
}

// ── Minimal WebSocket server ──────────────────────────────────────────────────

func (srv *server) handleWS(w http.ResponseWriter, r *http.Request) {
	// WebSocket upgrade — respond with 101.
	key := r.Header.Get("Sec-Websocket-Key")
	if key == "" {
		http.Error(w, "not a websocket request", http.StatusBadRequest)
		return
	}

	token    := r.URL.Query().Get("token")
	hostname := r.URL.Query().Get("hostname")
	agentID  := r.URL.Query().Get("agent_id")
	if token == "" || hostname == "" || agentID == "" {
		http.Error(w, "missing token/hostname/agent_id", http.StatusBadRequest)
		return
	}

	// Hijack the connection before writing the 101 response.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		log.Printf("ws hijack: %v", err)
		return
	}
	defer conn.Close()

	// Send 101 Switching Protocols.
	accept := wsAcceptKey(key)
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := bufrw.WriteString(resp); err != nil {
		return
	}
	if err := bufrw.Flush(); err != nil {
		return
	}

	connID := newID()
	srv.st.registerAgent(token, agentID, hostname, connID)
	defer srv.st.unregisterConn(connID)

	outCh := srv.st.connChan(connID)
	done := make(chan struct{})

	// Writer goroutine: pushes messages from the channel to the WS.
	go func() {
		defer close(done)
		for msg := range outCh {
			if err := wsSendText(conn, msg); err != nil {
				return
			}
		}
	}()

	// Reader loop: handles pings, status, logs from the agent.
	rdr := bufio.NewReaderSize(conn, 64*1024)
	for {
		conn.SetReadDeadline(time.Now().Add(90 * time.Second)) //nolint:errcheck
		payload, opcode, err := wsReadFrame(rdr)
		if err != nil {
			break
		}
		switch opcode {
		case 0x8: // close
			goto done
		case 0x9: // ping
			_ = wsSendFrame(conn, 0xA, payload)
		case 0x1, 0x2: // text/binary
			srv.handleAgentMessage(agentID, payload)
		}
	}
done:
	<-done
}

func (srv *server) handleAgentMessage(agentID string, payload []byte) {
	var msg struct {
		Action     string `json:"action"`
		Status     string `json:"status"`
		AssignedIP string `json:"assigned_ip"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return
	}
	if msg.Action == "status" {
		srv.st.setAgentStatus(agentID, msg.Status, msg.AssignedIP)
		log.Printf("agent status: id=%s status=%s ip=%s", agentID, msg.Status, msg.AssignedIP)
	}
}

// ── WebSocket frame helpers ───────────────────────────────────────────────────

func wsReadFrame(rdr *bufio.Reader) (payload []byte, opcode byte, err error) {
	h := make([]byte, 2)
	if _, err = io.ReadFull(rdr, h); err != nil {
		return
	}
	opcode = h[0] & 0x0F
	plen := int(h[1] & 0x7F)
	switch plen {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(rdr, ext); err != nil {
			return
		}
		plen = int(ext[0])<<8 | int(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(rdr, ext); err != nil {
			return
		}
		plen = int(ext[4])<<24 | int(ext[5])<<16 | int(ext[6])<<8 | int(ext[7])
	}
	masked := h[1]&0x80 != 0
	var maskKey [4]byte
	if masked {
		if _, err = io.ReadFull(rdr, maskKey[:]); err != nil {
			return
		}
	}
	payload = make([]byte, plen)
	if _, err = io.ReadFull(rdr, payload); err != nil {
		return
	}
	if masked {
		for i, b := range payload {
			payload[i] = b ^ maskKey[i%4]
		}
	}
	return
}

func wsSendText(conn net.Conn, payload []byte) error {
	return wsSendFrame(conn, 0x1, payload)
}

func wsSendFrame(conn net.Conn, opcode byte, payload []byte) error {
	n := len(payload)
	var hdr []byte
	hdr = append(hdr, 0x80|opcode)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n < 65536:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	_, err := conn.Write(append(hdr, payload...))
	return err
}

// wsAcceptKey computes Sec-WebSocket-Accept per RFC 6455 §4.2.2.
func wsAcceptKey(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + magic)) //nolint:errcheck
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func newID() string {
	var b [16]byte
	for i := range b {
		b[i] = byte(rand.IntN(256))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	addr := flag.String("addr", ":18080", "listen address")
	flag.Parse()

	st  := newStore()
	srv := &server{st: st}

	log.Printf("relay-server listening on %s", *addr)
	log.Printf("  Agent WS endpoint:  ws://<host>%s/ws", *addr)
	log.Printf("  App  API endpoint:  http://<host>%s/api/v1", *addr)
	log.Fatal(http.ListenAndServe(*addr, srv))
}
