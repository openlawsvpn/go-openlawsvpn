// Command mockserver is the go-openlawsvpn mock OpenVPN server.
//
// It handles the full control-channel + TLS + key-method-2 auth packet exchange
// needed by integration tests. Every event is logged to stdout as one JSON
// object per line, including all fields of the client's auth packet so they can
// be compared between Go and C++ clients.
//
// Environment:
//
//	MOCK_CRV1=1              — after auth exchange, Phase 1 sends AUTH_FAILED,CRV1
//	                           instead of PUSH_REPLY; Phase 2 validates token then sends PUSH_REPLY
//	MOCK_REDIRECT_GATEWAY=1  — include "redirect-gateway def1" in PUSH_REPLY
//	                           (simulates AWS Client VPN full-tunnel mode)
//	MOCK_TCP_PORT            — TCP listen port (default 4433)
//	MOCK_UDP_PORT            — UDP listen port (default 1194)
//	CERT_DIR                 — directory containing ca.crt server.crt server.key
//	                           when unset, self-signed certs are generated in memory
//	IDP_URL                  — base URL for the CRV1 login page (default: https://openlawsvpn.com/demo/login.html)
//	DEMO_TOKEN               — fixed token the login page POSTs to the ACS server (default: OPENLAWSVPN_DEMO_2026)
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// event is a structured log line emitted to stdout.
type event struct {
	TS     int64  `json:"ts"`
	Event  string `json:"event"`
	Detail string `json:"detail,omitempty"`
}

func logEvent(name, detail string) {
	e := event{
		TS:     time.Now().UnixMilli(),
		Event:  name,
		Detail: detail,
	}
	b, _ := json.Marshal(e)
	fmt.Println(string(b))
}

func main() {
	crv1 := os.Getenv("MOCK_CRV1") == "1"
	certDir := os.Getenv("CERT_DIR")

	tcpPort := os.Getenv("MOCK_TCP_PORT")
	if tcpPort == "" {
		tcpPort = "4433"
	}
	udpPort := os.Getenv("MOCK_UDP_PORT")
	if udpPort == "" {
		udpPort = "1194"
	}

	logEvent("start", fmt.Sprintf("crv1=%v tcp=%s udp=%s cert_dir=%q", crv1, tcpPort, udpPort, certDir))

	// Load or generate server TLS credentials.
	tlsCfg, caPEM, err := loadOrGenerateTLS(certDir)
	if err != nil {
		logEvent("error", "TLS setup: "+err.Error())
		os.Exit(1)
	}
	if certDir == "" {
		// Print the in-memory CA PEM to stderr so callers can embed it in test profiles.
		fmt.Fprintf(os.Stderr, "mock-server: generated CA PEM:\n%s\n", caPEM)
	}

	// TCP listener.
	tcpLn, err := net.Listen("tcp", "0.0.0.0:"+tcpPort)
	if err != nil {
		logEvent("error", "TCP listen: "+err.Error())
		os.Exit(1)
	}

	// UDP listener.
	udpConn, err := net.ListenPacket("udp", "0.0.0.0:"+udpPort)
	if err != nil {
		// UDP failure is non-fatal — log and continue with TCP only.
		logEvent("warn", "UDP listen failed: "+err.Error())
		udpConn = nil
	}

	udpAddr := "none"
	if udpConn != nil {
		udpAddr = udpConn.LocalAddr().String()
	}
	logEvent("ready", fmt.Sprintf("tcp=%s udp=%s", tcpLn.Addr().String(), udpAddr))

	// Start UDP acceptor if available.
	if udpConn != nil {
		go serveUDP(udpConn, tlsCfg, crv1)
	}

	// TCP accept loop.
	for {
		conn, err := tcpLn.Accept()
		if err != nil {
			logEvent("error", "accept: "+err.Error())
			continue
		}
		go handleTCPConn(conn, tlsCfg, crv1)
	}
}

// ---- TLS setup ----------------------------------------------------------------

// loadOrGenerateTLS returns a *tls.Config. When certDir is non-empty it reads
// ca.crt/server.crt/server.key from that directory; otherwise it generates an
// in-memory ECDSA P-256 CA + server cert. Returns the CA PEM for embedding.
func loadOrGenerateTLS(certDir string) (*tls.Config, []byte, error) {
	if certDir != "" {
		serverCert, err := tls.LoadX509KeyPair(certDir+"/server.crt", certDir+"/server.key")
		if err != nil {
			return nil, nil, fmt.Errorf("load server cert: %w", err)
		}
		caPEM, err := os.ReadFile(certDir + "/ca.crt")
		if err != nil {
			return nil, nil, fmt.Errorf("load CA: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caPEM) {
			return nil, nil, fmt.Errorf("parse CA PEM")
		}
		cfg := &tls.Config{
			Certificates:           []tls.Certificate{serverCert},
			ClientCAs:              caPool,
			ClientAuth:             tls.RequestClientCert,
			MinVersion:             tls.VersionTLS12,
			SessionTicketsDisabled: true,
		}
		return cfg, caPEM, nil
	}

	// Generate ephemeral CA + server cert.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("gen CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mock-ca", Organization: []string{"openlawsvpn-test"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("gen server key: %w", err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "mock-server", Organization: []string{"openlawsvpn-test"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create server cert: %w", err)
	}

	// Encode for tls.X509KeyPair.
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal server key: %w", err)
	}
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	tlsCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("make tls cert: %w", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	cfg := &tls.Config{
		Certificates:           []tls.Certificate{tlsCert},
		ClientCAs:              caPool,
		ClientAuth:             tls.RequestClientCert,
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
	}
	return cfg, caPEM, nil
}

// ---- TCP handler --------------------------------------------------------------

func handleTCPConn(rawConn net.Conn, tlsCfg *tls.Config, crv1 bool) {
	defer rawConn.Close()
	remote := rawConn.RemoteAddr().String()
	logEvent("connect", "tcp "+remote)

	r := &tcpFramer{conn: rawConn}
	handleSession(r, remote, tlsCfg, crv1)
}

// ---- UDP handler --------------------------------------------------------------

// serveUDP demultiplexes UDP datagrams by client address and spawns one
// session per new source address.
func serveUDP(pc net.PacketConn, tlsCfg *tls.Config, crv1 bool) {
	// Each unique remote addr gets its own pipe-based virtual connection.
	sessions := sync.Map{}
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			logEvent("udp_error", "ReadFrom: "+err.Error())
			return
		}
		data := make([]byte, n)
		copy(data, buf[:n])

		key := addr.String()
		raw, loaded := sessions.LoadOrStore(key, make(chan []byte, 256))
		ch := raw.(chan []byte)
		if !loaded {
			// New client — start a session.
			go func(addr net.Addr, ch chan []byte) {
				defer sessions.Delete(addr.String())
				r := &udpFramer{
					recvCh: ch,
					sendFn: func(p []byte) error {
						_, err := pc.WriteTo(p, addr)
						return err
					},
				}
				handleSession(r, addr.String(), tlsCfg, crv1)
			}(addr, ch)
		}
		// Deliver datagram to the session's receive channel.
		select {
		case ch <- data:
		default:
			logEvent("udp_warn", "drop: buffer full for "+key)
		}
	}
}

// ---- framer interface --------------------------------------------------------

// framer abstracts TCP (length-prefixed) vs UDP (raw datagram) I/O.
type framer interface {
	ReadPacket() ([]byte, error)
	WritePacket([]byte) error
}

// tcpFramer wraps a net.Conn with 2-byte big-endian length prefix framing.
type tcpFramer struct{ conn net.Conn }

func (f *tcpFramer) ReadPacket() ([]byte, error) { return readTCP(f.conn) }
func (f *tcpFramer) WritePacket(p []byte) error  { return writeTCP(f.conn, p) }

// udpFramer delivers pre-read datagrams from a channel and sends via a callback.
type udpFramer struct {
	recvCh chan []byte
	sendFn func([]byte) error
}

func (f *udpFramer) ReadPacket() ([]byte, error) {
	pkt, ok := <-f.recvCh
	if !ok {
		return nil, io.EOF
	}
	return pkt, nil
}
func (f *udpFramer) WritePacket(p []byte) error { return f.sendFn(p) }

// ---- session handler ---------------------------------------------------------

// handleSession runs the full OpenVPN3 server-side protocol:
//  1. HARD_RESET exchange
//  2. TLS handshake over P_CONTROL_V1 framing
//  3. Key-method-2 auth packet exchange (server reads client auth, sends server auth)
//  4. Read PUSH_REQUEST
//  5. Send CRV1 challenge (if crv1=true) or PUSH_REPLY
//  6. In CRV1 mode: read Phase 2 credential, send PUSH_REPLY
func handleSession(f framer, remote string, tlsCfg *tls.Config, crv1 bool) {
	// ---- HARD_RESET ----
	pkt, err := f.ReadPacket()
	if err != nil {
		logEvent("error", "read hard_reset: "+err.Error())
		return
	}
	if len(pkt) < 1 {
		logEvent("error", "empty packet from "+remote)
		return
	}
	opcode := pkt[0] >> 3
	if opcode != opcodeHardResetClientV2 {
		logEvent("error", fmt.Sprintf("unexpected opcode 0x%02x from %s", opcode, remote))
		return
	}
	var clientSID [8]byte
	if len(pkt) >= 9 {
		copy(clientSID[:], pkt[1:9])
	}
	logEvent("hard_reset_client", fmt.Sprintf("remote=%s session_id=%x", remote, clientSID))

	var serverSID [8]byte
	now := uint64(time.Now().UnixNano())
	binary.BigEndian.PutUint64(serverSID[:], now)

	reply := buildHardResetServer(serverSID, clientSID)
	if err := f.WritePacket(reply); err != nil {
		logEvent("error", "write hard_reset_server: "+err.Error())
		return
	}
	logEvent("hard_reset_server", fmt.Sprintf("session_id=%x", serverSID))

	// ---- TLS handshake via P_CONTROL_V1 relay ----
	tlsPipe1, tlsPipe2 := net.Pipe()
	defer tlsPipe1.Close()
	defer tlsPipe2.Close()

	// Sequence counters start at 1: packet_id=0 was used by HARD_RESET on
	// both sides, so the first P_CONTROL_V1 packet in either direction uses
	// packet_id=1.  (Matches openvpn3-core reliable.hpp counter behaviour.)
	var recvExp uint32 = 1
	var sendSeq uint32 = 1
	// writeMu serialises all writes to f so the ACK send in the read relay
	// and the fragment send in the write relay do not race.
	var writeMu sync.Mutex

	writePacket := func(pkt []byte) {
		writeMu.Lock()
		f.WritePacket(pkt) //nolint:errcheck
		writeMu.Unlock()
	}

	// rawConn → TLS: strip P_CONTROL_V1 framing, feed TLS bytes.
	go func() {
		defer tlsPipe1.Close()
		for {
			data, err := f.ReadPacket()
			if err != nil {
				if err != io.EOF {
					logEvent("relay_error", "read: "+err.Error())
				}
				return
			}
			if len(data) < 1 {
				continue
			}
			op := data[0] >> 3
			switch op {
			case opcodeControlV1:
				payload, packetID, _ := parseControlV1(data, clientSID)
				// Always ACK, even out-of-order packets.
				ack := buildAck(serverSID, clientSID, []uint32{packetID})
				writePacket(ack)
				if packetID == recvExp {
					recvExp++
					if len(payload) > 0 {
						if _, err := tlsPipe1.Write(payload); err != nil {
							return
						}
					}
				}
			case opcodeAckV1:
				// client ACKing our outbound packets — nothing to do
			}
		}
	}()

	// TLS → rawConn: wrap in P_CONTROL_V1.
	go func() {
		buf := make([]byte, 16384)
		for {
			n, err := tlsPipe1.Read(buf)
			if err != nil {
				return
			}
			payload := buf[:n]
			for len(payload) > 0 {
				chunk := payload
				if len(chunk) > 1024 {
					chunk = payload[:1024]
				}
				payload = payload[len(chunk):]
				writeMu.Lock()
				seq := sendSeq
				sendSeq++
				writeMu.Unlock()
				pkt := buildControlV1(serverSID, clientSID, seq, nil, chunk)
				writePacket(pkt)
			}
		}
	}()

	tlsConn := tls.Server(tlsPipe2, tlsCfg)
	tlsConn.SetDeadline(time.Now().Add(30 * time.Second)) //nolint:errcheck
	if err := tlsConn.Handshake(); err != nil {
		logEvent("tls_error", "handshake: "+err.Error())
		return
	}
	tlsConn.SetDeadline(time.Time{}) //nolint:errcheck
	cs := tlsConn.ConnectionState()
	logEvent("tls_ok", fmt.Sprintf("remote=%s version=0x%04x cipher=0x%04x peer_certs=%d",
		remote, cs.Version, cs.CipherSuite, len(cs.PeerCertificates)))

	// ---- Auth packet exchange ----
	// Order (openvpn3-core ssl/proto.hpp):
	//   1. Client sends its auth packet first.
	//   2. Server reads client auth packet and logs all fields in plaintext.
	//   3. Server sends its own auth packet in response.
	authInfo, raw, err := readClientAuthPacket(tlsConn)
	if err != nil {
		logEvent("error", "read client auth: "+err.Error())
		return
	}
	awsClient := len(raw) >= 4 && (int(raw[0])|int(raw[1])<<8|int(raw[2])<<16|int(raw[3])<<24) >= 85
	logEvent("auth_packet_recv", authInfo)

	serverAuthPkt := buildServerAuthPacket(awsClient)
	if _, err := tlsConn.Write(serverAuthPkt); err != nil {
		logEvent("error", "write server auth: "+err.Error())
		return
	}
	logEvent("server_auth_sent", fmt.Sprintf("len=%d", len(serverAuthPkt)))

	// ---- Read PUSH_REQUEST ----
	buf2 := make([]byte, 4096)
	n, err := tlsConn.Read(buf2)
	if err != nil {
		logEvent("error", "read push_request: "+err.Error())
		return
	}
	msg := strings.TrimRight(string(buf2[:n]), "\x00")
	logEvent("push_request", msg)

	if crv1 {
		// CRV1 mode: Phase 1 — check whether this is a Phase 1 or Phase 2 connection
		// by inspecting the password field already parsed above.
		pwdPrefix := authInfoField(authInfo, "password_prefix")
		if strings.HasPrefix(pwdPrefix, "CRV1::") {
			// This is a Phase 2 connection — validate stateID and send PUSH_REPLY.
			// The stateID is embedded in the password: CRV1::<stateID>::<token>
			handleCRV1Phase2(tlsConn, authInfo, remote)
			return
		}
		// Phase 1 — send CRV1 challenge.
		stateID := strconv.FormatInt(time.Now().UnixNano(), 16)
		idpBase := os.Getenv("IDP_URL")
		if idpBase == "" {
			idpBase = "https://openlawsvpn.com/demo/login.html"
		}
		samlURL := idpBase + "?state=" + stateID
		challenge := "AUTH_FAILED,CRV1:R:" + stateID + "::" + samlURL + "\x00"
		if _, err := tlsConn.Write([]byte(challenge)); err != nil {
			logEvent("error", "write crv1 challenge: "+err.Error())
			return
		}
		logEvent("crv1_challenge_sent", "state_id="+stateID)
		// Phase 1 done — client will open a new TCP connection for Phase 2.
		io.Copy(io.Discard, tlsConn) //nolint:errcheck
		logEvent("disconnect", remote)
		return
	}

	// Normal mode: PUSH_REPLY.
	pushReply := buildPushReply()
	if _, err := tlsConn.Write([]byte(pushReply)); err != nil {
		logEvent("error", "write push_reply: "+err.Error())
		return
	}
	logEvent("push_reply", "sent to "+remote)
	io.Copy(io.Discard, tlsConn) //nolint:errcheck
	logEvent("disconnect", remote)
}

// handleCRV1Phase2 handles a Phase 2 connection in CRV1 mode.
// The client has already sent its auth packet with password="CRV1::<stateID>::<token>".
// We just validate the format and send PUSH_REPLY.
func handleCRV1Phase2(tlsConn *tls.Conn, authInfo string, remote string) {
	password := authInfoField(authInfo, "password")
	const crv1Prefix = "CRV1::"
	if !strings.HasPrefix(password, crv1Prefix) {
		logEvent("crv1_phase2_error", "unexpected password format: "+password[:min(len(password), 40)])
		tlsConn.Write([]byte("AUTH_FAILED\x00")) //nolint:errcheck
		return
	}
	rest := password[len(crv1Prefix):]
	sepIdx := strings.Index(rest, "::")
	if sepIdx < 0 {
		logEvent("crv1_phase2_error", "missing :: in CRV1 password")
		tlsConn.Write([]byte("AUTH_FAILED\x00")) //nolint:errcheck
		return
	}
	stateID := rest[:sepIdx]
	token := rest[sepIdx+2:]

	demoToken := os.Getenv("DEMO_TOKEN")
	if demoToken == "" {
		demoToken = "DEMO2026OPENLAWS"
	}
	if token != demoToken {
		logEvent("crv1_phase2_rejected", fmt.Sprintf("state_id=%s bad_token_len=%d", stateID, len(token)))
		tlsConn.Write([]byte("AUTH_FAILED\x00")) //nolint:errcheck
		return
	}
	logEvent("crv1_phase2_ok", fmt.Sprintf("state_id=%s", stateID))

	pushReply := buildPushReply()
	if _, err := tlsConn.Write([]byte(pushReply)); err != nil {
		logEvent("error", "write push_reply (crv1 phase2): "+err.Error())
		return
	}
	logEvent("push_reply", "sent after crv1 phase2 to "+remote)
	io.Copy(io.Discard, tlsConn) //nolint:errcheck
	logEvent("disconnect", remote)
}

// ---- Auth packet helpers -----------------------------------------------------

// serverAuthOptions is the options string the server sends in its auth packet.
// Must be a valid V4 options string; the client validates that it starts with "V4".
const serverAuthOptions = "V4,dev-type tun,link-mtu 1521,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-server"

// buildServerAuthPacket constructs the server side of the key-method-2 handshake.
//
// When awsFormat is true, uses the AWS large-token patched wire format:
//
//	[total_len uint32_le][0x02][random 64B][uint32_be strings...]
//
// When awsFormat is false, uses stock OpenVPN CE format:
//
//	[0x00 0x00 0x00 0x00][0x02][random 64B][uint16_be strings...]
func buildServerAuthPacket(awsFormat bool) []byte {
	var body []byte
	body = append(body, 0x02) // key_method

	rnd := make([]byte, 64)
	rand.Read(rnd) //nolint:errcheck
	body = append(body, rnd...)

	if awsFormat {
		body = append(body, authStr(serverAuthOptions)...)
		body = append(body, authStr("")...)
		body = append(body, authStr("")...)
		body = append(body, authStr("")...)
		totalLen := uint32(4 + len(body))
		buf := []byte{byte(totalLen), byte(totalLen >> 8), byte(totalLen >> 16), byte(totalLen >> 24)}
		return append(buf, body...)
	}

	// Stock format: uint16_be length-prefixed strings, 4-byte zero header.
	body = append(body, authStr16(serverAuthOptions)...)
	body = append(body, authStr16("")...)
	body = append(body, authStr16("")...)
	body = append(body, authStr16("")...)
	return append([]byte{0x00, 0x00, 0x00, 0x00}, body...)
}

// readClientAuthPacket reads and parses the client's key-method-2 auth packet.
// Returns a JSON-encoded summary string for logging, plus the raw bytes.
//
// Two wire formats are auto-detected from the 4-byte header:
//
// AWS large-token patched format (awsFormat, totalLen >= 85):
//
//	[total_len uint32_le]                        4-byte LE total length
//	[0x02]                                       key_method byte
//	[pre_master 48B][random1 32B][random2 32B]   = 112 bytes TLSPRF
//	[uint32_be(len+1)][options\0]
//	[uint32_be(len+1)][username\0]
//	[uint32_be(len+1)][password\0]
//	[uint32_be(len+1)][peer_info\0]
//
// Stock OpenVPN CE format (header == 0x00000000):
//
//	[0x00 0x00 0x00 0x00]                        literal zero prefix
//	[0x02]                                       key_method byte
//	[pre_master 48B][random1 32B][random2 32B]   = 112 bytes TLSPRF
//	[uint16_be(len+1)][options\0]
//	[uint16_be(len+1)][username\0]
//	[uint16_be(len+1)][password\0]
//	[uint16_be(len+1)][peer_info\0]
func readClientAuthPacket(r io.Reader) (info string, raw []byte, err error) {
	// Read the 4-byte header — either LE total length (AWS) or 0x00000000 (stock).
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return "", nil, fmt.Errorf("read header: %w", err)
	}
	totalLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16 | int(hdr[3])<<24

	if totalLen >= 85 && totalLen <= 1<<21 {
		// AWS format: hdr is uint32_le total packet length.
		body := make([]byte, totalLen-4)
		if _, err := io.ReadFull(r, body); err != nil {
			return "", nil, fmt.Errorf("read body (totalLen=%d): %w", totalLen, err)
		}
		raw = append(hdr, body...)

		if len(body) < 1 || body[0] != 0x02 {
			return buildAuthInfo("(bad_key_method)", "", "", "", totalLen), raw, nil
		}
		off := 1
		const tlsPRFSize = 112
		if off+tlsPRFSize > len(body) {
			return buildAuthInfo("(short_after_key_method)", "", "", "", totalLen), raw, nil
		}
		off += tlsPRFSize
		// uint32_be length-prefixed strings.
		options, off2 := parseAuthStr(body, off)
		username, off3 := parseAuthStr(body, off2)
		password, off4 := parseAuthStr(body, off3)
		peerInfo, _ := parseAuthStr(body, off4)
		return buildAuthInfo(options, username, password, peerInfo, totalLen), raw, nil
	}

	// Stock OpenVPN CE format: header is 0x00000000, next byte is key_method.
	// Read the rest: key_method(1) + TLSPRF(112) + strings.
	// We read up to 8 KiB which is more than enough for any stock auth packet.
	rest := make([]byte, 8192)
	n, err2 := r.Read(rest)
	if err2 != nil && n == 0 {
		return "", nil, fmt.Errorf("read stock body: %w", err2)
	}
	body := rest[:n]
	raw = append(hdr, body...)

	if len(body) < 1 || body[0] != 0x02 {
		return buildAuthInfo("(bad_key_method_stock)", "", "", "", 4+n), raw, nil
	}
	off := 1
	const tlsPRFSize = 112
	if off+tlsPRFSize > len(body) {
		return buildAuthInfo("(short_after_key_method_stock)", "", "", "", 4+n), raw, nil
	}
	off += tlsPRFSize
	// uint16_be length-prefixed strings.
	options, off2 := parseAuthStr16(body, off)
	username, off3 := parseAuthStr16(body, off2)
	password, off4 := parseAuthStr16(body, off3)
	peerInfo, _ := parseAuthStr16(body, off4)
	return buildAuthInfo(options, username, password, peerInfo, 4+n), raw, nil
}

// buildAuthInfo formats the parsed auth packet fields as a JSON string for logEvent.
func buildAuthInfo(options, username, password, peerInfo string, totalBytes int) string {
	pwdPrefix := password
	if len(pwdPrefix) > 80 {
		pwdPrefix = pwdPrefix[:80] + "..."
	}
	// Encode as JSON object for structured parsing.
	type authLog struct {
		TotalBytes     int    `json:"total_bytes"`
		Options        string `json:"options"`
		Username       string `json:"username"`
		Password       string `json:"password"`
		PasswordLen    int    `json:"password_len"`
		PasswordPrefix string `json:"password_prefix"`
		PeerInfo       string `json:"peer_info"`
	}
	al := authLog{
		TotalBytes:     totalBytes,
		Options:        options,
		Username:       username,
		Password:       password,
		PasswordLen:    len(password),
		PasswordPrefix: pwdPrefix,
		PeerInfo:       peerInfo,
	}
	b, _ := json.Marshal(al)
	return string(b)
}

// authInfoField extracts a named field from the JSON-encoded authInfo string.
// Returns empty string if not found.
func authInfoField(authInfo, field string) string {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(authInfo), &m); err != nil {
		return ""
	}
	if v, ok := m[field]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// parseAuthStr reads a uint32_be-length-prefixed NUL-terminated string from buf
// starting at off. Returns the string (without NUL) and the new offset.
// An empty field is encoded as four zero bytes (length=0, no NUL).
// Uses 32-bit prefixes matching the AWS large-token ssl.c patch.
func parseAuthStr(buf []byte, off int) (string, int) {
	if off+4 > len(buf) {
		return "", off
	}
	length := int(binary.BigEndian.Uint32(buf[off:]))
	off += 4
	if length == 0 {
		return "", off
	}
	end := off + length
	if end > len(buf) {
		end = len(buf)
	}
	s := strings.TrimRight(string(buf[off:end]), "\x00")
	return s, end
}

// parseAuthStr16 reads a uint16_be-length-prefixed NUL-terminated string.
// Used for stock OpenVPN CE wire format.
func parseAuthStr16(buf []byte, off int) (string, int) {
	if off+2 > len(buf) {
		return "", off
	}
	length := int(binary.BigEndian.Uint16(buf[off:]))
	off += 2
	if length == 0 {
		return "", off
	}
	end := off + length
	if end > len(buf) {
		end = len(buf)
	}
	s := strings.TrimRight(string(buf[off:end]), "\x00")
	return s, end
}

// authStr encodes s as a uint32_be-length-prefixed NUL-terminated string.
// An empty string is encoded as [0x00 0x00 0x00 0x00] (length=0, no NUL).
// Uses 32-bit prefixes matching the AWS large-token ssl.c patch.
func authStr(s string) []byte {
	if s == "" {
		return []byte{0x00, 0x00, 0x00, 0x00}
	}
	l := uint32(len(s) + 1)
	b := []byte{byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
	b = append(b, s...)
	b = append(b, 0x00)
	return b
}

// authStr16 encodes s as a uint16_be-length-prefixed NUL-terminated string.
// Empty string: uint16_be(1) + NUL — matches stock OpenVPN CE encoding.
func authStr16(s string) []byte {
	if s == "" {
		return []byte{0x00, 0x01, 0x00}
	}
	l := uint16(len(s) + 1)
	b := []byte{byte(l >> 8), byte(l)}
	b = append(b, s...)
	b = append(b, 0x00)
	return b
}

// buildPushReply returns a PUSH_REPLY options string suitable for basic tests.
// When MOCK_REDIRECT_GATEWAY=1 is set, the reply includes "redirect-gateway def1"
// to simulate AWS Client VPN full-tunnel mode (all traffic via the VPN).
func buildPushReply() string {
	base := "PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,route 10.8.0.0 255.255.0.0," +
		"dhcp-option DNS 10.8.0.1,cipher AES-256-GCM," +
		"ping 10,ping-restart 60," +
		"key-derivation tls-ekm"
	if os.Getenv("MOCK_REDIRECT_GATEWAY") == "1" {
		base += ",redirect-gateway def1"
	}
	return base + "\x00"
}

// min returns the smaller of a and b.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---- TCP framing -------------------------------------------------------------

func readTCP(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n == 0 {
		return nil, fmt.Errorf("zero-length packet")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeTCP(w io.Writer, data []byte) error {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// ---- OpenVPN packet builders -------------------------------------------------

const (
	opcodeHardResetClientV2 = 0x07
	opcodeHardResetServerV2 = 0x08
	opcodeControlV1         = 0x04
	opcodeAckV1             = 0x05
)

// buildHardResetServer constructs a P_CONTROL_HARD_RESET_SERVER_V2 packet
// that ACKs the client's packet 0 and carries server packet_id=0.
func buildHardResetServer(serverSID, clientSID [8]byte) []byte {
	var b []byte
	b = append(b, byte(opcodeHardResetServerV2<<3))
	b = append(b, serverSID[:]...)
	b = append(b, 1)             // ack_array_len=1
	b = append(b, 0, 0, 0, 0)   // ACK client packet 0
	b = append(b, clientSID[:]...) // remote_session_id
	b = append(b, 0, 0, 0, 0)   // server packet_id=0
	return b
}

// parseControlV1 extracts the TLS payload, packet ID, and ACKed IDs from a
// P_CONTROL_V1 packet.
func parseControlV1(pkt []byte, _ [8]byte) (payload []byte, packetID uint32, ackIDs []uint32) {
	if len(pkt) < 10 {
		return
	}
	offset := 1 + 8 // opcode + session_id
	ackLen := int(pkt[offset])
	offset++
	if ackLen > 0 {
		for i := 0; i < ackLen; i++ {
			if offset+4 > len(pkt) {
				return
			}
			id := binary.BigEndian.Uint32(pkt[offset:])
			ackIDs = append(ackIDs, id)
			offset += 4
		}
		if offset+8 > len(pkt) {
			return
		}
		offset += 8 // remote_session_id
	}
	if offset+4 > len(pkt) {
		return
	}
	packetID = binary.BigEndian.Uint32(pkt[offset:])
	offset += 4
	payload = pkt[offset:]
	return
}

// buildControlV1 builds a P_CONTROL_V1 packet.
func buildControlV1(serverSID, clientSID [8]byte, packetID uint32, ackIDs []uint32, payload []byte) []byte {
	var b []byte
	b = append(b, byte(opcodeControlV1<<3))
	b = append(b, serverSID[:]...)
	if len(ackIDs) > 0 {
		b = append(b, byte(len(ackIDs)))
		for _, id := range ackIDs {
			b = append(b, byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
		}
		b = append(b, clientSID[:]...)
	} else {
		b = append(b, 0)
	}
	b = append(b, byte(packetID>>24), byte(packetID>>16), byte(packetID>>8), byte(packetID))
	b = append(b, payload...)
	return b
}

// buildAck builds a P_ACK_V1 packet.
func buildAck(serverSID, clientSID [8]byte, ackIDs []uint32) []byte {
	var b []byte
	b = append(b, byte(opcodeAckV1<<3))
	b = append(b, serverSID[:]...)
	b = append(b, byte(len(ackIDs)))
	for _, id := range ackIDs {
		b = append(b, byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
	}
	b = append(b, clientSID[:]...)
	return b
}
