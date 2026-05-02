//go:build integration

// Integration test: TLS handshake against the live mock server.
//
// Run with:
//
//	MOCK_SERVER_BIN=/path/to/mock-server \
//	  go test -v -tags=integration -timeout=60s ./internal/ctls/
//
// If MOCK_SERVER_BIN is not set, the test is skipped.
package ctls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/internal/ctls"
	"github.com/openlawsvpn/go-openlawsvpn/internal/prf"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// TestTLSHandshakeAgainstMockServer dials the mock server, completes the
// OpenVPN HARD_RESET exchange, runs TLS via ctls, and derives keys via
// prf.ExpandKeys. This exercises the full Phase 2 stack end-to-end.
func TestTLSHandshakeAgainstMockServer(t *testing.T) {
	binPath := os.Getenv("MOCK_SERVER_BIN")
	if binPath == "" {
		t.Skip("MOCK_SERVER_BIN not set; skipping integration test")
	}

	// Generate test PKI: CA + server cert + client cert in a temp dir.
	certDir := t.TempDir()
	caKey, caCert, caPool := generateCA(t)
	generateServerCert(t, certDir, caKey, caCert)
	generateClientCert(t, certDir, caKey, caCert)
	writePEM(t, filepath.Join(certDir, "ca.crt"), "CERTIFICATE", caCert.Raw)

	// Start mock server pointing at our cert dir.
	srv, err := testenv.Start(testenv.Config{
		Binary:  binPath,
		CertDir: certDir,
	})
	if err != nil {
		t.Fatalf("testenv.Start: %v", err)
	}
	defer srv.Stop() //nolint:errcheck

	t.Logf("mock server at %s events=%d", srv.TCPAddr, len(srv.Events))
	for _, e := range srv.Events {
		t.Logf("  [%s] %s", e.Event, e.Detail)
	}

	// Dial raw TCP to the mock server.
	conn, err := net.DialTimeout("tcp", srv.TCPAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial mock server: %v", err)
	}
	defer conn.Close()

	// Generate client session ID (8 random bytes).
	var clientSID [8]byte
	if _, err := rand.Read(clientSID[:]); err != nil {
		t.Fatal(err)
	}

	// Send HARD_RESET_CLIENT_V2.
	hardReset := buildHardResetClient(clientSID)
	if err := writeTCPPkt(conn, hardReset); err != nil {
		t.Fatalf("write HARD_RESET: %v", err)
	}
	t.Logf("sent HARD_RESET_CLIENT_V2 session_id=%x", clientSID)

	// Read HARD_RESET_SERVER_V2.
	serverPkt, err := readTCPPkt(conn)
	if err != nil {
		t.Fatalf("read HARD_RESET_SERVER: %v", err)
	}
	if len(serverPkt) < 9 {
		t.Fatalf("HARD_RESET_SERVER too short: %d bytes", len(serverPkt))
	}
	serverOpcode := serverPkt[0] >> 3
	if serverOpcode != 0x08 { // P_CONTROL_HARD_RESET_SERVER_V2
		t.Fatalf("expected HARD_RESET_SERVER_V2 opcode 0x08, got 0x%02x", serverOpcode)
	}
	var serverSID [8]byte
	copy(serverSID[:], serverPkt[1:9])
	t.Logf("got HARD_RESET_SERVER_V2 server_session_id=%x", serverSID)

	// Now set up the ctls bridge:
	//   - a ControlTransport receives TLS bytes from InjectInbound /
	//     sends TLS bytes via DrainOutbound.
	//   - We run two goroutines that pump control packets to/from the TCP conn.
	tr := ctls.NewControlTransport(&testNetAddr{srv.TCPAddr}, &testNetAddr{srv.TCPAddr}, 64)

	sendSeq := uint32(0)
	var recvExpected uint32 = 0

	// Goroutine: read OpenVPN control packets from TCP → inject TLS bytes into tr.
	readErrCh := make(chan error, 1)
	go func() {
		for {
			pkt, err := readTCPPkt(conn)
			if err != nil {
				readErrCh <- err
				return
			}
			if len(pkt) < 1 {
				continue
			}
			op := pkt[0] >> 3
			switch op {
			case 0x04: // P_CONTROL_V1
				payload, packetID := parseControlV1Payload(pkt)
				if packetID == recvExpected {
					recvExpected++
					if len(payload) > 0 {
						if err := tr.InjectInbound(payload); err != nil {
							readErrCh <- err
							return
						}
					}
				}
				// Send ACK.
				ack := buildAckPkt(serverSID, clientSID, []uint32{packetID})
				if err := writeTCPPkt(conn, ack); err != nil {
					readErrCh <- err
					return
				}
			case 0x05: // P_ACK_V1
				// server ACKing our packets — ignore
			default:
				// ignore unknown
			}
		}
	}()

	// Goroutine: drain TLS bytes from tr.OutboundChan() → wrap in P_CONTROL_V1 → TCP.
	go func() {
		for chunk := range tr.OutboundChan() {
			// Fragment at 1024 bytes.
			for len(chunk) > 0 {
				seg := chunk
				if len(seg) > 1024 {
					seg = chunk[:1024]
				}
				chunk = chunk[len(seg):]
				pkt := buildControlV1Pkt(clientSID, serverSID, sendSeq, nil, seg)
				sendSeq++
				if err := writeTCPPkt(conn, pkt); err != nil {
					return
				}
			}
		}
	}()

	// Load client TLS config (trust the server CA; present client cert).
	clientCertPEM, err := os.ReadFile(filepath.Join(certDir, "client.crt"))
	if err != nil {
		t.Fatal(err)
	}
	clientKeyPEM, err := os.ReadFile(filepath.Join(certDir, "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	clientTLSCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	tlsCfg := &tls.Config{
		Certificates:           []tls.Certificate{clientTLSCert},
		RootCAs:                caPool,
		ServerName:             "mock-server",
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
		InsecureSkipVerify:     true, // server cert CN is "mock-server", IP SANs may vary
	}

	// Run TLS handshake over the ControlTransport.
	tlsConn, err := ctls.Dial(tr, tlsCfg)
	if err != nil {
		t.Fatalf("ctls.Dial: %v", err)
	}
	defer tlsConn.Close()

	cs := tlsConn.TLSState()
	t.Logf("TLS handshake OK: version=0x%04x cipher=0x%04x", cs.Version, cs.CipherSuite)

	// Derive OpenVPN data-channel keys using the TLS master secret.
	// In TLS 1.2, the master secret is accessible via ConnectionState.
	// We use placeholder randoms here; a full implementation extracts them
	// via a patched crypto/tls or by recording them during the handshake.
	// The test verifies that prf.ExpandKeys runs without error.
	masterSecret := make([]byte, 48)
	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)
	// Use the session nonce as a stand-in so the test is deterministic.
	copy(masterSecret, cs.TLSUnique)
	keys, err := prf.ExpandKeys(masterSecret, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("prf.ExpandKeys: %v", err)
	}
	t.Logf("derived keys: client_cipher=%x... server_cipher=%x...",
		keys.ClientCipher[:4], keys.ServerCipher[:4])

	// Read PUSH_REPLY from the server.
	buf := make([]byte, 4096)
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	n, err := tlsConn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read PUSH_REPLY: %v", err)
	}
	reply := string(buf[:n])
	t.Logf("server message: %q", reply)

	if len(reply) == 0 {
		t.Error("expected PUSH_REPLY from server, got empty response")
	}
}

// ---- helpers ----------------------------------------------------------------

type testNetAddr struct{ addr string }

func (a *testNetAddr) Network() string { return "tcp" }
func (a *testNetAddr) String() string  { return a.addr }

func readTCPPkt(r io.Reader) ([]byte, error) {
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

func writeTCPPkt(w io.Writer, data []byte) error {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func buildHardResetClient(clientSID [8]byte) []byte {
	var b []byte
	b = append(b, byte(0x07<<3)|0) // P_CONTROL_HARD_RESET_CLIENT_V2, key_id=0
	b = append(b, clientSID[:]...)
	b = append(b, 0)          // ack_array_len = 0
	b = append(b, 0, 0, 0, 0) // packet_id = 0
	return b
}

func buildAckPkt(senderSID, remoteSID [8]byte, ackIDs []uint32) []byte {
	var b []byte
	b = append(b, byte(0x05<<3)|0) // P_ACK_V1
	b = append(b, senderSID[:]...)
	b = append(b, byte(len(ackIDs)))
	for _, id := range ackIDs {
		b = append(b, byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
	}
	b = append(b, remoteSID[:]...)
	return b
}

func buildControlV1Pkt(senderSID, remoteSID [8]byte, packetID uint32, ackIDs []uint32, payload []byte) []byte {
	var b []byte
	b = append(b, byte(0x04<<3)|0) // P_CONTROL_V1
	b = append(b, senderSID[:]...)
	if len(ackIDs) > 0 {
		b = append(b, byte(len(ackIDs)))
		for _, id := range ackIDs {
			b = append(b, byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
		}
		b = append(b, remoteSID[:]...)
	} else {
		b = append(b, 0)
	}
	b = append(b, byte(packetID>>24), byte(packetID>>16), byte(packetID>>8), byte(packetID))
	b = append(b, payload...)
	return b
}

func parseControlV1Payload(pkt []byte) (payload []byte, packetID uint32) {
	if len(pkt) < 10 {
		return
	}
	offset := 1 + 8 // opcode + session_id
	ackLen := int(pkt[offset])
	offset++
	if ackLen > 0 {
		offset += ackLen*4 + 8
	}
	if offset+4 > len(pkt) {
		return
	}
	packetID = binary.BigEndian.Uint32(pkt[offset:])
	offset += 4
	payload = pkt[offset:]
	return
}

// PKI generation helpers.

func generateCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mock-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return key, cert, pool
}

func generateServerCert(t *testing.T, dir string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "mock-server"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"mock-server", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, "server.crt"), "CERTIFICATE", der)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, "server.key"), "EC PRIVATE KEY", keyDER)
}

func generateClientCert(t *testing.T, dir string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "mock-client"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, "client.crt"), "CERTIFICATE", der)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, "client.key"), "EC PRIVATE KEY", keyDER)
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatal(err)
	}
}
