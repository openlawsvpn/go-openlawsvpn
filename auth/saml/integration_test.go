//go:build integration

// Integration test: CRV1 round-trip against the mock server's SAML stub.
//
// This test exercises the full Phase 5 SAML/CRV1 flow end-to-end:
//
//  1. Start mock server with MOCK_CRV1=1.
//  2. Perform HARD_RESET + TLS handshake (same as Phase 2/3 tests).
//  3. Server sends AUTH_FAILED,CRV1 challenge — parsed via HandlePhase1.
//  4. Synthesize a mock SAML token (no real browser; the mock server accepts any).
//  5. CompletePhase2 sends AUTH_REPLY credential; server responds PUSH_REPLY.
//  6. Verify PUSH_REPLY is returned and correctly classified.
//  7. Start a SessionMonitor and send a simulated AUTH_FAILED to verify expiry detection.
//
// Run with:
//
//	MOCK_SERVER_BIN=/path/to/mock-server \
//	  go test -v -tags=integration -timeout=60s ./auth/saml/
//
// If MOCK_SERVER_BIN is not set the test is skipped.
package saml_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/auth/saml"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// TestCRV1RoundTripMockServer performs a complete SAML/CRV1 two-phase
// authentication against the mock server running with MOCK_CRV1=1.
func TestCRV1RoundTripMockServer(t *testing.T) {
	binPath := os.Getenv("MOCK_SERVER_BIN")
	if binPath == "" {
		t.Skip("MOCK_SERVER_BIN not set; skipping integration test")
	}

	// Build a minimal PKI: CA + server cert + client cert.
	certDir := t.TempDir()
	caKey, caCert, caPool := crv1GenCA(t)
	crv1GenServerCert(t, certDir, caKey, caCert)
	crv1GenClientCert(t, certDir, caKey, caCert)
	crv1WritePEM(t, filepath.Join(certDir, "ca.crt"), "CERTIFICATE", caCert.Raw)

	// Start mock server in CRV1 mode.
	srv, err := testenv.Start(testenv.Config{
		Binary:   binPath,
		CertDir:  certDir,
		CRV1Mode: true,
	})
	if err != nil {
		t.Fatalf("testenv.Start CRV1 mode: %v", err)
	}
	defer srv.Stop() //nolint:errcheck

	t.Logf("mock server at %s (CRV1 mode)", srv.TCPAddr)

	// ---- Step 1: raw TCP dial + HARD_RESET exchange --------------------------
	conn, err := net.DialTimeout("tcp", srv.TCPAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	var clientSID [8]byte
	if _, err := rand.Read(clientSID[:]); err != nil {
		t.Fatal(err)
	}

	if err := crv1WriteTCP(conn, crv1BuildHardReset(clientSID)); err != nil {
		t.Fatalf("write HARD_RESET: %v", err)
	}

	srvReset, err := crv1ReadTCP(conn)
	if err != nil {
		t.Fatalf("read HARD_RESET_SERVER: %v", err)
	}
	if len(srvReset) < 9 || srvReset[0]>>3 != 0x08 {
		t.Fatalf("unexpected HARD_RESET_SERVER opcode 0x%02x", srvReset[0]>>3)
	}
	var serverSID [8]byte
	copy(serverSID[:], srvReset[1:9])
	t.Logf("HARD_RESET_SERVER session_id=%x", serverSID)

	// ---- Step 2: TLS handshake over P_CONTROL_V1 ----------------------------
	tlsPipe1, tlsPipe2 := net.Pipe()
	defer tlsPipe1.Close()
	defer tlsPipe2.Close()

	var sendSeq uint32
	var recvExpected uint32

	// relay: rawConn → tlsPipe1
	go func() {
		defer tlsPipe1.Close()
		for {
			pkt, err := crv1ReadTCP(conn)
			if err != nil {
				return
			}
			if len(pkt) < 1 {
				continue
			}
			op := pkt[0] >> 3
			switch op {
			case 0x04: // P_CONTROL_V1
				payload, pid := crv1ParseControlV1(pkt)
				if pid == recvExpected {
					recvExpected++
					if len(payload) > 0 {
						tlsPipe1.Write(payload) //nolint:errcheck
					}
				}
				ack := crv1BuildAck(clientSID, serverSID, []uint32{pid})
				crv1WriteTCP(conn, ack) //nolint:errcheck
			case 0x05: // P_ACK_V1 — ignore
			}
		}
	}()

	// relay: tlsPipe1 → rawConn
	go func() {
		buf := make([]byte, 16384)
		for {
			n, err := tlsPipe1.Read(buf)
			if err != nil {
				return
			}
			payload := buf[:n]
			for len(payload) > 0 {
				seg := payload
				if len(seg) > 1024 {
					seg = payload[:1024]
				}
				payload = payload[len(seg):]
				p := crv1BuildControlV1(clientSID, serverSID, sendSeq, nil, seg)
				sendSeq++
				crv1WriteTCP(conn, p) //nolint:errcheck
			}
		}
	}()

	// Load client TLS config.
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
		InsecureSkipVerify:     true, //nolint:gosec // test-only self-signed cert
	}

	tlsConn := tls.Client(tlsPipe2, tlsCfg)
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	cs := tlsConn.ConnectionState()
	t.Logf("TLS OK: version=0x%04x cipher=0x%04x", cs.Version, cs.CipherSuite)

	// Remove the per-handshake deadline; Phase 2 exchanges have their own.
	tlsConn.SetDeadline(time.Time{}) //nolint:errcheck

	// ---- Step 3: Phase 1 — read CRV1 challenge ------------------------------
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	cm, err := saml.HandlePhase1(tlsConn)
	if err != nil {
		t.Fatalf("HandlePhase1: %v", err)
	}
	if cm.Kind != saml.MsgKindAuthFailedCRV1 {
		t.Fatalf("Phase1 kind = %v, want MsgKindAuthFailedCRV1", cm.Kind)
	}
	ch := cm.Challenge
	t.Logf("CRV1 challenge: state_id=%s saml_url=%s remote_ip=%s",
		ch.StateID, ch.SAMLURL, ch.RemoteIP)

	// ---- Step 4: simulate SAML token ----------------------------------------
	// In a real flow the user visits ch.SAMLURL and the ACS server captures
	// the SAMLResponse. The mock server accepts any non-empty token.
	mockSAMLToken := "bW9ja1NBTU1SZXNwb25zZQ==" // base64("mockSAMLResponse")
	t.Logf("using mock SAML token: %s", mockSAMLToken)

	// ---- Step 5: Phase 2 — send AUTH_REPLY, receive PUSH_REPLY --------------
	tlsConn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	pushCM, err := saml.CompletePhase2(tlsConn, ch.StateID, mockSAMLToken, false)
	if err != nil {
		t.Fatalf("CompletePhase2: %v", err)
	}
	if pushCM.Kind != saml.MsgKindPushReply {
		t.Fatalf("Phase2 response kind = %v, want MsgKindPushReply", pushCM.Kind)
	}
	t.Logf("PUSH_REPLY: %s", pushCM.Raw)

	// Verify expected tunnel parameters are present in PUSH_REPLY.
	for _, want := range []string{"ifconfig", "route", "dhcp-option"} {
		if !contains(pushCM.Raw, want) {
			t.Errorf("PUSH_REPLY missing %q: %s", want, pushCM.Raw)
		}
	}
	t.Log("CRV1 round-trip: PASS")
}

// TestSessionExpiredDetection verifies that SessionMonitor delivers
// *SessionExpiredError when the server sends AUTH_FAILED after PUSH_REPLY.
// This test is fully in-process (no mock server required).
func TestSessionExpiredDetection(t *testing.T) {
	// Use a net.Pipe to simulate a TLS session where the server side sends
	// AUTH_FAILED after the tunnel is up.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Start the session monitor on the client side.
	mon := saml.NewSessionMonitor(clientConn)
	mon.Start(t.Context())

	// Server sends AUTH_FAILED (simulating mid-session expiry).
	go func() {
		time.Sleep(50 * time.Millisecond)
		serverConn.Write([]byte("AUTH_FAILED\x00")) //nolint:errcheck
	}()

	select {
	case err := <-mon.Done():
		var se *saml.SessionExpiredError
		if !errors.As(err, &se) {
			t.Fatalf("expected *SessionExpiredError, got %T: %v", err, err)
		}
		t.Logf("SessionExpiredError: %v", se)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for session expiry")
	}
}

// ---- helpers ----------------------------------------------------------------

func contains(s, sub string) bool {
	return len(s) >= len(sub) && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}()
}

// ---- PKI generation (local copies; each integration test is self-contained) -

func crv1GenCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, *x509.CertPool) {
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

func crv1GenServerCert(t *testing.T, dir string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) {
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
	crv1WritePEM(t, filepath.Join(dir, "server.crt"), "CERTIFICATE", der)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	crv1WritePEM(t, filepath.Join(dir, "server.key"), "EC PRIVATE KEY", keyDER)
}

func crv1GenClientCert(t *testing.T, dir string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) {
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
	crv1WritePEM(t, filepath.Join(dir, "client.crt"), "CERTIFICATE", der)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	crv1WritePEM(t, filepath.Join(dir, "client.key"), "EC PRIVATE KEY", keyDER)
}

func crv1WritePEM(t *testing.T, path, blockType string, der []byte) {
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

// ---- OpenVPN TCP framing helpers --------------------------------------------

func crv1ReadTCP(r io.Reader) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(h[:])
	if n == 0 {
		return nil, fmt.Errorf("zero-length packet")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func crv1WriteTCP(w io.Writer, data []byte) error {
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(data)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func crv1BuildHardReset(clientSID [8]byte) []byte {
	b := []byte{byte(0x07<<3) | 0}
	b = append(b, clientSID[:]...)
	b = append(b, 0, 0, 0, 0, 0) // ack_len=0, packet_id=0
	return b
}

func crv1BuildAck(senderSID, remoteSID [8]byte, ackIDs []uint32) []byte {
	b := []byte{byte(0x05<<3) | 0}
	b = append(b, senderSID[:]...)
	b = append(b, byte(len(ackIDs)))
	for _, id := range ackIDs {
		b = append(b, byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
	}
	b = append(b, remoteSID[:]...)
	return b
}

func crv1BuildControlV1(senderSID, remoteSID [8]byte, packetID uint32, ackIDs []uint32, payload []byte) []byte {
	b := []byte{byte(0x04<<3) | 0}
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

func crv1ParseControlV1(pkt []byte) (payload []byte, packetID uint32) {
	if len(pkt) < 10 {
		return
	}
	off := 1 + 8
	ackLen := int(pkt[off])
	off++
	if ackLen > 0 {
		off += ackLen*4 + 8
	}
	if off+4 > len(pkt) {
		return
	}
	packetID = binary.BigEndian.Uint32(pkt[off:])
	off += 4
	payload = pkt[off:]
	return
}
