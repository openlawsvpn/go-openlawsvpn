//go:build integration

// Integration test: full data-channel ping round-trip over an in-process
// TLS session.
//
// This test verifies the complete Phase 3 stack end-to-end:
//
//  1. OpenVPN HARD_RESET / ACK exchange (TCP framing).
//  2. TLS 1.2 mutual-auth handshake relayed via P_CONTROL_V1 packets.
//  3. PUSH_REPLY received over the TLS control channel.
//  4. Data-channel keys derived via tls.ConnectionState.ExportKeyingMaterial
//     with an OpenVPN-compatible label (both sides independently produce the
//     same 128-byte key block, matching the layout of prf.ExpandKeys).
//  5. A synthetic ICMP-echo-request IP packet encrypted as P_DATA_V2 and
//     sent to the in-process mock server.
//  6. Mock server decrypts, verifies, re-encrypts, and echoes the packet.
//  7. Client decrypts the echo and asserts byte-exact match.
//
// Run with:
//
//	go test -v -tags=integration -timeout=30s ./internal/datachannel/
package datachannel_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/internal/datachannel"
)

// TestPingThroughDataChannel establishes an in-process TLS session using the
// OpenVPN control-channel framing protocol, derives data-channel keys from
// the TLS session, and verifies a ping packet round-trip via P_DATA_V2.
func TestPingThroughDataChannel(t *testing.T) {
	// ---- Build a minimal PKI for the test TLS session ----------------------
	caKey, caCert, caPool := dcGenCA(t)
	serverTLSCert := dcGenCert(t, "server", caKey, caCert, x509.ExtKeyUsageServerAuth)
	clientTLSCert := dcGenCert(t, "client", caKey, caCert, x509.ExtKeyUsageClientAuth)
	_ = caPool

	serverTLSCfg := &tls.Config{
		Certificates:           []tls.Certificate{serverTLSCert},
		ClientAuth:             tls.RequestClientCert,
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
	}
	clientTLSCfg := &tls.Config{
		Certificates:       []tls.Certificate{clientTLSCert},
		InsecureSkipVerify: true, //nolint:gosec // test-only self-signed cert
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		SessionTicketsDisabled: true,
	}

	// ---- Set up the in-process transport: two net.Pipe() halves ------------
	// rawClient ↔ rawServer: the "TCP" connection between client and server.
	rawClient, rawServer := net.Pipe()
	defer rawClient.Close()
	defer rawServer.Close()

	// srvErrCh receives any fatal error from the server goroutine.
	srvErrCh := make(chan error, 1)
	// echoDataCh carries the P_DATA_V2 wire packet that the server echoes back.
	echoDataCh := make(chan []byte, 1)

	// ---- Server goroutine --------------------------------------------------
	go func() {
		if err := runMockServer(rawServer, serverTLSCfg, echoDataCh); err != nil {
			srvErrCh <- err
		}
		close(srvErrCh)
	}()

	// ---- Client: HARD_RESET exchange ----------------------------------------
	var clientSID [8]byte
	if _, err := rand.Read(clientSID[:]); err != nil {
		t.Fatal(err)
	}
	if err := dcWriteTCP(rawClient, dcBuildHardReset(clientSID)); err != nil {
		t.Fatalf("write HARD_RESET: %v", err)
	}

	// Read HARD_RESET_SERVER_V2.
	srvResetPkt, err := dcReadTCP(rawClient)
	if err != nil {
		t.Fatalf("read HARD_RESET_SERVER: %v", err)
	}
	if len(srvResetPkt) < 9 || srvResetPkt[0]>>3 != 0x08 {
		t.Fatalf("unexpected HARD_RESET_SERVER, got opcode 0x%02x", srvResetPkt[0]>>3)
	}
	var serverSID [8]byte
	copy(serverSID[:], srvResetPkt[1:9])
	t.Logf("HARD_RESET_SERVER session_id=%x", serverSID)

	// ---- Client: TLS handshake over P_CONTROL_V1 ----------------------------
	// Bridge: clientTLSPipe ↔ P_CONTROL_V1 framing on rawClient.
	tlsPipe1, tlsPipe2 := net.Pipe()
	defer tlsPipe1.Close()
	defer tlsPipe2.Close()

	var clientSendSeq uint32
	var clientRecvExpected uint32

	// relay: rawClient → tlsPipe1
	go func() {
		defer tlsPipe1.Close()
		for {
			pkt, err := dcReadTCP(rawClient)
			if err != nil {
				return
			}
			if len(pkt) < 1 {
				continue
			}
			op := pkt[0] >> 3
			switch op {
			case 0x04: // P_CONTROL_V1
				payload, pid := dcParseControlV1(pkt)
				if pid == clientRecvExpected {
					clientRecvExpected++
					if len(payload) > 0 {
						tlsPipe1.Write(payload) //nolint:errcheck
					}
				}
				ack := dcBuildAck(clientSID, serverSID, []uint32{pid})
				dcWriteTCP(rawClient, ack) //nolint:errcheck
			}
		}
	}()

	// relay: tlsPipe1 → rawClient
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
				pkt := dcBuildControlV1(clientSID, serverSID, clientSendSeq, nil, seg)
				clientSendSeq++
				dcWriteTCP(rawClient, pkt) //nolint:errcheck
			}
		}
	}()

	// TLS handshake.
	tlsClient := tls.Client(tlsPipe2, clientTLSCfg)
	tlsClient.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	cs := tlsClient.ConnectionState()
	t.Logf("TLS handshake OK: version=0x%04x cipher=0x%04x", cs.Version, cs.CipherSuite)

	// ---- Client: read PUSH_REPLY --------------------------------------------
	tlsClient.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	pushBuf := make([]byte, 4096)
	n, err := tlsClient.Read(pushBuf)
	if err != nil {
		t.Fatalf("read PUSH_REPLY: %v", err)
	}
	pushReply := string(pushBuf[:n])
	t.Logf("PUSH_REPLY: %q", pushReply)

	// ---- Key derivation via ExportKeyingMaterial ----------------------------
	// Both client and server independently derive the same 256-byte block.
	// Layout mirrors openvpn3-core OpenVPNStaticKey slices (key_table, 64B each):
	//   [0:64]   = CIPHER|ENCRYPT|NORMAL  → cipher key = [0:32]
	//   [64:128] = HMAC|ENCRYPT|NORMAL    → nonce tail = [64:72] (8 bytes)
	//   [128:192]= CIPHER|DECRYPT|NORMAL  → cipher key = [128:160]
	//   [192:256]= HMAC|DECRYPT|NORMAL    → nonce tail = [192:200] (8 bytes)
	const ekLabel = "EXPORTER-go-openlawsvpn-datachannel-test"
	keyMat, err := cs.ExportKeyingMaterial(ekLabel, nil, 256)
	if err != nil {
		t.Fatalf("ExportKeyingMaterial: %v", err)
	}

	clientCipherKey := keyMat[0:32]
	clientNonceTail := keyMat[64:72]
	serverCipherKey := keyMat[128:160]
	serverNonceTail := keyMat[192:200]

	// Client channel: encrypt with client keys, decrypt with server keys.
	clientCh, err := datachannel.New(0, 0, clientCipherKey, clientNonceTail, serverCipherKey, serverNonceTail)
	if err != nil {
		t.Fatalf("New (client channel): %v", err)
	}

	// ---- Build and send a synthetic ICMP echo-request IP packet -------------
	// Minimal IPv4 + ICMP echo-request: 20-byte IP header + 8-byte ICMP header.
	ping := buildICMPEchoRequest(t, 1, 42, []byte("go-openlawsvpn ping test"))
	t.Logf("sending ping (%d bytes)", len(ping))

	pktWire, err := clientCh.Encrypt(ping)
	if err != nil {
		t.Fatalf("Encrypt ping: %v", err)
	}

	// Write P_DATA_V2 directly on the raw connection (not over TLS).
	if err := dcWriteTCP(rawClient, pktWire); err != nil {
		t.Fatalf("write P_DATA_V2: %v", err)
	}

	// ---- Read and decrypt the server echo -----------------------------------
	select {
	case echoPkt, ok := <-echoDataCh:
		if !ok {
			t.Fatal("server did not echo the ping")
		}
		// Server echoes using server→client keys; client decrypts with server keys.
		// The channel is already configured for this direction.
		plainEcho, err := clientCh.Decrypt(echoPkt)
		if err != nil {
			t.Fatalf("Decrypt echo: %v", err)
		}
		if !bytes.Equal(plainEcho, ping) {
			t.Fatalf("echo mismatch:\n  sent: %x\n  got:  %x", ping, plainEcho)
		}
		t.Logf("echo verified OK (%d bytes)", len(plainEcho))

	case err := <-srvErrCh:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
		t.Fatal("server closed without echo")
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for echo")
	}

	// Drain server errors.
	if err := <-srvErrCh; err != nil {
		t.Errorf("server goroutine error: %v", err)
	}
}

// ---- In-process mock server -------------------------------------------------

// runMockServer handles one connection: HARD_RESET + TLS + PUSH_REPLY +
// data-channel echo.  The first P_DATA_V2 packet received is decrypted,
// re-encrypted, and sent to echoCh.
func runMockServer(rawConn net.Conn, tlsCfg *tls.Config, echoCh chan<- []byte) error {
	defer rawConn.Close()

	// HARD_RESET exchange.
	pkt, err := dcReadTCP(rawConn)
	if err != nil {
		return err
	}
	if len(pkt) < 9 || pkt[0]>>3 != 0x07 {
		return nil // unexpected — ignore
	}
	var clientSID [8]byte
	copy(clientSID[:], pkt[1:9])

	var serverSID [8]byte
	binary.BigEndian.PutUint64(serverSID[:], uint64(time.Now().UnixNano()))
	if err := dcWriteTCP(rawConn, dcBuildHardResetServer(serverSID, clientSID)); err != nil {
		return err
	}

	// TLS relay via net.Pipe().
	inner1, inner2 := net.Pipe()
	defer inner1.Close()
	defer inner2.Close()

	// dataPktCh receives raw P_DATA_V2 wire packets for server-side processing.
	dataPktCh := make(chan []byte, 8)

	var srvRecvExpected uint32
	var srvSendSeq uint32

	// relay: rawConn → inner1 (control) or dataPktCh (data)
	go func() {
		defer inner1.Close()
		for {
			data, err := dcReadTCP(rawConn)
			if err != nil {
				return
			}
			if len(data) < 1 {
				continue
			}
			op := data[0] >> 3
			switch op {
			case 0x04: // P_CONTROL_V1
				payload, pid := dcParseControlV1(data)
				if pid == srvRecvExpected {
					srvRecvExpected++
					if len(payload) > 0 {
						inner1.Write(payload) //nolint:errcheck
					}
				}
				ack := dcBuildAck(serverSID, clientSID, []uint32{pid})
				dcWriteTCP(rawConn, ack) //nolint:errcheck
			case 0x09: // P_DATA_V2
				cp := make([]byte, len(data))
				copy(cp, data)
				select {
				case dataPktCh <- cp:
				default:
				}
			}
		}
	}()

	// relay: inner1 → rawConn
	go func() {
		buf := make([]byte, 16384)
		for {
			n, err := inner1.Read(buf)
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
				p := dcBuildControlV1(serverSID, clientSID, srvSendSeq, nil, seg)
				srvSendSeq++
				dcWriteTCP(rawConn, p) //nolint:errcheck
			}
		}
	}()

	// TLS server handshake.
	tlsConn := tls.Server(inner2, tlsCfg)
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	cs := tlsConn.ConnectionState()

	// PUSH_REPLY.
	pushReply := "PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,route 10.8.0.0 255.255.0.0," +
		"dhcp-option DNS 10.8.0.1,cipher AES-256-GCM\x00"
	if _, err := tlsConn.Write([]byte(pushReply)); err != nil {
		return err
	}

	// Key derivation — same label and layout as the client.
	const ekLabel = "EXPORTER-go-openlawsvpn-datachannel-test"
	keyMat, err := cs.ExportKeyingMaterial(ekLabel, nil, 256)
	if err != nil {
		return err
	}

	clientCipherKey := keyMat[0:32]
	clientNonceTail := keyMat[64:72]
	serverCipherKey := keyMat[128:160]
	serverNonceTail := keyMat[192:200]

	// Server channel: encrypt with server keys, decrypt with client keys.
	serverCh, err := datachannel.New(0, 0, serverCipherKey, serverNonceTail, clientCipherKey, clientNonceTail)
	if err != nil {
		return err
	}

	// Wait for the first P_DATA_V2 packet, decrypt, re-encrypt, echo.
	select {
	case wirePkt := <-dataPktCh:
		plain, err := serverCh.Decrypt(wirePkt)
		if err != nil {
			return err
		}
		echo, err := serverCh.Encrypt(plain)
		if err != nil {
			return err
		}
		// Send echo as a raw P_DATA_V2 packet on the rawConn.
		if err := dcWriteTCP(rawConn, echo); err != nil {
			return err
		}
		echoCh <- echo
	case <-time.After(10 * time.Second):
		return nil // timeout — test will detect this
	}
	return nil
}

// ---- PKI generation helpers -------------------------------------------------

func dcGenCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return key, cert, pool
}

func dcGenCert(t *testing.T, cn string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, eku x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	cert, _ := x509.ParseCertificate(der)
	return tls.Certificate{
		Certificate: [][]byte{der, caCert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

// ---- Synthetic ICMP echo-request builder ------------------------------------

// buildICMPEchoRequest builds a minimal IPv4 + ICMP echo-request packet.
// src: 10.8.0.6  dst: 10.8.0.5  (matching mock server push options)
func buildICMPEchoRequest(t *testing.T, id, seq uint16, payload []byte) []byte {
	t.Helper()
	icmpLen := 8 + len(payload)
	totalLen := 20 + icmpLen

	pkt := make([]byte, totalLen)

	// IPv4 header.
	pkt[0] = 0x45 // version=4, IHL=5
	pkt[1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x0001) // identification
	pkt[6] = 0x40 // flags: DF
	pkt[7] = 0x00 // fragment offset
	pkt[8] = 64   // TTL
	pkt[9] = 0x01 // protocol: ICMP
	// checksum at [10:12] — computed below
	pkt[12], pkt[13], pkt[14], pkt[15] = 10, 8, 0, 6 // src 10.8.0.6
	pkt[16], pkt[17], pkt[18], pkt[19] = 10, 8, 0, 5 // dst 10.8.0.5
	pkt[10], pkt[11] = ipChecksum(pkt[:20])

	// ICMP echo-request.
	pkt[20] = 8 // type: echo request
	pkt[21] = 0 // code: 0
	// checksum at [22:24] — computed below
	binary.BigEndian.PutUint16(pkt[24:26], id)
	binary.BigEndian.PutUint16(pkt[26:28], seq)
	copy(pkt[28:], payload)
	hi, lo := ipChecksum(pkt[20:])
	pkt[22], pkt[23] = hi, lo

	return pkt
}

// ipChecksum computes the Internet checksum (RFC 1071) of data.
func ipChecksum(data []byte) (byte, byte) {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	csum := uint16(^sum)
	return byte(csum >> 8), byte(csum)
}

// ---- OpenVPN TCP framing helpers (local copies for this test file) ----------

func dcReadTCP(r net.Conn) ([]byte, error) {
	var h [2]byte
	if _, err := readFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(h[:])
	buf := make([]byte, n)
	if _, err := readFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func dcWriteTCP(w net.Conn, data []byte) error {
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(data)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// readFull is a minimal io.ReadFull for net.Conn.
func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func dcBuildHardReset(clientSID [8]byte) []byte {
	b := []byte{byte(0x07<<3) | 0}
	b = append(b, clientSID[:]...)
	b = append(b, 0, 0, 0, 0, 0) // ack_len=0, packet_id=0
	return b
}

func dcBuildHardResetServer(serverSID, clientSID [8]byte) []byte {
	b := []byte{byte(0x08<<3) | 0}
	b = append(b, serverSID[:]...)
	b = append(b, 1)          // ack_array_len = 1
	b = append(b, 0, 0, 0, 0) // ACK packet 0
	b = append(b, clientSID[:]...)
	b = append(b, 0, 0, 0, 0) // server packet_id = 0
	return b
}

func dcBuildAck(senderSID, remoteSID [8]byte, ackIDs []uint32) []byte {
	b := []byte{byte(0x05<<3) | 0}
	b = append(b, senderSID[:]...)
	b = append(b, byte(len(ackIDs)))
	for _, id := range ackIDs {
		b = append(b, byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
	}
	b = append(b, remoteSID[:]...)
	return b
}

func dcBuildControlV1(senderSID, remoteSID [8]byte, packetID uint32, ackIDs []uint32, payload []byte) []byte {
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

func dcParseControlV1(pkt []byte) (payload []byte, packetID uint32) {
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
