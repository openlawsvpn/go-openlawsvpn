package vpn

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/internal/ctls"
	"github.com/openlawsvpn/go-openlawsvpn/internal/framing"
	"github.com/openlawsvpn/go-openlawsvpn/internal/reliable"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
)

func TestWaitForRekeyResetRequiresPeerResetAndAck(t *testing.T) {
	sess := &controlSession{
		peerReset:  make(chan struct{}),
		resetAcked: make(chan struct{}),
	}
	result := make(chan error, 1)
	go func() {
		result <- waitForRekeyReset(context.Background(), sess, time.Now().Add(time.Second))
	}()

	close(sess.peerReset)
	select {
	case err := <-result:
		t.Fatalf("waitForRekeyReset returned before reset ACK: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(sess.resetAcked)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("waitForRekeyReset: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waitForRekeyReset did not complete after both reset events")
	}
}

func TestWaitForRekeyResetDeadline(t *testing.T) {
	sess := &controlSession{
		peerReset:  make(chan struct{}),
		resetAcked: make(chan struct{}),
	}
	err := waitForRekeyReset(context.Background(), sess, time.Now().Add(5*time.Millisecond))
	if err == nil || err.Error() != "rekey reset exchange: deadline exceeded (peer reset received=false, local reset acknowledged=false)" {
		t.Fatalf("waitForRekeyReset error = %v, want detailed reset-exchange deadline", err)
	}
}

func TestParseControlV1AckIDs(t *testing.T) {
	var sender, remote [8]byte
	pkt := buildControlV1WithKeyID(sender, remote, 3, 7, []uint32{0, 4}, nil)
	got := parseControlV1AckIDs(pkt)
	if len(got) != 2 || got[0] != 0 || got[1] != 4 {
		t.Fatalf("parseControlV1AckIDs = %v, want [0 4]", got)
	}
}

func TestBuildAckUsesControlSessionKeyID(t *testing.T) {
	var sender, remote [8]byte
	pkt := buildAck(sender, remote, 6, []uint32{0})
	if got := framing.KeyIDFromByte(pkt[0]); got != 6 {
		t.Fatalf("ACK key ID = %d, want 6", got)
	}
	if got := framing.OpcodeFromByte(pkt[0]); got != framing.P_ACK_V1 {
		t.Fatalf("ACK opcode = %d, want P_ACK_V1", got)
	}
}

func TestControlPacketAcknowledgesReliableQueue(t *testing.T) {
	var sender, remote [8]byte
	sess := &controlSession{sendQueue: reliable.NewSendQueue(1)}
	if _, err := sess.sendQueue.Enqueue([]byte("first")); err != nil {
		t.Fatalf("enqueue first: %v", err)
	}
	if _, err := sess.sendQueue.Enqueue([]byte("second")); err != nil {
		t.Fatalf("enqueue second: %v", err)
	}

	// P_CONTROL_V1 carries a packet ID of its own and can piggyback ACKs for
	// outbound client control packets.  The outbound queue starts at ID 1.
	pkt := buildControlV1WithKeyID(sender, remote, 1, 12, []uint32{1, 2}, []byte("server TLS"))
	sess.sendQueue.AckMany(parseControlV1AckIDs(pkt))
	if got := sess.sendQueue.Len(); got != 0 {
		t.Fatalf("unacknowledged control packets = %d, want 0", got)
	}
}

func TestWaitForControlAcks(t *testing.T) {
	sess := &controlSession{sendQueue: reliable.NewSendQueue(0)}
	if _, err := sess.sendQueue.Enqueue([]byte("auth")); err != nil {
		t.Fatalf("enqueue auth: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		result <- waitForControlAcks(context.Background(), sess, time.Now().Add(time.Second))
	}()

	select {
	case err := <-result:
		t.Fatalf("waitForControlAcks returned before ACK: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	sess.sendQueue.Ack(0)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("waitForControlAcks: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waitForControlAcks did not complete after ACK")
	}
}

func TestWaitForControlAcksDeadline(t *testing.T) {
	sess := &controlSession{sendQueue: reliable.NewSendQueue(0)}
	sess.sendQueue.Enqueue([]byte("auth")) //nolint:errcheck

	err := waitForControlAcks(context.Background(), sess, time.Now().Add(5*time.Millisecond))
	if err == nil || err.Error() != "rekey auth acknowledgement: deadline exceeded (1 control packets unacknowledged)" {
		t.Fatalf("waitForControlAcks error = %v", err)
	}
}

func TestRekeyAuthCredentialsReuseCRV1(t *testing.T) {
	c := &Client{}
	c.cachedStateID = "state-123"
	c.cachedSAMLToken = "saml-token"

	username, password := c.rekeyAuthCredentials()
	if username != "N/A" {
		t.Fatalf("username = %q, want N/A", username)
	}
	if password != "CRV1::state-123::saml-token" {
		t.Fatalf("password = %q, want cached CRV1 credential", password)
	}
}

func TestRekeyAuthCredentialsPreferAuthToken(t *testing.T) {
	c := &Client{}
	c.cachedStateID = "state-123"
	c.cachedSAMLToken = "saml-token"
	c.pushOpts = &routing.PushOptions{AuthToken: "server-session-token"}

	username, password := c.rekeyAuthCredentials()
	if username != "N/A" {
		t.Fatalf("username = %q, want N/A", username)
	}
	if password != "server-session-token" {
		t.Fatalf("password = %q, want auth-token", password)
	}
}

func TestRekeyPromotionDelayHonoursConfiguredDelay(t *testing.T) {
	c := &Client{prof: &profile.Profile{RenegSec: 60, BecomePrimarySec: 5}}
	if got := c.rekeyPromotionDelay(); got != 5*time.Second {
		t.Fatalf("rekeyPromotionDelay = %s, want 5s", got)
	}
}

func TestRekeyPromotionDelayUsesOpenVPNDefault(t *testing.T) {
	c := &Client{prof: &profile.Profile{RenegSec: 60}}
	if got := c.rekeyPromotionDelay(); got != 30*time.Second {
		t.Fatalf("rekeyPromotionDelay = %s, want 30s", got)
	}

	c.prof.RenegSec = 3600
	if got := c.rekeyPromotionDelay(); got != 60*time.Second {
		t.Fatalf("rekeyPromotionDelay = %s, want 1m0s", got)
	}
}

func TestRekeySoftResetAdvancesReceiveWindow(t *testing.T) {
	sess := &controlSession{
		transport:  ctls.NewControlTransport(nil, nil, 1),
		recvWindow: reliable.NewRecvWindow(),
	}
	defer sess.transport.Close() //nolint:errcheck

	// The server's SOFT_RESET is the first reliable packet in the new key
	// epoch.  Its empty payload must advance the window to packet ID 1.
	sess.receiveControl(0, nil)
	sess.receiveControl(1, []byte("server TLS"))

	if err := sess.transport.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, len("server TLS"))
	n, err := sess.transport.Read(buf)
	if err != nil {
		t.Fatalf("read TLS payload: %v", err)
	}
	if got := string(buf[:n]); got != "server TLS" {
		t.Fatalf("TLS payload = %q, want %q", got, "server TLS")
	}
}

func TestWritePacketSerializesTCPFrames(t *testing.T) {
	// net.Pipe makes each individual Write rendezvous with the reader. Without
	// Client.writeMu, concurrent WriteTCP calls can therefore interleave their
	// two writes (length then payload) deterministically.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	c := &Client{prof: &profile.Profile{Proto: profile.ProtoTCP}}
	const packetCount = 32
	start := make(chan struct{})
	errs := make(chan error, packetCount)
	for i := 0; i < packetCount; i++ {
		payload := []byte{byte(i)}
		go func() {
			<-start
			errs <- c.writePacket(clientConn, payload)
		}()
	}

	readErr := make(chan error, 1)
	go func() {
		seen := make(map[byte]bool, packetCount)
		for i := 0; i < packetCount; i++ {
			pkt, err := framing.ReadTCP(serverConn)
			if err != nil {
				readErr <- err
				return
			}
			if len(pkt) != 1 || seen[pkt[0]] {
				readErr <- fmt.Errorf("unexpected TCP frame: %x", pkt)
				return
			}
			seen[pkt[0]] = true
		}
		readErr <- nil
	}()

	close(start)
	for i := 0; i < packetCount; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("writePacket: %v", err)
		}
	}
	if err := <-readErr; err != nil {
		t.Fatalf("TCP framing was interleaved: %v", err)
	}
}
