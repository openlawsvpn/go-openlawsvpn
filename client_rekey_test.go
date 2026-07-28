package vpn

import (
	"context"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/internal/framing"
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
