package vpn

import (
	"context"
	"testing"
	"time"
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
	if err == nil || err.Error() != "rekey reset exchange: deadline exceeded" {
		t.Fatalf("waitForRekeyReset error = %v, want reset-exchange deadline", err)
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
