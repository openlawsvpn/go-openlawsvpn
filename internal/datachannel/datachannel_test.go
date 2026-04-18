package datachannel_test

import (
	"bytes"
	"testing"

	"github.com/openlawsvpn/go-openvpn3/internal/datachannel"
)

// ---- GCM (default) helpers --------------------------------------------------

func newChannel(t *testing.T) *datachannel.Channel {
	t.Helper()
	txKey := bytes.Repeat([]byte{0x01}, 32)
	txIV := bytes.Repeat([]byte{0x02}, 8) // 8-byte nonce tail
	rxKey := bytes.Repeat([]byte{0x03}, 32)
	rxIV := bytes.Repeat([]byte{0x04}, 8)
	ch, err := datachannel.New(1, 0, txKey, txIV, rxKey, rxIV)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

// loopbackPair creates two GCM channels wired together:
// channel A's tx == channel B's rx and vice-versa.
func loopbackPair(t *testing.T) (a, b *datachannel.Channel) {
	t.Helper()
	keyA := bytes.Repeat([]byte{0xAA}, 32)
	ivA := bytes.Repeat([]byte{0xBB}, 8)
	keyB := bytes.Repeat([]byte{0xCC}, 32)
	ivB := bytes.Repeat([]byte{0xDD}, 8)

	var err error
	// A sends with keyA/ivA, receives with keyB/ivB
	a, err = datachannel.New(42, 0, keyA, ivA, keyB, ivB)
	if err != nil {
		t.Fatal(err)
	}
	// B sends with keyB/ivB, receives with keyA/ivA
	b, err = datachannel.New(42, 0, keyB, ivB, keyA, ivA)
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

// ---- CBC helpers ------------------------------------------------------------

// cbcLoopbackPair creates two CBC channels wired together.
func cbcLoopbackPair(t *testing.T) (a, b *datachannel.Channel) {
	t.Helper()
	aesA := bytes.Repeat([]byte{0x11}, 32)
	hmacA := bytes.Repeat([]byte{0x22}, 32)
	aesB := bytes.Repeat([]byte{0x33}, 32)
	hmacB := bytes.Repeat([]byte{0x44}, 32)

	var err error
	a, err = datachannel.NewCBC(10, 1, aesA, hmacA, aesB, hmacB)
	if err != nil {
		t.Fatal(err)
	}
	b, err = datachannel.NewCBC(10, 1, aesB, hmacB, aesA, hmacA)
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

// ---- GCM tests --------------------------------------------------------------

func TestEncryptDecryptRoundTrip(t *testing.T) {
	a, b := loopbackPair(t)
	msg := []byte{0x45, 0x00, 0x00, 0x1c} // fake IPv4 header start

	pkt, err := a.Encrypt(msg)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := b.Decrypt(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, msg) {
		t.Fatalf("roundtrip mismatch: got %v want %v", plain, msg)
	}
}

func TestMultiplePackets(t *testing.T) {
	a, b := loopbackPair(t)
	for i := 0; i < 20; i++ {
		msg := []byte{byte(i), byte(i + 1)}
		pkt, err := a.Encrypt(msg)
		if err != nil {
			t.Fatalf("i=%d encrypt: %v", i, err)
		}
		plain, err := b.Decrypt(pkt)
		if err != nil {
			t.Fatalf("i=%d decrypt: %v", i, err)
		}
		if !bytes.Equal(plain, msg) {
			t.Fatalf("i=%d mismatch", i)
		}
	}
}

func TestReplayDetection(t *testing.T) {
	a, b := loopbackPair(t)
	msg := []byte("ip packet")

	pkt, _ := a.Encrypt(msg)
	if _, err := b.Decrypt(pkt); err != nil {
		t.Fatalf("first decrypt: %v", err)
	}
	// Replay the same packet.
	if _, err := b.Decrypt(pkt); err == nil {
		t.Fatal("expected replay error on second decrypt of same packet")
	}
}

func TestReplayTooOld(t *testing.T) {
	a, b := loopbackPair(t)
	// Encrypt 70 packets to advance the window well past 64.
	pkts := make([][]byte, 70)
	for i := range pkts {
		pkt, err := a.Encrypt([]byte{byte(i)})
		if err != nil {
			t.Fatalf("encrypt i=%d: %v", i, err)
		}
		pkts[i] = pkt
	}
	// Deliver the last 65 packets in order to advance b's window.
	for i := 5; i < 70; i++ {
		if _, err := b.Decrypt(pkts[i]); err != nil {
			t.Fatalf("decrypt i=%d: %v", i, err)
		}
	}
	// Packet 0 is now too old.
	if _, err := b.Decrypt(pkts[0]); err == nil {
		t.Fatal("expected 'too old' error for packet 0 after window advance")
	}
}

func TestShortPacketError(t *testing.T) {
	ch := newChannel(t)
	_, err := ch.Decrypt(make([]byte, 10)) // too short
	if err == nil {
		t.Fatal("expected error for short packet")
	}
}

// ---- CBC tests --------------------------------------------------------------

func TestCBCEncryptDecryptRoundTrip(t *testing.T) {
	a, b := cbcLoopbackPair(t)
	msg := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x01} // fake IPv4 packet

	pkt, err := a.Encrypt(msg)
	if err != nil {
		t.Fatalf("CBC encrypt: %v", err)
	}
	plain, err := b.Decrypt(pkt)
	if err != nil {
		t.Fatalf("CBC decrypt: %v", err)
	}
	if !bytes.Equal(plain, msg) {
		t.Fatalf("CBC roundtrip mismatch: got %v want %v", plain, msg)
	}
}

func TestCBCMultiplePackets(t *testing.T) {
	a, b := cbcLoopbackPair(t)
	for i := 0; i < 10; i++ {
		msg := []byte{byte(i), byte(i + 10), byte(i + 20)}
		pkt, err := a.Encrypt(msg)
		if err != nil {
			t.Fatalf("CBC i=%d encrypt: %v", i, err)
		}
		plain, err := b.Decrypt(pkt)
		if err != nil {
			t.Fatalf("CBC i=%d decrypt: %v", i, err)
		}
		if !bytes.Equal(plain, msg) {
			t.Fatalf("CBC i=%d mismatch", i)
		}
	}
}

func TestCBCReplayDetection(t *testing.T) {
	a, b := cbcLoopbackPair(t)
	msg := []byte("ip-over-cbc")

	pkt, _ := a.Encrypt(msg)
	if _, err := b.Decrypt(pkt); err != nil {
		t.Fatalf("first CBC decrypt: %v", err)
	}
	if _, err := b.Decrypt(pkt); err == nil {
		t.Fatal("expected CBC replay error")
	}
}
