package reliable_test

import (
	"encoding/binary"
	"testing"

	"github.com/openlawsvpn/go-openvpn3/internal/reliable"
)

// FuzzRecvWindowReceive feeds random (packetID, payload) pairs to
// RecvWindow.Receive to verify it never panics or deadlocks.
//
// The seed corpus uses the first realistic packet ID (0) and a minimal
// payload, covering the common case where the window is fresh.
func FuzzRecvWindowReceive(f *testing.F) {
	// Seed: packetID=0, small payload.
	f.Add(uint32(0), []byte("hello"))
	// Seed: packetID matching window size boundary.
	f.Add(uint32(reliable.WindowSize-1), []byte{0x01, 0x02})
	// Seed: packetID well beyond window (should be dropped).
	f.Add(uint32(reliable.WindowSize+100), []byte{})
	// Seed: packetID wraps (near max uint32).
	f.Add(^uint32(0), []byte("wrap"))
	// Seed: realistic multi-byte packet.
	payload := make([]byte, 1024)
	binary.BigEndian.PutUint32(payload[:4], 42)
	f.Add(uint32(0), payload)

	f.Fuzz(func(t *testing.T, packetID uint32, payload []byte) {
		w := reliable.NewRecvWindow()
		// First call — must not panic.
		payloads, ackIDs := w.Receive(packetID, payload)

		// Structural invariant: if we got payloads, we must have got ackIDs.
		if len(payloads) > 0 && len(ackIDs) == 0 {
			t.Errorf("got %d payloads but no ackIDs for packetID=%d", len(payloads), packetID)
		}

		// Second call with the same ID — must not panic and must not return
		// the payload again (duplicate suppression).
		payloads2, _ := w.Receive(packetID, payload)
		if len(payloads2) > 0 {
			t.Errorf("duplicate packetID=%d returned payload on second call", packetID)
		}
	})
}
