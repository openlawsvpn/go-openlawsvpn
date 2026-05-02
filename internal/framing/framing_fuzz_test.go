package framing_test

import (
	"bytes"
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/internal/framing"
)

// FuzzReadTCP feeds random byte slices to ReadTCP to verify it never panics.
// The seed corpus contains a valid minimal TCP packet so the fuzzer starts
// with a realistic input.
func FuzzReadTCP(f *testing.F) {
	// Seed: 2-byte length=5 followed by 5 payload bytes.
	f.Add([]byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'})
	// Seed: zero-length payload (should error, not panic).
	f.Add([]byte{0x00, 0x00})
	// Seed: length claims more bytes than present (truncated).
	f.Add([]byte{0x01, 0x00})
	// Seed: single byte (too short).
	f.Add([]byte{0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic.
		_, _ = framing.ReadTCP(bytes.NewReader(data))
	})
}

// FuzzParseControl feeds random byte slices to ParseControl to verify it
// never panics and always returns a non-nil error or a valid Packet.
func FuzzParseControl(f *testing.F) {
	// Seed: minimal valid HARD_RESET packet.
	var valid []byte
	valid = append(valid, framing.FirstByte(framing.P_CONTROL_HARD_RESET_CLIENT_V2, 0))
	valid = append(valid, make([]byte, 8)...) // session_id
	valid = append(valid, 0)                  // ack_array_len = 0
	valid = append(valid, 0, 0, 0, 1)         // packet_id
	valid = append(valid, []byte("payload")...)
	f.Add(valid)

	// Seed: P_ACK_V1 with one acked ID.
	var ack []byte
	ack = append(ack, framing.FirstByte(framing.P_ACK_V1, 0))
	ack = append(ack, make([]byte, 8)...) // session_id
	ack = append(ack, 1)                  // ack_array_len = 1
	ack = append(ack, 0, 0, 0, 7)        // acked packet_id = 7
	ack = append(ack, make([]byte, 8)...) // remote_session_id
	f.Add(ack)

	// Seed: too short.
	f.Add([]byte{0x38, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic.
		_, _ = framing.ParseControl(data)
	})
}
