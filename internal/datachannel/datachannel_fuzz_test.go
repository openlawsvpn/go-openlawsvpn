package datachannel_test

import (
	"bytes"
	"testing"

	"github.com/openlawsvpn/go-openvpn3/internal/datachannel"
)

// FuzzChannelDecrypt feeds random byte slices to Channel.Decrypt to verify
// it never panics regardless of input.
//
// The seed corpus contains a valid GCM-encrypted P_DATA_V2 packet produced
// by Channel.Encrypt so the fuzzer starts from a realistic encoding.
func FuzzChannelDecrypt(f *testing.F) {
	txKey := bytes.Repeat([]byte{0xAA}, 32)
	txIV := bytes.Repeat([]byte{0x55}, 8)
	rxKey := bytes.Repeat([]byte{0xBB}, 32)
	rxIV := bytes.Repeat([]byte{0x66}, 8)

	enc, err := datachannel.New(0, 0, txKey, txIV, rxKey, rxIV)
	if err != nil {
		f.Fatal(err)
	}

	// Build a valid P_DATA_V2 packet to use as seed.
	// We need a matching decrypt channel (rx key of enc = tx key of dec).
	dec, err := datachannel.New(0, 0, rxKey, rxIV, txKey, txIV)
	if err != nil {
		f.Fatal(err)
	}
	validPkt, err := enc.Encrypt([]byte("seed plaintext for datachannel fuzzer"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validPkt)

	// Seed: empty packet.
	f.Add([]byte{})
	// Seed: 4-byte header only (no GCM payload).
	f.Add([]byte{0x48, 0x00, 0x00, 0x00})
	// Seed: header + packet_id, no ciphertext.
	f.Add([]byte{0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	// Seed: all-zero packet at minimum GCM length (header+pid+tag).
	f.Add(make([]byte, 4+4+16))

	f.Fuzz(func(t *testing.T, pkt []byte) {
		// Must not panic.
		_, _ = dec.Decrypt(pkt)
	})
}
