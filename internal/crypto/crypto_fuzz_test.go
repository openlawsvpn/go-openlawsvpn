package crypto_test

import (
	"bytes"
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/internal/crypto"
)

// FuzzCBCOpen feeds random byte slices to CBCCipher.Open to verify it never
// panics. All error paths should return an error, not a panic.
//
// The seed corpus includes a valid CBC body produced by CBCCipher.Seal so the
// fuzzer starts from a realistic encoding and can discover boundary conditions.
func FuzzCBCOpen(f *testing.F) {
	aesKey := bytes.Repeat([]byte{0x11}, 32)
	hmacKey := bytes.Repeat([]byte{0x22}, 32)
	c, err := crypto.NewCBCCipher(aesKey, hmacKey)
	if err != nil {
		f.Fatal(err)
	}

	// Seed: valid body for a small plaintext (packet_id prefix + data).
	validPlain := append([]byte{0, 0, 0, 1}, []byte("seed data for fuzzer")...)
	validBody := c.Seal(0, validPlain, nil)
	f.Add(validBody)

	// Seed: truncated body (HMAC only, no IV or ciphertext).
	f.Add(make([]byte, 32))
	// Seed: empty body.
	f.Add([]byte{})
	// Seed: body exactly at minimum size (HMAC+IV+1 block).
	f.Add(make([]byte, 32+16+16))

	f.Fuzz(func(t *testing.T, body []byte) {
		// Must not panic.
		_, _ = c.Open(0, body, nil)
	})
}

// FuzzGCMOpen feeds random byte slices to GCMCipher.Open to verify it never
// panics and always returns an error for non-authentic inputs.
func FuzzGCMOpen(f *testing.F) {
	key := bytes.Repeat([]byte{0xAA}, 32)
	iv := bytes.Repeat([]byte{0x55}, 8)
	g, err := crypto.NewGCMCipher(key, iv)
	if err != nil {
		f.Fatal(err)
	}

	// Seed: valid GCM ciphertext (plaintext + 16-byte tag).
	aad := []byte{0x09, 0x00, 0x00, 0x01}
	validCT := g.Seal(1, []byte("seed plaintext for fuzzer"), aad)
	f.Add(uint32(1), aad, validCT)

	// Seed: short ciphertext (no room for GCM tag).
	f.Add(uint32(0), []byte{}, make([]byte, 4))
	// Seed: empty ciphertext.
	f.Add(uint32(0), []byte{}, []byte{})
	// Seed: ciphertext exactly at tag length (no plaintext).
	f.Add(uint32(0), []byte{}, make([]byte, 16))

	f.Fuzz(func(t *testing.T, packetID uint32, aad, ct []byte) {
		// Must not panic.
		_, _ = g.Open(packetID, ct, aad)
	})
}
