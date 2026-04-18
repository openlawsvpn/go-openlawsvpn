package prf_test

import (
	"bytes"
	"testing"

	"github.com/openlawsvpn/go-openvpn3/internal/prf"
)

// TestDeriveLength checks that Derive produces exactly n bytes.
func TestDeriveLength(t *testing.T) {
	secret := make([]byte, 48)
	seed := make([]byte, 64)
	for _, n := range []int{1, 32, 64, 100, 128, 200} {
		out, err := prf.Derive(secret, "test label", seed, n)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if len(out) != n {
			t.Fatalf("n=%d: got %d bytes", n, len(out))
		}
	}
}

// TestDeriveDeterministic checks that same inputs always produce same output.
func TestDeriveDeterministic(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, 48)
	seed := bytes.Repeat([]byte{0xCD}, 64)
	a, _ := prf.Derive(secret, "OpenVPN master secret", seed, 128)
	b, _ := prf.Derive(secret, "OpenVPN master secret", seed, 128)
	if !bytes.Equal(a, b) {
		t.Fatal("non-deterministic output")
	}
}

// TestDeriveDifferentLabels checks that different labels produce different output.
func TestDeriveDifferentLabels(t *testing.T) {
	secret := make([]byte, 48)
	seed := make([]byte, 64)
	a, _ := prf.Derive(secret, "label A", seed, 32)
	b, _ := prf.Derive(secret, "label B", seed, 32)
	if bytes.Equal(a, b) {
		t.Fatal("different labels produced identical output")
	}
}

// TestDeriveError checks that n<=0 returns an error.
func TestDeriveError(t *testing.T) {
	_, err := prf.Derive(nil, "", nil, 0)
	if err == nil {
		t.Fatal("expected error for n=0")
	}
}

// TestExpandKeys checks that ExpandKeys splits the 128 output bytes correctly.
func TestExpandKeys(t *testing.T) {
	master := bytes.Repeat([]byte{0x01}, 48)
	cRand := bytes.Repeat([]byte{0x02}, 32)
	sRand := bytes.Repeat([]byte{0x03}, 32)

	km, err := prf.ExpandKeys(master, cRand, sRand)
	if err != nil {
		t.Fatal(err)
	}

	// All four slots must be 64 bytes (openvpn3-core KEY_SIZE=64).
	for name, slot := range map[string][]byte{
		"ClientCipher": km.ClientCipher,
		"ClientHMAC":   km.ClientHMAC,
		"ServerCipher": km.ServerCipher,
		"ServerHMAC":   km.ServerHMAC,
	} {
		if len(slot) != 64 {
			t.Errorf("%s: len=%d, want 64", name, len(slot))
		}
	}

	// Client and server keys must differ.
	if bytes.Equal(km.ClientCipher, km.ServerCipher) {
		t.Error("ClientCipher == ServerCipher")
	}

	// Consistent with raw Derive output (256 bytes = 4 × 64-byte slots).
	seed := append(append([]byte{}, cRand...), sRand...)
	raw, _ := prf.Derive(master, "OpenVPN master secret", seed, 256)
	if !bytes.Equal(km.ClientCipher, raw[0:64]) {
		t.Error("ClientCipher mismatch with raw Derive")
	}
	if !bytes.Equal(km.ServerHMAC, raw[192:256]) {
		t.Error("ServerHMAC mismatch with raw Derive")
	}
}
