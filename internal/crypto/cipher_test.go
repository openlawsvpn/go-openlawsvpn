package crypto_test

import (
	"bytes"
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/internal/crypto"
)

func TestParseSuite(t *testing.T) {
	cases := []struct {
		name string
		want crypto.Suite
		ok   bool
	}{
		{"AES-256-GCM", crypto.SuiteAES256GCM, true},
		{"AES-128-GCM", crypto.SuiteAES128GCM, true},
		{"AES-256-CBC", crypto.SuiteAES256CBC, true},
		{"CHACHA20", 0, false},
	}
	for _, c := range cases {
		s, err := crypto.ParseSuite(c.name)
		if c.ok && (err != nil || s != c.want) {
			t.Errorf("ParseSuite(%q): got (%v,%v), want (%v,nil)", c.name, s, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("ParseSuite(%q): expected error", c.name)
		}
	}
}

func TestGCMSealOpen(t *testing.T) {
	key := bytes.Repeat([]byte{0xAA}, 32) // AES-256
	tail := bytes.Repeat([]byte{0x55}, 8) // 8-byte nonce tail (from HMAC key slice)

	gc, err := crypto.NewGCMCipher(key, tail)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello openvpn data channel")
	aad := []byte{0x09, 0x00, 0x00, 0x01} // fake P_DATA_V2 header

	ct := gc.Seal(1, plaintext, aad)
	if bytes.Equal(ct, plaintext) {
		t.Fatal("ciphertext should not equal plaintext")
	}

	pt, err := gc.Open(1, ct, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("roundtrip mismatch: got %q want %q", pt, plaintext)
	}
}

func TestGCMWrongPacketID(t *testing.T) {
	key := bytes.Repeat([]byte{0xBB}, 32)
	tail := make([]byte, 8)
	gc, _ := crypto.NewGCMCipher(key, tail)

	ct := gc.Seal(1, []byte("data"), nil)
	// Decrypt with wrong packet ID — nonce mismatch → auth failure.
	_, err := gc.Open(2, ct, nil)
	if err == nil {
		t.Fatal("expected auth failure for wrong packet ID")
	}
}

func TestGCMWrongAAD(t *testing.T) {
	key := bytes.Repeat([]byte{0xCC}, 32)
	tail := make([]byte, 8)
	gc, _ := crypto.NewGCMCipher(key, tail)

	ct := gc.Seal(0, []byte("data"), []byte("aad1"))
	_, err := gc.Open(0, ct, []byte("aad2"))
	if err == nil {
		t.Fatal("expected auth failure for wrong AAD")
	}
}

func TestNewGCMCipherBadTail(t *testing.T) {
	key := make([]byte, 32)
	_, err := crypto.NewGCMCipher(key, make([]byte, 3)) // too short
	if err == nil {
		t.Fatal("expected error for nonce tail that is too short")
	}
}

func TestNewGCMCipherBadKey(t *testing.T) {
	_, err := crypto.NewGCMCipher(make([]byte, 7), make([]byte, 8)) // invalid key
	if err == nil {
		t.Fatal("expected error for bad key length")
	}
}

func TestGCMIsAEAD(t *testing.T) {
	gc, _ := crypto.NewGCMCipher(make([]byte, 32), make([]byte, 8))
	if !gc.IsAEAD() {
		t.Fatal("GCM should report IsAEAD() == true")
	}
}

func TestCBCSealOpen(t *testing.T) {
	aesKey := bytes.Repeat([]byte{0x11}, 32)
	hmacKey := bytes.Repeat([]byte{0x22}, 32)
	c, err := crypto.NewCBCCipher(aesKey, hmacKey)
	if err != nil {
		t.Fatal(err)
	}

	// CBC callers embed packet_id as first 4 bytes of plaintext.
	plain := append([]byte{0, 0, 0, 1}, []byte("hello openvpn cbc")...)
	body := c.Seal(0, plain, nil)
	if len(body) < 32+16 {
		t.Fatalf("body too short: %d", len(body))
	}

	got, err := c.Open(0, body, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, plain)
	}
}

func TestCBCIsAEAD(t *testing.T) {
	c, _ := crypto.NewCBCCipher(make([]byte, 32), make([]byte, 32))
	if c.IsAEAD() {
		t.Fatal("CBC should report IsAEAD() == false")
	}
}

func TestCBCBadHMAC(t *testing.T) {
	aesKey := bytes.Repeat([]byte{0x33}, 32)
	hmacKey := bytes.Repeat([]byte{0x44}, 32)
	c, _ := crypto.NewCBCCipher(aesKey, hmacKey)

	plain := []byte{0, 0, 0, 0, 'p', 'a', 'd'}
	body := c.Seal(0, plain, nil)
	// Corrupt the HMAC.
	body[0] ^= 0xFF
	if _, err := c.Open(0, body, nil); err == nil {
		t.Fatal("expected HMAC error for corrupted body")
	}
}

func TestCBCBadKeyLen(t *testing.T) {
	_, err := crypto.NewCBCCipher(make([]byte, 16), make([]byte, 32)) // 16-byte AES key invalid
	if err == nil {
		t.Fatal("expected error for 16-byte AES key (need 32)")
	}
}
