package compress_test

import (
	"testing"

	"github.com/openlawsvpn/go-openvpn3/internal/compress"
)

// TestParseModeNone verifies that a PUSH_REPLY without compression options
// returns ModeNone.
func TestParseModeNone(t *testing.T) {
	msg := "PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5,route 10.0.0.0 255.255.0.0,cipher AES-256-GCM"
	if got := compress.ParseMode(msg); got != compress.ModeNone {
		t.Errorf("ParseMode = %v, want ModeNone", got)
	}
}

// TestParseModeLZ4 verifies detection of 'compress lz4'.
func TestParseModeLZ4(t *testing.T) {
	cases := []string{
		"PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5,compress lz4",
		"compress lz4,route 10.0.0.0 255.255.0.0",
		"compress lz4-v2",
	}
	for _, msg := range cases {
		if got := compress.ParseMode(msg); got != compress.ModeLZ4 {
			t.Errorf("ParseMode(%q) = %v, want ModeLZ4", msg, got)
		}
	}
}

// TestParseModeLZO verifies detection of 'comp-lzo' (with warning).
func TestParseModeLZO(t *testing.T) {
	cases := []string{
		"PUSH_REPLY,comp-lzo,route 10.0.0.0 255.255.0.0",
		"comp-lzo no",
	}
	for _, msg := range cases {
		if got := compress.ParseMode(msg); got != compress.ModeLZO {
			t.Errorf("ParseMode(%q) = %v, want ModeLZO", msg, got)
		}
	}
}

// TestWrapUnwrapLZ4 verifies the stub-byte round-trip for ModeLZ4.
func TestWrapUnwrapLZ4(t *testing.T) {
	payload := []byte("hello openvpn3 compress")
	wrapped := compress.Wrap(compress.ModeLZ4, payload)

	if len(wrapped) != len(payload)+1 {
		t.Fatalf("Wrap: len=%d, want %d", len(wrapped), len(payload)+1)
	}
	if wrapped[0] != 0x69 {
		t.Fatalf("Wrap: first byte = 0x%02x, want 0x69", wrapped[0])
	}

	unwrapped, err := compress.Unwrap(compress.ModeLZ4, wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(unwrapped) != string(payload) {
		t.Fatalf("Unwrap: got %q, want %q", unwrapped, payload)
	}
}

// TestWrapUnwrapNone verifies that ModeNone is a pass-through.
func TestWrapUnwrapNone(t *testing.T) {
	payload := []byte("no compression here")
	if got := compress.Wrap(compress.ModeNone, payload); string(got) != string(payload) {
		t.Errorf("Wrap(ModeNone): payload changed")
	}
	got, err := compress.Unwrap(compress.ModeNone, payload)
	if err != nil {
		t.Fatalf("Unwrap(ModeNone): %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("Unwrap(ModeNone): payload changed")
	}
}

// TestWrapUnwrapLZO verifies that ModeLZO is also a pass-through (no bytes stripped).
func TestWrapUnwrapLZO(t *testing.T) {
	payload := []byte("comp-lzo pass-through")
	if got := compress.Wrap(compress.ModeLZO, payload); string(got) != string(payload) {
		t.Errorf("Wrap(ModeLZO): payload changed")
	}
	got, err := compress.Unwrap(compress.ModeLZO, payload)
	if err != nil {
		t.Fatalf("Unwrap(ModeLZO): %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("Unwrap(ModeLZO): payload changed")
	}
}

// TestUnwrapLZ4CompressedError verifies that a 0xfa stub byte returns an error.
func TestUnwrapLZ4CompressedError(t *testing.T) {
	payload := []byte{0xfa, 0x01, 0x02}
	_, err := compress.Unwrap(compress.ModeLZ4, payload)
	if err == nil {
		t.Fatal("expected error for compressed (0xfa) payload")
	}
}

// TestUnwrapLZ4EmptyError verifies that an empty payload returns an error for LZ4.
func TestUnwrapLZ4EmptyError(t *testing.T) {
	_, err := compress.Unwrap(compress.ModeLZ4, []byte{})
	if err == nil {
		t.Fatal("expected error for empty payload in LZ4 mode")
	}
}

// TestUnwrapLZ4BadStubByte verifies that an unknown stub byte returns an error.
func TestUnwrapLZ4BadStubByte(t *testing.T) {
	payload := []byte{0xFF, 0x01}
	_, err := compress.Unwrap(compress.ModeLZ4, payload)
	if err == nil {
		t.Fatal("expected error for unknown stub byte 0xFF")
	}
}
