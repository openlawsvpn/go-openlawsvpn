// Package prf implements the OpenVPN3 key-derivation pseudo-random function.
//
// OpenVPN does NOT use the standard TLS PRF. Instead it uses an HMAC-SHA256
// construction described in openvpn3-core openvpn/prf/prfplus.hpp.
//
// The PRF produces an arbitrary number of bytes via the standard TLS PRF+
// construction (RFC 5246 §5 adapted with HMAC-SHA256):
//
//	A(0) = seed
//	A(i) = HMAC-SHA256(secret, A(i-1))
//	output_block(i) = HMAC-SHA256(secret, A(i) || seed)
//	output = output_block(1) || output_block(2) || ...
//
// Key material is then split as:
//
//	key_material[0:32]  = client→server cipher key
//	key_material[32:64] = client→server HMAC key  (unused for GCM)
//	key_material[64:96] = server→client cipher key
//	key_material[96:128]= server→client HMAC key  (unused for GCM)
//
// Reference: openvpn3-core openvpn/prf/prfplus.hpp, ssl/proto.hpp generate_key_expansion()
package prf

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// Derive runs the OpenVPN HMAC-SHA256 PRF and returns n output bytes.
//
//   - secret: the TLS master secret (48 bytes for TLS 1.2)
//   - label:  ASCII label, e.g. "OpenVPN master secret"
//   - seed:   client_random || server_random (64 bytes for TLS 1.2)
//   - n:      number of output bytes to produce
func Derive(secret []byte, label string, seed []byte, n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("prf: n must be positive, got %d", n)
	}

	// The full seed passed to HMAC is label || seed.
	fullSeed := append([]byte(label), seed...)

	// A(0) = fullSeed
	// A(i) = HMAC(secret, A(i-1))
	aCurrent := fullSeed
	var out []byte

	for len(out) < n {
		// A(i)
		mac := hmac.New(sha256.New, secret)
		mac.Write(aCurrent)
		aCurrent = mac.Sum(nil)

		// output_block = HMAC(secret, A(i) || fullSeed)
		mac = hmac.New(sha256.New, secret)
		mac.Write(aCurrent)
		mac.Write(fullSeed)
		out = append(out, mac.Sum(nil)...)
	}
	return out[:n], nil
}

// KeyMaterial holds the four key slots derived for one session.
//
// Each slot is 64 bytes, matching openvpn3-core crypto/static_key.hpp KEY_SIZE=64.
// Total output is 256 bytes (4 × 64), matching OpenVPNStaticKey::BYTES=256.
//
// For AES-256-GCM: use the first 32 bytes of each cipher slot and first 8 bytes
// of each HMAC slot (nonce tail). For AES-256-CBC: use the first 32 bytes of each
// cipher slot and first 32 bytes of each HMAC slot.
type KeyMaterial struct {
	ClientCipher []byte // client→server AES key slot (64 bytes; use [0:32] for AES-256)
	ClientHMAC   []byte // client→server HMAC/nonce slot (64 bytes; [0:8] for GCM nonce tail)
	ServerCipher []byte // server→client AES key slot (64 bytes; use [0:32] for AES-256)
	ServerHMAC   []byte // server→client HMAC/nonce slot (64 bytes; [0:8] for GCM nonce tail)
}

// ExpandKeys derives the four 64-byte key slots from TLS 1.2 keying material.
//
//   - masterSecret: 48-byte TLS 1.2 master secret (from SSL_SESSION_get_master_key)
//   - clientRandom: 32-byte TLS ClientHello random
//   - serverRandom: 32-byte TLS ServerHello random
//
// The output is 256 bytes split into four 64-byte slots, matching
// openvpn3-core crypto/static_key.hpp OpenVPNStaticKey::BYTES=256, KEY_SIZE=64.
// Slot layout with NORMAL direction (client):
//
//	slot 0 [  0: 64] CIPHER|ENCRYPT → client→server cipher key
//	slot 1 [ 64:128] HMAC|ENCRYPT   → client→server HMAC/nonce material
//	slot 2 [128:192] CIPHER|DECRYPT → server→client cipher key
//	slot 3 [192:256] HMAC|DECRYPT   → server→client HMAC/nonce material
func ExpandKeys(masterSecret, clientRandom, serverRandom []byte) (*KeyMaterial, error) {
	seed := append(append([]byte{}, clientRandom...), serverRandom...)
	raw, err := Derive(masterSecret, "OpenVPN master secret", seed, 256)
	if err != nil {
		return nil, err
	}
	return &KeyMaterial{
		ClientCipher: raw[0:64],
		ClientHMAC:   raw[64:128],
		ServerCipher: raw[128:192],
		ServerHMAC:   raw[192:256],
	}, nil
}
