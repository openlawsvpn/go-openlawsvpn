// Package crypto implements the OpenVPN3 data-channel cipher suite.
//
// Supported ciphers:
//   - AES-256-GCM  (primary, used by AWS Client VPN)
//   - AES-128-GCM
//   - AES-256-CBC  (legacy, no AEAD tag — separate HMAC-SHA256 required)
//
// Reference: openvpn3-core crypto/cipher.hpp, data_epoch.cpp
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// DataCipher is the interface implemented by all supported data-channel ciphers.
//
// Seal encrypts plaintext and returns ciphertext (plus tag for AEAD modes,
// or HMAC prepended for CBC mode).  aad is the AAD header for GCM; ignored
// for CBC.  packetID is the 32-bit counter used in IV derivation.
//
// Open decrypts ciphertext (including the authentication data) and returns
// plaintext, or a non-nil error if authentication fails or the packet is
// malformed.
//
// IsAEAD reports whether the cipher is an AEAD mode (GCM). When false, the
// data channel uses the CBC-with-HMAC path.
//
// Overhead returns the number of bytes added by encryption beyond the
// plaintext length. For GCM this is 12 (IV) + 16 (tag) = 28; for CBC it is
// 16 (random IV) + 32 (HMAC-SHA256).
type DataCipher interface {
	Seal(packetID uint32, plaintext, aad []byte) []byte
	Open(packetID uint32, ciphertext, aad []byte) ([]byte, error)
	IsAEAD() bool
	Overhead() int
}

// Suite identifies the negotiated cipher suite.
type Suite int

const (
	// SuiteAES256GCM is AES-256-GCM (recommended).
	SuiteAES256GCM Suite = iota
	// SuiteAES128GCM is AES-128-GCM.
	SuiteAES128GCM
	// SuiteAES256CBC is AES-256-CBC with HMAC-SHA256 (legacy).
	SuiteAES256CBC
)

// ParseSuite maps the cipher name from a .ovpn profile / PUSH_REPLY to a Suite.
func ParseSuite(name string) (Suite, error) {
	switch name {
	case "AES-256-GCM":
		return SuiteAES256GCM, nil
	case "AES-128-GCM":
		return SuiteAES128GCM, nil
	case "AES-256-CBC":
		return SuiteAES256CBC, nil
	default:
		return 0, fmt.Errorf("crypto: unsupported cipher %q", name)
	}
}

// GCMCipher encrypts and decrypts data-channel packets with AES-GCM.
//
// IV construction (openvpn3-core data_epoch.cpp):
//
//	iv = implicit_iv XOR (packetID zero-padded to ivLen bytes, big-endian)
//
// The implicit IV is derived from the key material (last ivLen bytes of
// the HMAC key slot, or a dedicated field — see ExpandImplicitIV).
type GCMCipher struct {
	aead       cipher.AEAD
	implicitIV []byte // len == aead.NonceSize()
}

// NewGCMCipher creates a GCMCipher from a raw AES key and a nonce tail.
//
//   - key:       16 bytes for AES-128-GCM, 32 bytes for AES-256-GCM
//   - nonceTail: 8 bytes — the last 8 bytes of the 12-byte GCM nonce
//     (set from the first 8 bytes of the HMAC key slice via set_tail in
//     openvpn3-core crypto_aead.hpp).
func NewGCMCipher(key, nonceTail []byte) (*GCMCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: AES key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: GCM: %w", err)
	}
	const tailLen = 8
	if len(nonceTail) < tailLen {
		return nil, fmt.Errorf("crypto: nonceTail len=%d, want %d", len(nonceTail), tailLen)
	}
	iv := make([]byte, tailLen)
	copy(iv, nonceTail[:tailLen])
	return &GCMCipher{aead: aead, implicitIV: iv}, nil
}

// buildNonce constructs the 12-byte GCM nonce for a given 32-bit packet ID.
//
// openvpn3-core crypto_aead.hpp Nonce layout (data[16]):
//
//	data[0..3]   = op32 (used as AAD, not part of IV)
//	data[4..7]   = packet_id (4 bytes, big-endian) — placed here by pid_send
//	data[8..15]  = nonce tail (first 8 bytes of the HMAC key slice, set by set_tail)
//
// The 12-byte crypto IV is data[4..15]: packet_id(4B) || tail(8B).
// implicitIV here holds the 8-byte tail (no XOR — it's set directly).
func (g *GCMCipher) buildNonce(packetID uint32) []byte {
	nonce := make([]byte, g.aead.NonceSize()) // 12 bytes
	// Bytes [0..3]: packet_id (big-endian).
	binary.BigEndian.PutUint32(nonce[0:4], packetID)
	// Bytes [4..11]: nonce tail from HMAC key (8 bytes).
	copy(nonce[4:], g.implicitIV)
	return nonce
}

// Seal encrypts plaintext and returns tag(16B) || ciphertext.
//
// OpenVPN3 wire format (crypto_aead.hpp encrypt, line ~192):
//
//	auth_tag = e.work.prepend_alloc(AUTH_TAG_LEN)  // tag slot at START of buffer
//	e.impl.encrypt(..., work_data, ..., auth_tag, ...)
//	// result: e.work = [tag(16B)][ciphertext(NB)]
//
// The C++ sample confirms: [OP32][seq#][auth_tag(16B)][ciphertext...]
// Go's aead.Seal returns ciphertext||tag; we reorder to match the wire.
func (g *GCMCipher) Seal(packetID uint32, plaintext, aad []byte) []byte {
	nonce := g.buildNonce(packetID)
	// Go produces ciphertext || tag.
	out := g.aead.Seal(nil, nonce, plaintext, aad)
	const tagLen = 16
	ct := out[:len(out)-tagLen]
	tag := out[len(out)-tagLen:]
	// Reorder to tag || ciphertext for the OpenVPN3 wire.
	result := make([]byte, len(out))
	copy(result[:tagLen], tag)
	copy(result[tagLen:], ct)
	return result
}

// Open decrypts a payload in OpenVPN3 wire order: tag(16B) || ciphertext.
//
// OpenVPN3 wire format (crypto_aead.hpp decrypt, line ~238):
//
//	auth_tag = buf.read_alloc(AUTH_TAG_LEN)  // reads 16-byte tag from FRONT
//	d.impl.decrypt(buf.c_data(), ..., auth_tag, ...)  // remaining bytes = ciphertext
//
// Go's aead.Open expects ciphertext||tag; we reorder from tag||ciphertext.
func (g *GCMCipher) Open(packetID uint32, tagThenCT, aad []byte) ([]byte, error) {
	const tagLen = 16
	if len(tagThenCT) < tagLen {
		return nil, fmt.Errorf("crypto: GCM ciphertext too short (%d bytes)", len(tagThenCT))
	}
	nonce := g.buildNonce(packetID)
	// Reorder tag||ciphertext → ciphertext||tag for Go's aead.Open.
	ctWithTag := make([]byte, len(tagThenCT))
	copy(ctWithTag[:len(tagThenCT)-tagLen], tagThenCT[tagLen:])
	copy(ctWithTag[len(tagThenCT)-tagLen:], tagThenCT[:tagLen])
	plain, err := g.aead.Open(nil, nonce, ctWithTag, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: GCM open: %w", err)
	}
	return plain, nil
}

// IsAEAD returns true because GCM is an authenticated encryption mode.
func (g *GCMCipher) IsAEAD() bool { return true }

// Overhead returns the byte overhead added by GCM encryption beyond the
// plaintext: 16 bytes for the authentication tag. The IV is derived from the
// packet counter (already in the wire header) so it adds 0 overhead here.
func (g *GCMCipher) Overhead() int { return 16 }
