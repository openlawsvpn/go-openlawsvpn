// CBC cipher implementation for the OpenVPN3 data channel.
//
// AES-256-CBC with HMAC-SHA256 is the legacy cipher mode used when the
// server does not negotiate an AEAD cipher.  The wire layout for the body
// portion of a P_DATA_V2 packet in CBC mode is:
//
//	[HMAC-SHA256 (32 B)][random IV (16 B)][AES-CBC ciphertext (padded to 16B)]
//
// The HMAC covers: IV || ciphertext.
// The plaintext includes a 4-byte packet_id prefix (big-endian) prepended
// by the caller so that replay-protection works the same way as for GCM.
//
// Reference: openvpn3-core crypto/cipher.hpp, ssl/proto.hpp (P_DATA_V2 CBC path)
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// CBCCipher encrypts and decrypts data-channel packets with AES-CBC and
// HMAC-SHA256 authentication.
//
// Wire body layout (excluding the 4-byte P_DATA_V2 header):
//
//	[HMAC (32 B)][IV (16 B)][ciphertext (multiple of 16 B)]
//
// The HMAC authenticates IV || ciphertext.
// The plaintext is: [packet_id (4 B BE)][ip_packet...][PKCS#7 padding]
type CBCCipher struct {
	block   cipher.Block
	hmacKey []byte // 32 bytes for HMAC-SHA256
}

// NewCBCCipher creates a CBCCipher from a 32-byte AES key and a 32-byte HMAC key.
func NewCBCCipher(aesKey, hmacKey []byte) (*CBCCipher, error) {
	if len(aesKey) != 32 {
		return nil, fmt.Errorf("crypto: CBC AES key must be 32 bytes, got %d", len(aesKey))
	}
	if len(hmacKey) != 32 {
		return nil, fmt.Errorf("crypto: CBC HMAC key must be 32 bytes, got %d", len(hmacKey))
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: CBC AES key: %w", err)
	}
	hk := make([]byte, len(hmacKey))
	copy(hk, hmacKey)
	return &CBCCipher{block: block, hmacKey: hk}, nil
}

// Seal encrypts plaintext (which must already include a 4-byte packet_id prefix)
// and returns [HMAC(32)][IV(16)][ciphertext].
//
// aad is unused for CBC (the P_DATA_V2 header is NOT authenticated in the
// legacy HMAC path). packetID is ignored because the caller embeds it in
// plaintext before calling Seal.
func (c *CBCCipher) Seal(_ uint32, plaintext, _ []byte) []byte {
	bs := c.block.BlockSize() // 16

	// Generate random IV.
	iv := make([]byte, bs)
	if _, err := rand.Read(iv); err != nil {
		panic("crypto: rand.Read failed: " + err.Error())
	}

	// PKCS#7 pad plaintext.
	padded := pkcs7Pad(plaintext, bs)

	// Encrypt with AES-CBC.
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(c.block, iv).CryptBlocks(ct, padded)

	// Compute HMAC-SHA256 over IV || ciphertext.
	mac := hmac.New(sha256.New, c.hmacKey)
	mac.Write(iv)
	mac.Write(ct)
	tag := mac.Sum(nil) // 32 bytes

	// Wire: HMAC || IV || ciphertext
	out := make([]byte, 32+bs+len(ct))
	copy(out[0:32], tag)
	copy(out[32:32+bs], iv)
	copy(out[32+bs:], ct)
	return out
}

// Open decrypts a CBC body: [HMAC(32)][IV(16)][ciphertext].
// Returns the plaintext (with the 4-byte packet_id prefix still present) or
// an error if HMAC verification fails or padding is corrupt.
//
// aad is unused. packetID is ignored; the caller validates it from the plaintext.
func (c *CBCCipher) Open(_ uint32, body, _ []byte) ([]byte, error) {
	bs := c.block.BlockSize()
	const hmacLen = 32
	minLen := hmacLen + bs + bs // HMAC + IV + at least one ciphertext block
	if len(body) < minLen {
		return nil, fmt.Errorf("crypto: CBC body too short: %d bytes", len(body))
	}
	if (len(body)-hmacLen-bs)%bs != 0 {
		return nil, fmt.Errorf("crypto: CBC ciphertext length not block-aligned")
	}

	tag := body[:hmacLen]
	iv := body[hmacLen : hmacLen+bs]
	ct := body[hmacLen+bs:]

	// Verify HMAC.
	mac := hmac.New(sha256.New, c.hmacKey)
	mac.Write(iv)
	mac.Write(ct)
	expected := mac.Sum(nil)
	if subtle.ConstantTimeCompare(tag, expected) != 1 {
		return nil, fmt.Errorf("crypto: CBC HMAC authentication failed")
	}

	// Decrypt.
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(c.block, iv).CryptBlocks(plain, ct)

	// Remove PKCS#7 padding.
	unpadded, err := pkcs7Unpad(plain, bs)
	if err != nil {
		return nil, fmt.Errorf("crypto: CBC: %w", err)
	}
	return unpadded, nil
}

// IsAEAD returns false because CBC uses a separate HMAC for authentication.
func (c *CBCCipher) IsAEAD() bool { return false }

// Overhead returns the fixed overhead: 32 (HMAC) + 16 (IV) + up to 16 (pad).
// The maximum overhead is 64 bytes.
func (c *CBCCipher) Overhead() int { return 32 + 16 + 16 }

// pkcs7Pad pads src to a multiple of blockSize using PKCS#7.
func pkcs7Pad(src []byte, blockSize int) []byte {
	padLen := blockSize - (len(src) % blockSize)
	padded := make([]byte, len(src)+padLen)
	copy(padded, src)
	for i := len(src); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded
}

// pkcs7Unpad removes PKCS#7 padding from src.
func pkcs7Unpad(src []byte, blockSize int) ([]byte, error) {
	if len(src) == 0 || len(src)%blockSize != 0 {
		return nil, fmt.Errorf("pkcs7: invalid padded length %d", len(src))
	}
	padLen := int(src[len(src)-1])
	if padLen == 0 || padLen > blockSize {
		return nil, fmt.Errorf("pkcs7: invalid padding value %d", padLen)
	}
	for i := len(src) - padLen; i < len(src); i++ {
		if src[i] != byte(padLen) {
			return nil, fmt.Errorf("pkcs7: inconsistent padding bytes")
		}
	}
	return src[:len(src)-padLen], nil
}
