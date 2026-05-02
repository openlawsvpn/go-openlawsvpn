// Package datachannel implements the OpenVPN3 data channel: P_DATA_V2 packet
// framing, the encrypt/decrypt pipeline, and replay-protection sliding window.
//
// P_DATA_V2 wire layout — GCM mode (openvpn3-core ssl/proto.hpp):
//
//	[opcode|keyid (1B)][peer_id (3B)][packet_id (4B)][ciphertext+GCM-tag]
//
// For AES-256-GCM the AAD for authentication is the 4-byte header
// (opcode+peer_id) and the first 4 bytes after it (packet_id).
//
// P_DATA_V2 wire layout — CBC mode:
//
//	[opcode|keyid (1B)][peer_id (3B)][HMAC (32B)][IV (16B)][ciphertext]
//
// The packet_id is embedded in the first 4 bytes of the AES-CBC plaintext
// for replay protection; the P_DATA_V2 header (4B) is NOT authenticated.
//
// Replay protection uses a 64-bit sliding window (matching openvpn3-core
// REPLAY_WINDOW_SIZE).
//
// Reference: openvpn3-core crypto/cipher.hpp, data_epoch.cpp, ssl/proto.hpp
package datachannel

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/openlawsvpn/go-openlawsvpn/internal/crypto"
	"github.com/openlawsvpn/go-openlawsvpn/internal/framing"
)

// replayWindowSize is the number of bits in the replay-protection window.
// Matches openvpn3-core REPLAY_WINDOW_SIZE (64 in recent versions).
const replayWindowSize = 64

// Channel encrypts and decrypts data-channel packets for one key epoch.
//
// A Channel is safe for concurrent use by multiple goroutines.
type Channel struct {
	peerID    uint32 // 3-byte peer_id assigned by the server
	keyID     uint8
	encryptor crypto.DataCipher
	decryptor crypto.DataCipher

	mu        sync.Mutex
	sendSeq   uint32
	replayBit [replayWindowSize]bool
	replayTop uint32
	replaySet bool // true once any packet has been received
}

// New creates a Channel using AES-256-GCM for both directions.
//
//   - peerID:  3-byte peer identifier from the server (0 for first connection)
//   - keyID:   key slot index (0–7)
//   - txKey:   cipher key for the send direction (32 bytes for AES-256-GCM)
//   - txIV:    implicit IV for the send direction (12 bytes)
//   - rxKey:   cipher key for the receive direction
//   - rxIV:    implicit IV for the receive direction
func New(peerID uint32, keyID uint8, txKey, txIV, rxKey, rxIV []byte) (*Channel, error) {
	enc, err := crypto.NewGCMCipher(txKey, txIV)
	if err != nil {
		return nil, fmt.Errorf("datachannel: tx cipher: %w", err)
	}
	dec, err := crypto.NewGCMCipher(rxKey, rxIV)
	if err != nil {
		return nil, fmt.Errorf("datachannel: rx cipher: %w", err)
	}
	return newWithCiphers(peerID, keyID, enc, dec), nil
}

// NewCBC creates a Channel using AES-256-CBC + HMAC-SHA256 for both directions.
//
//   - peerID:    3-byte peer identifier
//   - keyID:     key slot index (0–7)
//   - txAESKey:  32-byte AES key, send direction
//   - txHMACKey: 32-byte HMAC key, send direction
//   - rxAESKey:  32-byte AES key, receive direction
//   - rxHMACKey: 32-byte HMAC key, receive direction
func NewCBC(peerID uint32, keyID uint8, txAESKey, txHMACKey, rxAESKey, rxHMACKey []byte) (*Channel, error) {
	enc, err := crypto.NewCBCCipher(txAESKey, txHMACKey)
	if err != nil {
		return nil, fmt.Errorf("datachannel: tx CBC cipher: %w", err)
	}
	dec, err := crypto.NewCBCCipher(rxAESKey, rxHMACKey)
	if err != nil {
		return nil, fmt.Errorf("datachannel: rx CBC cipher: %w", err)
	}
	return newWithCiphers(peerID, keyID, enc, dec), nil
}

// newWithCiphers is the internal constructor used by New and NewCBC.
func newWithCiphers(peerID uint32, keyID uint8, enc, dec crypto.DataCipher) *Channel {
	return &Channel{
		peerID:    peerID & 0x00FFFFFF,
		keyID:     keyID & 0x07,
		encryptor: enc,
		decryptor: dec,
	}
}

// Encrypt encapsulates a plaintext IP packet into a P_DATA_V2 wire packet.
//
// For GCM mode the packet_id appears explicitly after the header; the
// ciphertext follows with the 16-byte GCM tag appended.
//
// For CBC mode the packet_id is embedded as the first 4 bytes of the
// plaintext before encryption; the HMAC and IV appear in the body.
func (c *Channel) Encrypt(plaintext []byte) ([]byte, error) {
	c.mu.Lock()
	seq := c.sendSeq
	c.sendSeq++
	c.mu.Unlock()

	// Build the 4-byte header: [opcode+keyid][peer_id 3B]
	header := buildHeader(framing.P_DATA_V2, c.keyID, c.peerID)

	if c.encryptor.IsAEAD() {
		return c.encryptGCM(header, seq, plaintext)
	}
	return c.encryptCBC(header, seq, plaintext)
}

// encryptGCM builds a P_DATA_V2 packet for AEAD modes.
//
// Wire: header(4B) + packet_id(4B) + tag(16B) + ciphertext
// AAD = header(4B) + packet_id(4B)
//
// Reference: openvpn3-core crypto/crypto_aead.hpp encrypt() sample comment:
//   48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
//   [ OP32 ] [seq # ] [             auth tag            ] [ payload ... ]
func (c *Channel) encryptGCM(header []byte, seq uint32, plaintext []byte) ([]byte, error) {
	// AAD = header || packet_id (both authenticated but not encrypted)
	var seqBuf [4]byte
	binary.BigEndian.PutUint32(seqBuf[:], seq)
	aad := append(header, seqBuf[:]...) //nolint:gocritic // intentional append

	ct := c.encryptor.Seal(seq, plaintext, aad)

	// Wire: header(4B) + packet_id(4B) + ciphertext+tag
	pkt := make([]byte, 4+4+len(ct))
	copy(pkt[:4], header)
	binary.BigEndian.PutUint32(pkt[4:8], seq)
	copy(pkt[8:], ct)
	return pkt, nil
}

// encryptCBC builds a P_DATA_V2 packet for CBC+HMAC mode.
// Wire: header(4B) + body  where body = [HMAC(32)][IV(16)][ciphertext]
// Plaintext passed to CBCCipher.Seal includes a 4-byte packet_id prefix.
func (c *Channel) encryptCBC(header []byte, seq uint32, plaintext []byte) ([]byte, error) {
	// Prepend packet_id to plaintext so it is encrypted and authenticated.
	inner := make([]byte, 4+len(plaintext))
	binary.BigEndian.PutUint32(inner[:4], seq)
	copy(inner[4:], plaintext)

	body := c.encryptor.Seal(seq, inner, nil)

	pkt := make([]byte, 4+len(body))
	copy(pkt[:4], header)
	copy(pkt[4:], body)
	return pkt, nil
}

// Decrypt decapsulates a P_DATA_V2 wire packet into a plaintext IP packet.
// It enforces replay protection.
func (c *Channel) Decrypt(pkt []byte) ([]byte, error) {
	if c.decryptor.IsAEAD() {
		return c.decryptGCM(pkt)
	}
	return c.decryptCBC(pkt)
}

// decryptGCM handles GCM-mode P_DATA_V2 packets.
//
// Wire: header(4B) + packet_id(4B) + tag(16B) + ciphertext
// (tag precedes ciphertext — see GCMCipher.Open for reorder logic)
func (c *Channel) decryptGCM(pkt []byte) ([]byte, error) {
	const minLen = 4 + 4 + 16 // header + packetID + min GCM tag
	if len(pkt) < minLen {
		return nil, fmt.Errorf("datachannel: GCM packet too short: %d bytes", len(pkt))
	}

	header := pkt[:4]
	seq := binary.BigEndian.Uint32(pkt[4:8])
	ct := pkt[8:]

	if err := c.checkReplay(seq); err != nil {
		return nil, err
	}

	aad := pkt[:8] // header + packet_id
	plain, err := c.decryptor.Open(seq, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("datachannel: decrypt GCM seq=%d: %w", seq, err)
	}
	_ = header
	c.markSeen(seq)
	return plain, nil
}

// decryptCBC handles CBC+HMAC P_DATA_V2 packets.
// Wire: header(4B) + [HMAC(32)][IV(16)][ciphertext]
// After decryption the first 4 bytes of plaintext are the packet_id.
func (c *Channel) decryptCBC(pkt []byte) ([]byte, error) {
	const minBodyLen = 32 + 16 + 16 // HMAC + IV + 1 ciphertext block
	if len(pkt) < 4+minBodyLen {
		return nil, fmt.Errorf("datachannel: CBC packet too short: %d bytes", len(pkt))
	}

	body := pkt[4:] // strip P_DATA_V2 header

	inner, err := c.decryptor.Open(0, body, nil)
	if err != nil {
		return nil, fmt.Errorf("datachannel: decrypt CBC: %w", err)
	}
	if len(inner) < 4 {
		return nil, fmt.Errorf("datachannel: CBC plaintext too short after decrypt")
	}

	seq := binary.BigEndian.Uint32(inner[:4])
	if err := c.checkReplay(seq); err != nil {
		return nil, err
	}
	c.markSeen(seq)
	return inner[4:], nil // strip the embedded packet_id
}

// buildHeader constructs the 4-byte P_DATA_V2 header.
func buildHeader(opcode, keyID uint8, peerID uint32) []byte {
	h := make([]byte, 4)
	h[0] = framing.FirstByte(opcode, keyID)
	h[1] = byte(peerID >> 16)
	h[2] = byte(peerID >> 8)
	h[3] = byte(peerID)
	return h
}

// checkReplay returns an error if seq has been seen before or is too old.
func (c *Channel) checkReplay(seq uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.replaySet {
		return nil // first packet ever — always allowed
	}
	if seq > c.replayTop {
		return nil // new high-water mark — always allowed
	}
	diff := c.replayTop - seq
	if diff >= replayWindowSize {
		return fmt.Errorf("datachannel: replay: seq %d too old (top=%d)", seq, c.replayTop)
	}
	if c.replayBit[diff] {
		return fmt.Errorf("datachannel: replay: seq %d already seen", seq)
	}
	return nil
}

// markSeen records seq as received and advances the replay window if needed.
func (c *Channel) markSeen(seq uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.replaySet || seq > c.replayTop {
		advance := uint32(0)
		if c.replaySet {
			advance = seq - c.replayTop
		}
		// Shift window: clear bits that are moving into range.
		for i := uint32(0); i < advance && i < replayWindowSize; i++ {
			c.replayBit[(c.replayTop+1+i)%replayWindowSize] = false
		}
		c.replayTop = seq
		c.replaySet = true
	}
	diff := c.replayTop - seq
	if diff < replayWindowSize {
		c.replayBit[diff] = true
	}
}
