// Key rotation manager for the OpenVPN3 data channel.
//
// OpenVPN renegotiates data-channel keys either after a time interval
// (reneg-sec) or after a byte threshold (reneg-bytes), whichever comes first.
// The server advertises these limits in the PUSH_REPLY options; the client is
// responsible for initiating renegotiation.
//
// Renegotiation lifecycle (openvpn3-core client/ovpncli.cpp):
//
//  1. Caller detects the limit via NeedsRekey.
//  2. Caller sends P_CONTROL_SOFT_RESET_V1 over the control channel.
//  3. A new TLS session completes and new KeyMaterial is derived.
//  4. Caller calls Rotate with a new *Channel built from the new keys.
//     The old Channel is retained until the peer confirms the new keys.
//
// This package only tracks the *when* of renegotiation; the actual TLS
// renegotiation is handled by the caller (the ctls / reliable layer).
//
// Reference: openvpn3-core ssl/proto.hpp key_state, options.hpp
package datachannel

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/internal/compress"
)

// DefaultRenegSec is the default key renegotiation interval (3600 s = 1 hour).
// Matches openvpn3-core options.hpp default_reneg_sec.
const DefaultRenegSec = 3600

// DefaultRenegBytes is the default byte threshold for key renegotiation.
// 0 means no byte-limit renegotiation (openvpn3-core default).
const DefaultRenegBytes = 0

// Manager wraps a Channel and tracks the byte and time limits that trigger
// key renegotiation.  It is safe for concurrent use.
type Manager struct {
	mu      sync.RWMutex
	current *Channel

	renegSec   int           // renegotiation interval in seconds (0 = disabled)
	renegBytes int64         // byte threshold (0 = disabled)
	startedAt  time.Time     // time the current key epoch started
	bytesSent  atomic.Int64  // bytes encrypted since last rotation
	bytesRecv  atomic.Int64  // bytes decrypted since last rotation

	// compress is the compression mode negotiated with the server.
	// Reference: openvpn3-core ssl/proto.hpp parse_pushed_compression() line ~875.
	compress compress.Mode
}

// ManagerConfig holds the renegotiation parameters parsed from PUSH_REPLY.
type ManagerConfig struct {
	// RenegSec is the key renegotiation interval in seconds.
	// 0 disables time-based renegotiation.
	RenegSec int

	// RenegBytes is the byte threshold for renegotiation.
	// 0 disables byte-based renegotiation.
	RenegBytes int64

	// Compress is the compression mode negotiated with the server.
	// Reference: openvpn3-core ssl/proto.hpp parse_pushed_compression() line ~875:
	// parses "compress lz4[-v2]" and "comp-lzo" from the PUSH_REPLY option list.
	// ModeNone (default) means no compression framing bytes are added/stripped.
	// ModeLZ4 prepends/strips a 0x69 stub byte on every data packet.
	// ModeLZO is partially supported (no byte added on send; receive unwrapped as-is).
	Compress compress.Mode
}

// NewManager creates a Manager wrapping ch with the given renegotiation config.
// If cfg is nil, defaults are used (3600 s, no byte limit).
func NewManager(ch *Channel, cfg *ManagerConfig) *Manager {
	m := &Manager{
		current:   ch,
		startedAt: time.Now(),
	}
	if cfg != nil {
		m.renegSec = cfg.RenegSec
		m.renegBytes = cfg.RenegBytes
		m.compress = cfg.Compress
	} else {
		m.renegSec = DefaultRenegSec
		m.renegBytes = DefaultRenegBytes
	}
	return m
}

// Encrypt encrypts a plaintext IP packet, updates the byte counter, and
// returns the P_DATA_V2 wire packet.
//
// If a compression mode is active, a stub byte is prepended to the plaintext
// before encryption (Wrap).
// Reference: openvpn3-core ssl/proto.hpp KeyContext::do_encrypt() line ~2500:
// calls comp_ctx.compress(buf, true) which for stub modes prepends the stub byte.
func (m *Manager) Encrypt(plaintext []byte) ([]byte, error) {
	m.mu.RLock()
	ch := m.current
	cmode := m.compress
	m.mu.RUnlock()

	inner := compress.Wrap(cmode, plaintext)
	pkt, err := ch.Encrypt(inner)
	if err != nil {
		return nil, err
	}
	m.bytesSent.Add(int64(len(plaintext)))
	return pkt, nil
}

// Decrypt decrypts a P_DATA_V2 wire packet, updates the byte counter, and
// returns the plaintext IP packet.
//
// If a compression mode is active, the compression stub byte is stripped after
// decryption (Unwrap).
// Reference: openvpn3-core ssl/proto.hpp KeyContext::do_decrypt() line ~4238:
// calls comp_ctx.decompress(buf) which for stub modes strips the first byte.
func (m *Manager) Decrypt(pkt []byte) ([]byte, error) {
	m.mu.RLock()
	ch := m.current
	cmode := m.compress
	m.mu.RUnlock()

	inner, err := ch.Decrypt(pkt)
	if err != nil {
		return nil, err
	}
	plain, err := compress.Unwrap(cmode, inner)
	if err != nil {
		return nil, err
	}
	m.bytesRecv.Add(int64(len(plain)))
	return plain, nil
}

// NeedsRekey reports whether the current key epoch has exceeded the configured
// time or byte limits and a renegotiation should be initiated.
func (m *Manager) NeedsRekey() bool {
	if m.renegSec > 0 {
		if time.Since(m.startedAt) >= time.Duration(m.renegSec)*time.Second {
			return true
		}
	}
	if m.renegBytes > 0 {
		total := m.bytesSent.Load() + m.bytesRecv.Load()
		if total >= m.renegBytes {
			return true
		}
	}
	return false
}

// Rotate atomically replaces the active Channel with next and resets the
// renegotiation counters.  The old Channel is discarded; the caller must
// ensure that no in-flight packets for the old epoch are delivered after Rotate.
func (m *Manager) Rotate(next *Channel) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.current = next
	m.startedAt = time.Now()
	m.bytesSent.Store(0)
	m.bytesRecv.Store(0)
}

// Stats returns a snapshot of the current key epoch's byte counters.
func (m *Manager) Stats() (bytesSent, bytesRecv int64) {
	return m.bytesSent.Load(), m.bytesRecv.Load()
}
