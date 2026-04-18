// Package compress implements the OpenVPN3 data-channel compression framing
// stubs for the 'compress lz4' and 'comp-lzo' options pushed by the server.
//
// Background:
//
// Some OpenVPN servers push a 'compress lz4' or 'comp-lzo' option inside
// PUSH_REPLY. When active, each data-channel payload is prefixed with a
// one-byte compression opcode:
//
//	0x69 — data is NOT compressed (lz4 stub byte, used as a pass-through)
//	0xfa — data IS lz4-compressed (not implemented; never sent by this client)
//
// go-openvpn3 does not link liblz4 (CGO_ENABLED=0), so it only supports the
// pass-through path (no actual compression). Sending 0x69 on every packet is
// safe and interoperable with openvpn3-core: the server accepts it and does
// not compress replies either, because the client never set the LZ4 capability
// flag in the handshake options.
//
// Reference: openvpn3-core compress/compress.hpp, compress/lz4.hpp
package compress

import (
	"fmt"
	"log"
)

// Mode describes the compression mode negotiated with the server.
type Mode int

const (
	// ModeNone means no compression framing (most servers, including AWS Client VPN).
	ModeNone Mode = iota
	// ModeLZ4 means 'compress lz4' was pushed; stub byte 0x69 is prepended on send.
	ModeLZ4
	// ModeLZO means 'comp-lzo' was pushed; framing is not implemented.
	// A warning is logged and packets pass through without modification.
	ModeLZO
)

// stubByte is prepended to every outgoing payload when ModeLZ4 is active.
// 0x69 signals "not compressed" in the openvpn3-core lz4 framing.
// Reference: openvpn3-core compress/lz4.hpp COMPRESS_STUB_V2
const stubByte = byte(0x69)

// ParseMode inspects the options from a PUSH_REPLY string and returns the
// appropriate compression Mode.  It scans for "compress lz4" or "comp-lzo"
// among the comma-separated option tokens.
//
// If 'comp-lzo' is detected a warning is logged; the tunnel will continue but
// may not carry traffic correctly if the server actually compresses payloads.
func ParseMode(pushReply string) Mode {
	// Split by comma and scan each token.
	for i := 0; i < len(pushReply); {
		j := i
		for j < len(pushReply) && pushReply[j] != ',' {
			j++
		}
		token := trim(pushReply[i:j])
		i = j + 1

		switch token {
		case "compress lz4", "compress lz4-v2":
			return ModeLZ4
		case "comp-lzo", "comp-lzo no":
			log.Println("compress: comp-lzo not supported, tunnel may fail if server compresses payloads")
			return ModeLZO
		}
	}
	return ModeNone
}

// Wrap prepends the compression stub byte to payload when mode requires it.
// For ModeNone and ModeLZO the payload is returned unchanged.
// For ModeLZ4 a new slice is returned with 0x69 prepended.
func Wrap(mode Mode, payload []byte) []byte {
	if mode != ModeLZ4 {
		return payload
	}
	out := make([]byte, 1+len(payload))
	out[0] = stubByte
	copy(out[1:], payload)
	return out
}

// Unwrap strips the compression stub byte from payload when mode requires it.
// For ModeNone the payload is returned unchanged.
// For ModeLZ4 it expects 0x69 as the first byte (uncompressed path);
// if the first byte indicates actual lz4 compression (0xfa) an error is returned.
// For ModeLZO the payload is returned unchanged with no byte stripped.
func Unwrap(mode Mode, payload []byte) ([]byte, error) {
	if mode == ModeNone || mode == ModeLZO {
		return payload, nil
	}
	// ModeLZ4
	if len(payload) == 0 {
		return nil, fmt.Errorf("compress: lz4: empty payload, missing stub byte")
	}
	switch payload[0] {
	case stubByte: // 0x69 — not compressed, strip stub byte
		return payload[1:], nil
	case 0xfa: // lz4-compressed — not supported
		return nil, fmt.Errorf("compress: lz4: server sent compressed payload (0xfa); decompression not supported")
	default:
		return nil, fmt.Errorf("compress: lz4: unexpected stub byte 0x%02x", payload[0])
	}
}

// trim removes leading and trailing ASCII spaces and tabs from s.
func trim(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
