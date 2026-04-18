package framing

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// MaxPacketSize is the maximum allowed size of a single OpenVPN packet.
// openvpn3-core uses 65535 as the ceiling for the 2-byte length field.
const MaxPacketSize = 65535

// ReadTCP reads one OpenVPN packet from a TCP stream.
// The wire format is: [length uint16 big-endian][payload bytes]
// where length == len(payload).
//
// Reference: openvpn3-core transport/tcplink.hpp TCPTransport::read_handler
func ReadTCP(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("framing: read length: %w", err)
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n == 0 {
		return nil, fmt.Errorf("framing: zero-length packet")
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("framing: read payload (%d bytes): %w", n, err)
	}
	return payload, nil
}

// WriteTCP writes one OpenVPN packet to a TCP stream with the 2-byte
// big-endian length prefix.
func WriteTCP(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("framing: cannot write zero-length packet")
	}
	if len(payload) > MaxPacketSize {
		return fmt.Errorf("framing: packet too large: %d > %d", len(payload), MaxPacketSize)
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("framing: write length: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("framing: write payload: %w", err)
	}
	return nil
}

// ReadUDP reads one OpenVPN packet from a UDP connection.
// UDP packets are raw (no 2-byte length prefix); each datagram is one packet.
//
// Reference: openvpn3-core transport/udplink.hpp
func ReadUDP(conn net.Conn) ([]byte, error) {
	buf := make([]byte, MaxPacketSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("framing: udp read: %w", err)
	}
	return buf[:n], nil
}

// WriteUDP writes one OpenVPN packet to a UDP connection.
// UDP packets are sent as raw datagrams (no 2-byte length prefix).
func WriteUDP(conn net.Conn, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("framing: cannot write zero-length packet")
	}
	_, err := conn.Write(payload)
	if err != nil {
		return fmt.Errorf("framing: udp write: %w", err)
	}
	return nil
}

// Packet is a parsed OpenVPN control-channel packet header.
// Data-channel packets (P_DATA_V2) use a different layout and are
// handled by the datachannel package.
type Packet struct {
	Opcode   uint8
	KeyID    uint8
	PeerID   uint32 // 3 bytes, 0 for non-P_DATA_V2
	PacketID uint32 // sequence number for reliable transport
	AckIDs   []uint32
	Payload  []byte // TLS or control-message bytes
}

// ParseControl parses a P_CONTROL_V1 / P_CONTROL_HARD_RESET / P_ACK_V1
// packet from raw bytes.
//
// Wire layout (openvpn3-core ssl/proto.hpp):
//
//	[opcode+keyid 1B][session_id 8B][ack_array_len 1B][ack_ids N*4B]
//	[remote_session_id 8B if ack_array_len>0][packet_id 4B if not P_ACK_V1]
//	[payload...]
func ParseControl(raw []byte) (*Packet, error) {
	if len(raw) < 10 {
		return nil, fmt.Errorf("framing: packet too short: %d bytes", len(raw))
	}
	p := &Packet{
		Opcode: OpcodeFromByte(raw[0]),
		KeyID:  KeyIDFromByte(raw[0]),
	}

	offset := 1
	// session_id (8 bytes) — we skip it for now; it belongs to session state
	offset += 8

	ackLen := int(raw[offset])
	offset++

	if ackLen > 0 {
		if len(raw) < offset+ackLen*4+8 {
			return nil, fmt.Errorf("framing: truncated ack array")
		}
		p.AckIDs = make([]uint32, ackLen)
		for i := range p.AckIDs {
			p.AckIDs[i] = binary.BigEndian.Uint32(raw[offset:])
			offset += 4
		}
		// remote_session_id (8 bytes) — skip
		offset += 8
	}

	// P_ACK_V1 has no packet_id or payload
	if p.Opcode == P_ACK_V1 {
		return p, nil
	}

	if len(raw) < offset+4 {
		return nil, fmt.Errorf("framing: truncated packet_id")
	}
	p.PacketID = binary.BigEndian.Uint32(raw[offset:])
	offset += 4

	p.Payload = raw[offset:]
	return p, nil
}
