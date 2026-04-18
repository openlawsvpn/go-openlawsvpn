// Package framing implements the OpenVPN3 wire format: packet opcodes,
// the 2-byte length-prefixed TCP framing, and raw UDP framing.
//
// References:
//   - openvpn3-core ssl/proto.hpp (opcode definitions)
//   - openvpn3-core transport/tcplink.hpp (TCP framing)
//   - openvpn3-core transport/udplink.hpp (UDP framing)
//   - OpenVPN protocol extensions (P_DATA_V2, AEAD, peer-id, NCP):
//     https://github.com/OpenVPN/openvpn3/blob/master/doc/openvpn-protocol-extensions.txt
package framing

// Opcode constants for the OpenVPN3 control and data channel.
// The top 5 bits of the first byte of every packet carry the opcode;
// the bottom 3 bits carry the key_id.
//
// Source: openvpn3-core ssl/proto.hpp lines ~100-130
const (
	// P_CONTROL_HARD_RESET_CLIENT_V2 starts a new client session.
	// Sent as the very first packet from client to server.
	P_CONTROL_HARD_RESET_CLIENT_V2 = 0x07

	// P_CONTROL_HARD_RESET_SERVER_V2 is the server's reply to HARD_RESET.
	P_CONTROL_HARD_RESET_SERVER_V2 = 0x08

	// P_CONTROL_SOFT_RESET_V1 initiates key renegotiation without
	// tearing down the data channel.
	P_CONTROL_SOFT_RESET_V1 = 0x03

	// P_CONTROL_V1 carries TLS handshake and control-channel payload.
	P_CONTROL_V1 = 0x04

	// P_ACK_V1 acknowledges received control-channel packets.
	P_ACK_V1 = 0x05

	// P_DATA_V1 is a legacy data channel packet (OpenVPN 2.x).
	P_DATA_V1 = 0x06

	// P_DATA_V2 is the OpenVPN3 data channel packet with peer_id header.
	P_DATA_V2 = 0x09
)

// opcodeShift is the number of bits key_id occupies in the first byte.
const opcodeShift = 3

// keyIDMask masks the 3-bit key_id from the first byte.
const keyIDMask = 0x07

// OpcodeFromByte extracts the opcode from the first byte of a packet.
func OpcodeFromByte(b byte) uint8 {
	return b >> opcodeShift
}

// KeyIDFromByte extracts the key_id (0-7) from the first byte of a packet.
func KeyIDFromByte(b byte) uint8 {
	return b & keyIDMask
}

// FirstByte constructs the first byte of a packet from opcode and key_id.
func FirstByte(opcode, keyID uint8) byte {
	return (opcode << opcodeShift) | (keyID & keyIDMask)
}
