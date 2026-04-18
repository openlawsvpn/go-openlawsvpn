package framing_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/openlawsvpn/go-openvpn3/internal/framing"
)

// TestFirstByte checks that opcode+keyid encoding round-trips.
func TestFirstByte(t *testing.T) {
	tests := []struct {
		opcode, keyID uint8
		want          byte
	}{
		{framing.P_CONTROL_HARD_RESET_CLIENT_V2, 0, 0x38},
		{framing.P_ACK_V1, 0, 0x28},
		{framing.P_CONTROL_V1, 0, 0x20},
		{framing.P_DATA_V2, 0, 0x48},
	}
	for _, tt := range tests {
		got := framing.FirstByte(tt.opcode, tt.keyID)
		if got != tt.want {
			t.Errorf("FirstByte(%#x, %d) = %#x, want %#x", tt.opcode, tt.keyID, got, tt.want)
		}
		if framing.OpcodeFromByte(got) != tt.opcode {
			t.Errorf("OpcodeFromByte(%#x) = %d, want %d", got, framing.OpcodeFromByte(got), tt.opcode)
		}
		if framing.KeyIDFromByte(got) != tt.keyID {
			t.Errorf("KeyIDFromByte(%#x) = %d, want %d", got, framing.KeyIDFromByte(got), tt.keyID)
		}
	}
}

// TestTCPRoundTrip writes a packet and reads it back.
func TestTCPRoundTrip(t *testing.T) {
	payload := []byte("hello openvpn3")
	var buf bytes.Buffer
	if err := framing.WriteTCP(&buf, payload); err != nil {
		t.Fatal(err)
	}
	// Verify wire: 2-byte big-endian length then payload
	wire := buf.Bytes()
	gotLen := binary.BigEndian.Uint16(wire[:2])
	if int(gotLen) != len(payload) {
		t.Fatalf("wire length field = %d, want %d", gotLen, len(payload))
	}
	got, err := framing.ReadTCP(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("ReadTCP returned %q, want %q", got, payload)
	}
}

// TestWriteTCPErrors checks boundary conditions.
func TestWriteTCPErrors(t *testing.T) {
	var buf bytes.Buffer
	if err := framing.WriteTCP(&buf, nil); err == nil {
		t.Error("expected error writing nil payload")
	}
	if err := framing.WriteTCP(&buf, make([]byte, 65536)); err == nil {
		t.Error("expected error writing >MaxPacketSize payload")
	}
}

// TestParseControl parses a minimal HARD_RESET packet built by hand.
// Layout: [opcode+keyid][session_id 8B][ack_len=0][packet_id 4B]
func TestParseControl(t *testing.T) {
	var raw []byte
	raw = append(raw, framing.FirstByte(framing.P_CONTROL_HARD_RESET_CLIENT_V2, 0))
	raw = append(raw, make([]byte, 8)...) // session_id
	raw = append(raw, 0)                  // ack_array_len = 0
	pktID := []byte{0, 0, 0, 1}
	raw = append(raw, pktID...)
	raw = append(raw, []byte("payload")...)

	p, err := framing.ParseControl(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Opcode != framing.P_CONTROL_HARD_RESET_CLIENT_V2 {
		t.Errorf("opcode = %d, want %d", p.Opcode, framing.P_CONTROL_HARD_RESET_CLIENT_V2)
	}
	if p.PacketID != 1 {
		t.Errorf("packet_id = %d, want 1", p.PacketID)
	}
	if string(p.Payload) != "payload" {
		t.Errorf("payload = %q, want %q", p.Payload, "payload")
	}
}

// TestParseControlAck parses a P_ACK_V1 packet with one acked ID.
func TestParseControlAck(t *testing.T) {
	var raw []byte
	raw = append(raw, framing.FirstByte(framing.P_ACK_V1, 0))
	raw = append(raw, make([]byte, 8)...) // session_id
	raw = append(raw, 1)                  // ack_array_len = 1
	raw = append(raw, 0, 0, 0, 7)        // acked packet_id = 7
	raw = append(raw, make([]byte, 8)...) // remote_session_id

	p, err := framing.ParseControl(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Opcode != framing.P_ACK_V1 {
		t.Errorf("opcode = %d, want %d", p.Opcode, framing.P_ACK_V1)
	}
	if len(p.AckIDs) != 1 || p.AckIDs[0] != 7 {
		t.Errorf("ack_ids = %v, want [7]", p.AckIDs)
	}
}
