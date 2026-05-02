package mssfix_test

import (
	"encoding/binary"
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/internal/mssfix"
)

// buildSYN4 constructs a minimal IPv4 TCP SYN packet with an MSS option.
func buildSYN4(mssVal uint16) []byte {
	// IPv4 header (20) + TCP header (24: 20 fixed + 4 MSS option)
	pkt := make([]byte, 44)
	pkt[0] = 0x45 // version=4, IHL=5 (20 bytes)
	binary.BigEndian.PutUint16(pkt[2:4], 44)
	pkt[9] = 6 // TCP
	// src 10.0.0.1, dst 10.0.0.2
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	// TCP: data offset=6 (24 bytes), SYN flag
	tcp := pkt[20:]
	tcp[12] = 0x60 // data offset = 6 (6*4=24)
	tcp[13] = 0x02 // SYN
	// MSS option: kind=2, length=4, value
	tcp[20] = 2
	tcp[21] = 4
	binary.BigEndian.PutUint16(tcp[22:24], mssVal)
	// Compute checksums
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))
	writeTCPChecksum4(pkt, 20)
	return pkt
}

func ipChecksum(hdr []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		s += uint32(binary.BigEndian.Uint16(hdr[i:]))
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}

func writeTCPChecksum4(pkt []byte, ihl int) {
	tcp := pkt[ihl:]
	tcpLen := len(pkt) - ihl
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], pkt[12:16])
	copy(pseudo[4:8], pkt[16:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(tcpLen))
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[16:18], vecChecksum(pseudo, tcp))
}

func vecChecksum(a, b []byte) uint16 {
	var s uint32
	add := func(buf []byte) {
		for i := 0; i+1 < len(buf); i += 2 {
			s += uint32(binary.BigEndian.Uint16(buf[i:]))
		}
		if len(buf)%2 != 0 {
			s += uint32(buf[len(buf)-1]) << 8
		}
	}
	add(a)
	add(b)
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}

func mssOf(pkt []byte) uint16 {
	ihl := int(pkt[0]&0x0f) * 4
	tcp := pkt[ihl:]
	doff := int(tcp[12]>>4) * 4
	opts := tcp[20:doff]
	for i := 0; i < len(opts); {
		if opts[i] == 0 {
			break
		}
		if opts[i] == 1 {
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		l := int(opts[i+1])
		if opts[i] == 2 && l == 4 {
			return binary.BigEndian.Uint16(opts[i+2:])
		}
		i += l
	}
	return 0
}

func TestClamp_ClampsOversizedMSS(t *testing.T) {
	pkt := buildSYN4(1460)
	mssfix.Clamp(pkt, 1350)
	if got := mssOf(pkt); got != 1350 {
		t.Fatalf("MSS after clamp: got %d, want 1350", got)
	}
}

func TestClamp_DoesNotIncreaseSmallMSS(t *testing.T) {
	pkt := buildSYN4(1200)
	mssfix.Clamp(pkt, 1350)
	if got := mssOf(pkt); got != 1200 {
		t.Fatalf("MSS should not increase: got %d, want 1200", got)
	}
}

func TestClamp_NonSYNUntouched(t *testing.T) {
	pkt := buildSYN4(1460)
	pkt[20+13] = 0x10 // ACK, not SYN
	before := make([]byte, len(pkt))
	copy(before, pkt)
	mssfix.Clamp(pkt, 1000)
	for i, b := range pkt {
		if b != before[i] {
			t.Fatal("non-SYN packet was modified")
		}
	}
}

func TestClamp_ZeroMaxMSSIsNoop(t *testing.T) {
	pkt := buildSYN4(1460)
	before := make([]byte, len(pkt))
	copy(before, pkt)
	mssfix.Clamp(pkt, 0)
	for i, b := range pkt {
		if b != before[i] {
			t.Fatal("zero maxMSS should be a no-op")
		}
	}
}

func TestClamp_ChecksumValid(t *testing.T) {
	pkt := buildSYN4(1460)
	mssfix.Clamp(pkt, 1300)
	// IP checksum
	if ipChecksum(pkt[:20]) != 0 {
		t.Fatal("IP checksum invalid after clamp")
	}
	// TCP checksum (verify by recomputing and comparing)
	tcp := pkt[20:]
	savedCsum := binary.BigEndian.Uint16(tcp[16:18])
	writeTCPChecksum4(pkt, 20)
	if binary.BigEndian.Uint16(tcp[16:18]) != savedCsum {
		t.Fatal("TCP checksum invalid after clamp")
	}
}

func TestClamp_ShortPacketNoPanic(t *testing.T) {
	for _, l := range []int{0, 1, 10, 19} {
		mssfix.Clamp(make([]byte, l), 1300)
	}
}
