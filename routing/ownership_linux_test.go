//go:build linux

package routing

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseRouteIdentityFromNetlink(t *testing.T) {
	dst := net.ParseIP("10.20.0.0").To4()
	gw := net.ParseIP("10.8.0.1").To4()
	rt := unix.RtMsg{Family: unix.AF_INET, Dst_len: 16, Table: unix.RT_TABLE_MAIN}
	payload := marshalRtMsg(rt)
	payload = append(payload, nlAttr(unix.RTA_DST, dst)...)
	payload = append(payload, nlAttr(unix.RTA_GATEWAY, gw)...)
	var index [4]byte
	binary.LittleEndian.PutUint32(index[:], 7)
	payload = append(payload, nlAttr(unix.RTA_OIF, index[:])...)
	hdr := unix.NlMsghdr{Len: uint32(nlmsgHdrSize + len(payload)), Type: unix.RTM_NEWROUTE}
	wire := append(marshalNlHdr(hdr), payload...)

	got, err := parseRouteIdentity(wire, dst, 16)
	if err != nil {
		t.Fatal(err)
	}
	want := RouteIdentity{Destination: "10.20.0.0/16", Gateway: "10.8.0.1", Interface: 7}
	if got == nil || *got != want {
		t.Fatalf("identity = %#v, want %#v", got, want)
	}
}

func TestParseRouteIdentityRejectsBroaderFallback(t *testing.T) {
	dst := net.ParseIP("10.20.0.0").To4()
	rt := unix.RtMsg{Family: unix.AF_INET, Dst_len: 0, Table: unix.RT_TABLE_MAIN}
	payload := marshalRtMsg(rt)
	hdr := unix.NlMsghdr{Len: uint32(nlmsgHdrSize + len(payload)), Type: unix.RTM_NEWROUTE}
	got, err := parseRouteIdentity(append(marshalNlHdr(hdr), payload...), dst, 16)
	if err != nil || got != nil {
		t.Fatalf("identity = %#v, err=%v", got, err)
	}
}

func TestFindRouteIdentitySkipsResolvedRouteAndFindsExactPrefix(t *testing.T) {
	dst := net.ParseIP("10.130.0.0").To4()
	gw := net.ParseIP("172.16.76.1").To4()

	message := func(prefix uint8) []byte {
		rt := unix.RtMsg{Family: unix.AF_INET, Dst_len: prefix, Table: unix.RT_TABLE_MAIN}
		payload := marshalRtMsg(rt)
		payload = append(payload, nlAttr(unix.RTA_DST, dst)...)
		payload = append(payload, nlAttr(unix.RTA_GATEWAY, gw)...)
		var index [4]byte
		binary.LittleEndian.PutUint32(index[:], 5)
		payload = append(payload, nlAttr(unix.RTA_OIF, index[:])...)
		hdr := unix.NlMsghdr{Len: uint32(nlmsgHdrSize + len(payload)), Type: unix.RTM_NEWROUTE}
		return append(marshalNlHdr(hdr), payload...)
	}

	// A route-resolution query may produce the /32 first. Table inspection must
	// skip it and retain the actual configured /16 route that follows.
	wire := append(message(32), message(16)...)
	done := marshalNlHdr(unix.NlMsghdr{Len: nlmsgHdrSize, Type: unix.NLMSG_DONE})
	wire = append(wire, done...)

	got, completed, err := findRouteIdentity(wire, dst, 16)
	if err != nil {
		t.Fatal(err)
	}
	if completed {
		t.Fatal("reported dump completion before exact route")
	}
	want := RouteIdentity{Destination: "10.130.0.0/16", Gateway: "172.16.76.1", Interface: 5}
	if got == nil || *got != want {
		t.Fatalf("identity = %#v, want %#v", got, want)
	}
}
