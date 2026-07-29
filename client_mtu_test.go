package vpn

import (
	"strings"
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

func TestBuildTunnelOptionsUsesConfiguredMTU(t *testing.T) {
	tests := []struct {
		name  string
		proto profile.Proto
		mtu   int
		want  string
	}{
		{
			name:  "udp",
			proto: profile.ProtoUDP,
			mtu:   1400,
			want:  "link-mtu 1421,tun-mtu 1400,proto UDPv4",
		},
		{
			name:  "tcp",
			proto: profile.ProtoTCP,
			mtu:   1400,
			want:  "link-mtu 1443,tun-mtu 1400,proto TCPv4_CLIENT",
		},
		{
			name:  "default",
			proto: profile.ProtoUDP,
			mtu:   0,
			want:  "link-mtu 1521,tun-mtu 1500,proto UDPv4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildTunnelOptions(tt.proto, tt.mtu); !strings.Contains(got, tt.want) {
				t.Errorf("buildTunnelOptions(%v, %d) = %q, want substring %q", tt.proto, tt.mtu, got, tt.want)
			}
		})
	}
}

func TestParseTunMTURespectsProfileMaximum(t *testing.T) {
	tests := []struct {
		name       string
		push       string
		profileMTU int
		want       int
	}{
		{name: "profile without push", profileMTU: 1400, want: 1400},
		{name: "profile caps larger push", push: "PUSH_REPLY,tun-mtu 1500", profileMTU: 1400, want: 1400},
		{name: "server reduces profile", push: "PUSH_REPLY,tun-mtu 1300", profileMTU: 1400, want: 1300},
		{name: "push without profile", push: "PUSH_REPLY,tun-mtu 1400", want: 1400},
		{name: "default", want: 1500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseTunMTU(tt.push, tt.profileMTU); got != tt.want {
				t.Errorf("parseTunMTU(%q, %d) = %d, want %d", tt.push, tt.profileMTU, got, tt.want)
			}
		})
	}
}
