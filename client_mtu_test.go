package vpn

import (
	"net"
	"strings"
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/internal/compress"
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

func TestEffectiveMSSFixMatchesOpenVPN2Default(t *testing.T) {
	profileWithoutMSSFix := &profile.Profile{}

	tests := []struct {
		name        string
		profile     *profile.Profile
		pushedMSS   int
		tunMTU      int
		proto       profile.Proto
		cipher      string
		compression compress.Mode
		remote      net.Addr
		wantMSS     int
		wantMTU     int
	}{
		{
			name:    "default UDP over IPv4 AES-GCM",
			profile: profileWithoutMSSFix,
			tunMTU:  1500,
			proto:   profile.ProtoUDP,
			cipher:  "AES-256-GCM",
			remote:  &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443},
			wantMTU: 1440,
		},
		{
			name:    "default UDP over IPv6 AES-GCM",
			profile: profileWithoutMSSFix,
			tunMTU:  1500,
			proto:   profile.ProtoUDP,
			cipher:  "AES-256-GCM",
			remote:  &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443},
			wantMTU: 1420,
		},
		{
			name:        "LZ4 framing uses one byte of the packet budget",
			profile:     profileWithoutMSSFix,
			tunMTU:      1500,
			proto:       profile.ProtoUDP,
			cipher:      "AES-256-GCM",
			compression: compress.ModeLZ4,
			remote:      &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443},
			wantMTU:     1439,
		},
		{
			name:      "server MSS takes precedence",
			profile:   profileWithoutMSSFix,
			pushedMSS: 1350,
			tunMTU:    1500,
			proto:     profile.ProtoUDP,
			cipher:    "AES-256-GCM",
			wantMSS:   1350,
		},
		{
			name:    "explicit profile MSS takes precedence over default",
			profile: &profile.Profile{MSSFix: 1300, MSSFixSet: true},
			tunMTU:  1500,
			proto:   profile.ProtoUDP,
			cipher:  "AES-256-GCM",
			wantMSS: 1300,
		},
		{
			name:    "explicit mssfix zero disables the default",
			profile: &profile.Profile{MSSFixSet: true},
			tunMTU:  1500,
			proto:   profile.ProtoUDP,
			cipher:  "AES-256-GCM",
		},
		{
			name:    "reduced tunnel MTU becomes the packet budget",
			profile: profileWithoutMSSFix,
			tunMTU:  1400,
			proto:   profile.ProtoUDP,
			cipher:  "AES-256-GCM",
			wantMTU: 1400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMSS, gotMTU := effectiveMSSFix(tt.profile, tt.pushedMSS, tt.tunMTU, tt.proto, tt.cipher, tt.compression, tt.remote)
			if gotMSS != tt.wantMSS || gotMTU != tt.wantMTU {
				t.Fatalf("effectiveMSSFix() = (%d, %d), want (%d, %d)", gotMSS, gotMTU, tt.wantMSS, tt.wantMTU)
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
