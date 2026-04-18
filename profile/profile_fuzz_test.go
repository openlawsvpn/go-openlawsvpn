package profile_test

import (
	"strings"
	"testing"

	"github.com/openlawsvpn/go-openvpn3/profile"
)

// FuzzParseString feeds random strings to ParseString to verify it never
// panics. Profile files are read from disk but may also come from untrusted
// sources (MDM push, CI pipelines, etc.).
func FuzzParseString(f *testing.F) {
	// Seed: minimal valid profile.
	f.Add("remote vpn.example.com 443\nproto tcp-client\n")
	// Seed: AWS Client VPN profile structure.
	f.Add("remote cvpn-endpoint-abc123.amazonaws.com 443\nproto tcp-client\nremote-random-hostname\nverify-x509-name mtlab.ai\n")
	// Seed: with inline CA block.
	f.Add("remote vpn.example.com 1194\nproto udp\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n")
	// Seed: all directives.
	f.Add("remote vpn.example.com 443\nproto tcp-client\ncipher AES-128-GCM\nauth SHA512\nreneg-sec 3600\nreneg-bytes 10000000\ntun-mtu 1400\nmssfix 1350\n")
	// Seed: missing remote (should error, not panic).
	f.Add("proto tcp-client\ncipher AES-256-GCM\n")
	// Seed: empty.
	f.Add("")
	// Seed: only comments.
	f.Add("# comment\n; another comment\n")
	// Seed: invalid port.
	f.Add("remote vpn.example.com 99999\n")
	// Seed: long lines.
	f.Add("remote " + strings.Repeat("a", 1000) + ".example.com 443\nproto tcp-client\n")
	// Seed: unclosed inline block.
	f.Add("remote vpn.example.com 443\nproto tcp-client\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n")
	// Seed: nested-looking tags.
	f.Add("remote vpn.example.com 443\nproto tcp-client\n<ca>\n<cert>\n-----END CERTIFICATE-----\n</ca>\n")

	f.Fuzz(func(t *testing.T, s string) {
		_, _ = profile.ParseString(s)
	})
}
