package profile_test

import (
	"os"
	"strings"
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

const minimal = `
client
remote vpn.example.com 443
proto tcp-client
cipher AES-256-GCM
auth SHA256
reneg-sec 3600

<ca>
-----BEGIN CERTIFICATE-----
MIIB...
-----END CERTIFICATE-----
</ca>

<cert>
-----BEGIN CERTIFICATE-----
MIIC...
-----END CERTIFICATE-----
</cert>

<key>
-----BEGIN RSA PRIVATE KEY-----
MIIE...
-----END RSA PRIVATE KEY-----
</key>
`

func TestParseMinimal(t *testing.T) {
	p, err := profile.ParseString(minimal)
	if err != nil {
		t.Fatal(err)
	}
	if p.Remote != "vpn.example.com" {
		t.Errorf("Remote = %q", p.Remote)
	}
	if p.Port != 443 {
		t.Errorf("Port = %d, want 443", p.Port)
	}
	if p.Proto != profile.ProtoTCP {
		t.Errorf("Proto = %v, want TCP", p.Proto)
	}
	if p.Cipher != "AES-256-GCM" {
		t.Errorf("Cipher = %q", p.Cipher)
	}
	if p.RenegSec != 3600 {
		t.Errorf("RenegSec = %d, want 3600", p.RenegSec)
	}
	if !strings.Contains(string(p.CA), "BEGIN CERTIFICATE") {
		t.Error("CA PEM not parsed")
	}
	if !strings.Contains(string(p.Cert), "BEGIN CERTIFICATE") {
		t.Error("Cert PEM not parsed")
	}
	if !strings.Contains(string(p.Key), "BEGIN RSA PRIVATE KEY") {
		t.Error("Key PEM not parsed")
	}
}

func TestParseRenegSecZeroDisablesClientRekey(t *testing.T) {
	p, err := profile.ParseString("remote vpn.example.test 443\nreneg-sec 0\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.RenegSec != 0 {
		t.Fatalf("RenegSec = %d, want 0", p.RenegSec)
	}
}

func TestParseWithoutRenegSecUsesOpenVPNDefault(t *testing.T) {
	p, err := profile.ParseString("remote vpn.example.test 443\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.RenegSec != 3600 {
		t.Fatalf("RenegSec = %d, want 3600", p.RenegSec)
	}
}

func TestParseDefaults(t *testing.T) {
	p, err := profile.ParseString("remote vpn.example.com\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.Port != 1194 {
		t.Errorf("default Port = %d, want 1194", p.Port)
	}
	if p.Proto != profile.ProtoUDP {
		t.Errorf("default Proto = %v, want UDP", p.Proto)
	}
	if p.Cipher != "AES-256-GCM" {
		t.Errorf("default Cipher = %q", p.Cipher)
	}
}

func TestParseStaticDNSOptions(t *testing.T) {
	p, err := profile.ParseString(`
remote vpn.example.test
dhcp-option DNS 10.130.0.2
dhcp-option DOMAIN corp.example.test
dhcp-option DOMAIN-ROUTE internal.company.com
dhcp-option DOMAIN-ROUTE us-east-2.eks.amazonaws.com
`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(p.DNSServers), 1; got != want || p.DNSServers[0].String() != "10.130.0.2" {
		t.Errorf("DNS servers = %v, want [10.130.0.2]", p.DNSServers)
	}
	if got, want := p.DNSSearchDomains, []string{"corp.example.test"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("search domains = %v, want %v", got, want)
	}
	if got, want := p.DNSRouteDomains, []string{"internal.company.com", "us-east-2.eks.amazonaws.com"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("route domains = %v, want %v", got, want)
	}
}

func TestParseMissingRemote(t *testing.T) {
	_, err := profile.ParseString("cipher AES-256-GCM\n")
	if err == nil {
		t.Fatal("expected error for missing remote")
	}
}

func TestParseInvalidPort(t *testing.T) {
	_, err := profile.ParseString("remote host 99999\n")
	if err == nil {
		t.Fatal("expected error for invalid port 99999")
	}
}

func TestParseInvalidProto(t *testing.T) {
	_, err := profile.ParseString("remote host 443\nproto kcp\n")
	if err == nil {
		t.Fatal("expected error for unknown proto")
	}
}

func TestParseComments(t *testing.T) {
	cfg := `
# This is a comment
; And this
remote vpn.example.com 1194
`
	p, err := profile.ParseString(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if p.Remote != "vpn.example.com" {
		t.Errorf("Remote = %q", p.Remote)
	}
}

func TestParseRemoteInlinePort(t *testing.T) {
	p, err := profile.ParseString("remote 10.0.0.1 443\nproto udp\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.Port != 443 {
		t.Errorf("Port = %d, want 443", p.Port)
	}
}

func TestParseRenegBytes(t *testing.T) {
	p, err := profile.ParseString("remote h 443\nreneg-bytes 10485760\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.RenegBytes != 10485760 {
		t.Errorf("RenegBytes = %d, want 10485760", p.RenegBytes)
	}
}

func TestParseBecomePrimary(t *testing.T) {
	p, err := profile.ParseString("remote h 443\nbecome-primary 5\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.BecomePrimarySec != 5 {
		t.Errorf("BecomePrimarySec = %d, want 5", p.BecomePrimarySec)
	}
}

func TestParsePath(t *testing.T) {
	// Write a minimal .ovpn to a temp file.
	f, err := os.CreateTemp(t.TempDir(), "test*.ovpn")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("remote vpn.example.com 443\nproto tcp-client\n")
	f.Close()

	p, err := profile.ParsePath(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if p.Remote != "vpn.example.com" {
		t.Errorf("Remote = %q", p.Remote)
	}
}

func TestParsePathMissing(t *testing.T) {
	_, err := profile.ParsePath("/nonexistent/path/test.ovpn")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseTunMTU(t *testing.T) {
	p, err := profile.ParseString("remote h 443\ntun-mtu 1400\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.TunMTU != 1400 {
		t.Errorf("TunMTU = %d, want 1400", p.TunMTU)
	}
}

func TestParseTunMTUDefault(t *testing.T) {
	p, err := profile.ParseString("remote h 443\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.TunMTU != 0 {
		t.Errorf("TunMTU = %d, want 0 (default)", p.TunMTU)
	}
}

func TestParseTunMTUInvalid(t *testing.T) {
	cases := []string{
		"remote h 443\ntun-mtu 0\n",
		"remote h 443\ntun-mtu abc\n",
		"remote h 443\ntun-mtu 65536\n",
		"remote h 443\ntun-mtu -1\n",
	}
	for _, cfg := range cases {
		if _, err := profile.ParseString(cfg); err == nil {
			t.Errorf("expected error for config: %q", cfg)
		}
	}
}

func TestParseMSSFix(t *testing.T) {
	p, err := profile.ParseString("remote h 443\nmssfix 1200\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.MSSFix != 1200 {
		t.Errorf("MSSFix = %d, want 1200", p.MSSFix)
	}
}

func TestParseMSSFixZero(t *testing.T) {
	// mssfix 0 is valid — means "disabled".
	p, err := profile.ParseString("remote h 443\nmssfix 0\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.MSSFix != 0 {
		t.Errorf("MSSFix = %d, want 0", p.MSSFix)
	}
}

func TestParseMSSFixInvalid(t *testing.T) {
	cases := []string{
		"remote h 443\nmssfix abc\n",
		"remote h 443\nmssfix -1\n",
	}
	for _, cfg := range cases {
		if _, err := profile.ParseString(cfg); err == nil {
			t.Errorf("expected error for config: %q", cfg)
		}
	}
}

func TestAuthFederateForcesSAMLFlow(t *testing.T) {
	p, err := profile.ParseString("remote vpn.example.test 443\nauth-federate\n")
	if err != nil {
		t.Fatal(err)
	}
	if !p.ForceSAMLFlow {
		t.Fatal("ForceSAMLFlow = false, want true")
	}
	if got := p.DetectFlow(); got != profile.FlowAWSSSO {
		t.Errorf("DetectFlow() = %v, want FlowAWSSSO", got)
	}
}
