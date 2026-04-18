// Unit tests for the routing package.
//
// ParsePushReply tests exercise the pure-Go parser and require no special
// privileges. The netlink tests are skipped unless running as root.
package routing

import (
	"net"
	"testing"
)

// ---- ParsePushReply ----------------------------------------------------------

func TestParsePushReply_Basic(t *testing.T) {
	msg := "PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,route 10.8.0.0 255.255.0.0," +
		"dhcp-option DNS 10.8.0.1,cipher AES-256-GCM\x00"

	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}

	if opts.Ifconfig == nil {
		t.Fatal("expected Ifconfig to be set")
	}
	if !opts.Ifconfig.Local.Equal(net.ParseIP("10.8.0.6")) {
		t.Errorf("local IP: got %s, want 10.8.0.6", opts.Ifconfig.Local)
	}
	// Net30 topology: second ifconfig arg is the P2P peer, stored as Gateway.
	if !opts.Ifconfig.Gateway.Equal(net.ParseIP("10.8.0.5")) {
		t.Errorf("gateway IP: got %s, want 10.8.0.5", opts.Ifconfig.Gateway)
	}

	if len(opts.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(opts.Routes))
	}
	r := opts.Routes[0]
	if !r.Network.Equal(net.ParseIP("10.8.0.0")) {
		t.Errorf("route network: got %s, want 10.8.0.0", r.Network)
	}
	wantMask := net.IPMask(net.ParseIP("255.255.0.0").To4())
	if r.Mask.String() != wantMask.String() {
		t.Errorf("route mask: got %s, want %s", r.Mask, wantMask)
	}
	if opts.RedirectGateway {
		t.Error("RedirectGateway should be false")
	}
}

func TestParsePushReply_RedirectGateway(t *testing.T) {
	msg := "PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5,redirect-gateway def1 bypass-dhcp"

	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}
	if !opts.RedirectGateway {
		t.Error("expected RedirectGateway=true")
	}
}

func TestParsePushReply_RouteWithGateway(t *testing.T) {
	msg := "PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5,route 192.168.0.0 255.255.0.0 10.0.0.5"

	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}
	if len(opts.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(opts.Routes))
	}
	if !opts.Routes[0].Gateway.Equal(net.ParseIP("10.0.0.5")) {
		t.Errorf("gateway: got %s, want 10.0.0.5", opts.Routes[0].Gateway)
	}
}

func TestParsePushReply_Empty(t *testing.T) {
	opts, err := ParsePushReply("PUSH_REPLY")
	if err != nil {
		t.Fatalf("ParsePushReply empty: %v", err)
	}
	if opts.Ifconfig != nil {
		t.Error("expected nil Ifconfig")
	}
	if len(opts.Routes) != 0 {
		t.Errorf("expected 0 routes, got %d", len(opts.Routes))
	}
}

func TestParsePushReply_BadIfconfig(t *testing.T) {
	_, err := ParsePushReply("PUSH_REPLY,ifconfig 10.0.0.1")
	if err == nil {
		t.Error("expected error for truncated ifconfig")
	}
}

func TestParsePushReply_BadIP(t *testing.T) {
	_, err := ParsePushReply("PUSH_REPLY,ifconfig not-an-ip 10.0.0.1")
	if err == nil {
		t.Error("expected error for invalid IP in ifconfig")
	}
}

func TestParsePushReply_SubnetTopology(t *testing.T) {
	// AWS Client VPN typical PUSH_REPLY with subnet topology.
	msg := "PUSH_REPLY,topology subnet,ifconfig 172.16.77.4 255.255.255.224," +
		"route-gateway 172.16.77.1,route 10.130.0.0 255.255.0.0," +
		"dhcp-option DNS 10.130.0.2,peer-id 0,cipher AES-256-GCM\x00"

	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}
	if opts.Topology != TopologySubnet {
		t.Errorf("topology: got %v, want TopologySubnet", opts.Topology)
	}
	if opts.Ifconfig == nil {
		t.Fatal("expected Ifconfig to be set")
	}
	if !opts.Ifconfig.Local.Equal(net.ParseIP("172.16.77.4")) {
		t.Errorf("local IP: got %s, want 172.16.77.4", opts.Ifconfig.Local)
	}
	wantMask := net.IPMask(net.ParseIP("255.255.255.224").To4())
	if opts.Ifconfig.Mask.String() != wantMask.String() {
		t.Errorf("mask: got %s, want %s", opts.Ifconfig.Mask, wantMask)
	}
	if !opts.Ifconfig.Gateway.Equal(net.ParseIP("172.16.77.1")) {
		t.Errorf("gateway: got %s, want 172.16.77.1", opts.Ifconfig.Gateway)
	}
	if len(opts.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(opts.Routes))
	}
	if !opts.Routes[0].Network.Equal(net.ParseIP("10.130.0.0")) {
		t.Errorf("route: got %s, want 10.130.0.0", opts.Routes[0].Network)
	}
}

func TestParsePushReply_UnknownDirectivesIgnored(t *testing.T) {
	msg := "PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5,comp-lzo no,tun-mtu 1500"
	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply with unknown directives: %v", err)
	}
	if opts.Ifconfig == nil {
		t.Error("expected Ifconfig to be set")
	}
}

func TestParsePushReply_Mssfix(t *testing.T) {
	msg := "PUSH_REPLY,mssfix 1400"
	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}
	if opts.Mssfix != 1400 {
		t.Errorf("Mssfix: got %d, want 1400", opts.Mssfix)
	}
}

func TestParsePushReply_MssfixOutOfRange(t *testing.T) {
	// Values outside [68, 65535] must be silently ignored.
	for _, tc := range []string{"mssfix 10", "mssfix 70000", "mssfix 0"} {
		msg := "PUSH_REPLY," + tc
		opts, err := ParsePushReply(msg)
		if err != nil {
			t.Fatalf("ParsePushReply(%q): %v", tc, err)
		}
		if opts.Mssfix != 0 {
			t.Errorf("Mssfix for %q: got %d, want 0", tc, opts.Mssfix)
		}
	}
}

func TestParsePushReply_InactiveTimeout(t *testing.T) {
	msg := "PUSH_REPLY,inactive 300"
	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}
	if opts.InactiveTimeout != 300 {
		t.Errorf("InactiveTimeout: got %d, want 300", opts.InactiveTimeout)
	}
	if opts.InactiveBytes != 0 {
		t.Errorf("InactiveBytes: got %d, want 0", opts.InactiveBytes)
	}
}

func TestParsePushReply_InactiveTimeoutAndBytes(t *testing.T) {
	msg := "PUSH_REPLY,inactive 300 100"
	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}
	if opts.InactiveTimeout != 300 {
		t.Errorf("InactiveTimeout: got %d, want 300", opts.InactiveTimeout)
	}
	if opts.InactiveBytes != 100 {
		t.Errorf("InactiveBytes: got %d, want 100", opts.InactiveBytes)
	}
}

func TestParsePushReply_Keepalive(t *testing.T) {
	// AWS Client VPN typical push with ping/ping-restart.
	msg := "PUSH_REPLY,topology subnet,ifconfig 172.16.77.135 255.255.255.224," +
		"route-gateway 172.16.77.129,route 10.130.0.0 255.255.0.0," +
		"dhcp-option DNS 10.130.0.2,ping 1,ping-restart 20,peer-id 0,cipher AES-256-GCM\x00"

	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}
	if opts.PingInterval != 1 {
		t.Errorf("PingInterval: got %d, want 1", opts.PingInterval)
	}
	if opts.PingRestart != 20 {
		t.Errorf("PingRestart: got %d, want 20", opts.PingRestart)
	}
}

func TestParsePushReply_ProtocolFlagsTLSEKM(t *testing.T) {
	msg := "PUSH_REPLY,protocol-flags cc-exit tls-ekm dyn-tls-crypt,cipher AES-256-GCM"
	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}
	if opts.KeyDerivation != KeyDerivationTLSEKM {
		t.Errorf("KeyDerivation: got %v, want TLSEKm", opts.KeyDerivation)
	}
}

func TestParsePushReply_KeyDerivationDirective(t *testing.T) {
	msg := "PUSH_REPLY,key-derivation tls-ekm,cipher AES-256-GCM"
	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}
	if opts.KeyDerivation != KeyDerivationTLSEKM {
		t.Errorf("KeyDerivation: got %v, want TLSEKM", opts.KeyDerivation)
	}
}

func TestParsePushReply_DefaultKeyDerivationPRF(t *testing.T) {
	// Stock OpenVPN 2.x does not push protocol-flags; default must be PRF.
	msg := "PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,cipher AES-256-CBC"
	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}
	if opts.KeyDerivation != KeyDerivationOpenVPNPRF {
		t.Errorf("KeyDerivation: got %v, want OpenVPNPRF", opts.KeyDerivation)
	}
}
