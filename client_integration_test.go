//go:build integration

// Package vpn integration tests — require a running mock server.
//
// Run with:
//
//	go test -v -tags=integration ./...
//
// The tests build the mock server binary, start it on a random port,
// connect the Go client, and assert on the server's structured event log.
package vpn_test

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vpn "github.com/openlawsvpn/go-openlawsvpn"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// buildMockServer compiles the mock server binary into a temp dir and returns
// the binary path.
func buildMockServer(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "mock-server")
	cmd := exec.Command("go", "build", "-o", bin, "./mock/mockserver")
	cmd.Dir = findModuleRoot(t)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build mock server: %v", err)
	}
	return bin
}

// findModuleRoot walks up from the test binary's working directory to find
// the go.mod file.
func findModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// mockProfile returns an in-memory profile pointing to a local mock server.
func mockProfile(t *testing.T, addr string) *profile.Profile {
	t.Helper()
	host, port, _ := splitAddr(addr)
	p := &profile.Profile{
		Remote: host,
		Port:   port,
		Proto:  profile.ProtoTCP,
	}
	return p
}

func splitAddr(addr string) (host string, port int, err error) {
	var portStr string
	host, portStr, err = splitHostPort(addr)
	if err != nil {
		return
	}
	_, err = parsePort(portStr, &port)
	return
}

func splitHostPort(addr string) (string, string, error) {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return addr, "4433", nil
	}
	return addr[:idx], addr[idx+1:], nil
}

func parsePort(s string, out *int) (int, error) {
	var v int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, nil
		}
		v = v*10 + int(c-'0')
	}
	*out = v
	return v, nil
}

// TestConnectNoCRV1 verifies that in normal mode the client receives PUSH_REPLY
// and the server logs an auth_packet_recv event with username="N/A".
func TestConnectNoCRV1(t *testing.T) {
	bin := buildMockServer(t)
	srv, err := testenv.Start(testenv.Config{
		Binary:   bin,
		CRV1Mode: false,
	})
	if err != nil {
		t.Fatalf("start mock server: %v", err)
	}
	defer srv.Stop()

	time.Sleep(200 * time.Millisecond)

	p := mockProfile(t, srv.TCPAddr)
	client := vpn.New(p)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		if !strings.Contains(err.Error(), "operation not permitted") &&
			!strings.Contains(err.Error(), "CAP_NET_ADMIN") {
			t.Fatalf("Connect: %v", err)
		}
		t.Logf("Connect: TUN not available (%v) — checking auth events only", err)
	}
	client.Disconnect() //nolint:errcheck
	client.WaitForDisconnect() //nolint:errcheck

	time.Sleep(300 * time.Millisecond)

	authEvents := srv.AuthEvents()
	if len(authEvents) == 0 {
		t.Fatal("no auth_packet_recv events logged by mock server")
	}
	ae := authEvents[0]
	t.Logf("auth_packet_recv: username=%q password_len=%d options=%q peer_info=%q",
		ae.Username, ae.PasswordLen, ae.Options, ae.PeerInfo)

	if ae.Username != "N/A" {
		t.Errorf("username: got %q, want %q", ae.Username, "N/A")
	}
	if ae.Password != "ACS::35001" {
		t.Errorf("password: got %q, want %q", ae.Password, "ACS::35001")
	}
	if !strings.HasPrefix(ae.Options, "V4,") {
		t.Errorf("options should start with 'V4,', got %q", ae.Options)
	}
	if ae.TotalBytes < 200 {
		t.Errorf("auth packet too small: %d bytes", ae.TotalBytes)
	}
}

// TestConnectCRV1Flow verifies the full two-phase SAML/CRV1 flow against the
// local mock server. It drives the two phases via Phase1ForTest +
// ConnectPhase2Reuse to exercise the same code path as Connect does for AWS SSO
// profiles, without requiring a resolvable amazonaws.com hostname.
func TestConnectCRV1Flow(t *testing.T) {
	bin := buildMockServer(t)
	srv, err := testenv.Start(testenv.Config{
		Binary:   bin,
		CRV1Mode: true,
	})
	if err != nil {
		t.Fatalf("start mock server: %v", err)
	}
	defer srv.Stop()

	time.Sleep(200 * time.Millisecond)

	p := mockProfile(t, srv.TCPAddr)
	client := vpn.New(p)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	challenge, err := client.Phase1ForTest(ctx)
	if err != nil {
		t.Fatalf("Phase1ForTest: %v", err)
	}
	if challenge == nil {
		t.Fatal("expected SAML challenge in CRV1 mode, got nil")
	}
	t.Logf("challenge: stateID=%q url=%q", challenge.StateID, challenge.URL)

	fakeToken := base64.StdEncoding.EncodeToString([]byte("fake-saml-response"))
	if err := client.ConnectPhase2Reuse(ctx, fakeToken); err != nil {
		if !strings.Contains(err.Error(), "operation not permitted") &&
			!strings.Contains(err.Error(), "CAP_NET_ADMIN") {
			t.Fatalf("ConnectPhase2Reuse: %v", err)
		}
		t.Logf("ConnectPhase2Reuse: TUN not available (%v) — checking auth events only", err)
	}
	client.Disconnect() //nolint:errcheck
	client.WaitForDisconnect() //nolint:errcheck

	time.Sleep(300 * time.Millisecond)

	authEvents := srv.AuthEvents()
	if len(authEvents) < 2 {
		t.Fatalf("expected at least 2 auth_packet_recv events (phase1 + phase2), got %d: %v",
			len(authEvents), authEvents)
	}

	p1 := authEvents[0]
	t.Logf("phase1 auth: username=%q password=%q", p1.Username, p1.Password)
	if p1.Password != "ACS::35001" {
		t.Errorf("phase1 password: got %q, want %q", p1.Password, "ACS::35001")
	}

	p2 := authEvents[1]
	t.Logf("phase2 auth: username=%q password_prefix=%q", p2.Username, p2.PasswordPrefix)
	if !strings.HasPrefix(p2.Password, "CRV1::") {
		t.Errorf("phase2 password should start with 'CRV1::', got %q", p2.PasswordPrefix)
	}
	if !strings.Contains(p2.Password, fakeToken) {
		t.Errorf("phase2 password should contain the SAML token")
	}
}
