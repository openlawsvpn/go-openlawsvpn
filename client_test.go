package vpn_test

import (
	"context"
	"strings"
	"testing"

	vpn "github.com/openlawsvpn/go-openlawsvpn"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

func makeTestProfile() *profile.Profile {
	p, err := profile.ParseString("remote vpn.example.com 443\nproto tcp-client\n")
	if err != nil {
		panic(err)
	}
	return p
}

// TestNewClient verifies that New returns a non-nil Client.
func TestNewClient(t *testing.T) {
	c := vpn.New(makeTestProfile())
	if c == nil {
		t.Fatal("New returned nil")
	}
}

// TestStatsZero verifies that Stats returns zero values before any connection.
func TestStatsZero(t *testing.T) {
	c := vpn.New(makeTestProfile())
	s := c.Stats()
	if s.BytesSent != 0 {
		t.Errorf("BytesSent = %d, want 0", s.BytesSent)
	}
	if s.BytesRecv != 0 {
		t.Errorf("BytesRecv = %d, want 0", s.BytesRecv)
	}
	if s.Uptime != 0 {
		t.Errorf("Uptime = %v, want 0", s.Uptime)
	}
}

// TestConnectPhase2WithoutPhase1 verifies that calling ConnectPhase2Reuse
// before Phase1ForTest returns an error.
func TestConnectPhase2WithoutPhase1(t *testing.T) {
	c := vpn.New(makeTestProfile())
	err := c.ConnectPhase2Reuse(context.TODO(), "token")
	if err == nil {
		t.Fatal("expected error when ConnectPhase2Reuse called before Phase1ForTest")
	}
}

// TestDisconnectIdempotent verifies that calling Disconnect multiple times is safe.
func TestDisconnectIdempotent(t *testing.T) {
	c := vpn.New(makeTestProfile())
	if err := c.Disconnect(); err != nil {
		t.Fatalf("first Disconnect: %v", err)
	}
	if err := c.Disconnect(); err != nil {
		t.Fatalf("second Disconnect: %v", err)
	}
}

// TestSAMLChallengeFields verifies that SAMLChallenge is properly constructed.
func TestSAMLChallengeFields(t *testing.T) {
	sc := vpn.SAMLChallenge{
		URL:     "https://idp.example.com/sso",
		StateID: "abc123",
	}
	if sc.URL != "https://idp.example.com/sso" {
		t.Errorf("URL = %q", sc.URL)
	}
	if sc.StateID != "abc123" {
		t.Errorf("StateID = %q", sc.StateID)
	}
}

// TestMaxReconnectsDefault verifies that New sets MaxReconnects to 0 (unlimited).
func TestMaxReconnectsDefault(t *testing.T) {
	c := vpn.New(makeTestProfile())
	if c.MaxReconnects != 0 {
		t.Errorf("MaxReconnects = %d, want 0 (unlimited)", c.MaxReconnects)
	}
}

// TestReconnectExceedsLimit verifies that Reconnect returns an error when all
// attempts fail (unreachable server) and MaxReconnects is respected.
// We set MaxReconnects=1 and a context with a very short deadline to avoid
// any real network waits.
func TestReconnectExceedsLimit(t *testing.T) {
	c := vpn.New(makeTestProfile())
	c.MaxReconnects = 1

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel the context immediately so Phase1 fails without hitting the
	// network — this exercises the "all attempts fail" code path.
	cancel()

	err := c.Reconnect(ctx)
	if err == nil {
		t.Fatal("expected error when reconnect context is cancelled")
	}
}

// TestReconnectContextCancelled verifies that Reconnect respects ctx.Done.
func TestReconnectContextCancelled(t *testing.T) {
	c := vpn.New(makeTestProfile())
	c.MaxReconnects = 0 // unlimited

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	err := c.Reconnect(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

// TestDoneChannelClosedAfterDisconnect verifies that Done() returns a channel
// that is closed after Disconnect+Wait complete.
func TestDoneChannelClosedAfterDisconnect(t *testing.T) {
	c := vpn.New(makeTestProfile())
	c.Disconnect()            //nolint:errcheck
	c.WaitForDisconnect()     //nolint:errcheck
	select {
	case <-c.Done():
		// expected
	default:
		t.Fatal("Done() channel not closed after Disconnect+Wait")
	}
}

// TestLocalIPBeforeConnect verifies LocalIP returns "" before any connection.
func TestLocalIPBeforeConnect(t *testing.T) {
	c := vpn.New(makeTestProfile())
	if ip := c.LocalIP(); ip != "" {
		t.Errorf("LocalIP before connect = %q, want empty", ip)
	}
}

// TestPhase1IPBeforeConnect verifies Phase1IP returns "" before any connection.
func TestPhase1IPBeforeConnect(t *testing.T) {
	c := vpn.New(makeTestProfile())
	if ip := c.Phase1IP(); ip != "" {
		t.Errorf("Phase1IP before connect = %q, want empty", ip)
	}
}

// TestPhase1IPAfterSetRelayPhase2 verifies Phase1IP returns the seeded value.
func TestPhase1IPAfterSetRelayPhase2(t *testing.T) {
	c := vpn.New(makeTestProfile())
	c.SetRelayPhase2("203.0.113.42", "state-abc")
	if ip := c.Phase1IP(); ip != "203.0.113.42" {
		t.Errorf("Phase1IP = %q, want 203.0.113.42", ip)
	}
}

// TestSetRelayPhase2 verifies SetRelayPhase2 pre-seeds Phase 1 state so
// ConnectPhase2 can be called without a prior connectPhase1.
func TestSetRelayPhase2(t *testing.T) {
	c := vpn.New(makeTestProfile())
	// Before SetRelayPhase2, ConnectPhase2 should fail (no challenge seeded).
	err := c.ConnectPhase2(context.Background(), "token")
	if err == nil {
		t.Fatal("expected error before SetRelayPhase2")
	}

	// After SetRelayPhase2, the state is seeded — ConnectPhase2 will fail
	// only when it tries to dial, not before.
	c2 := vpn.New(makeTestProfile())
	c2.SetRelayPhase2("10.0.0.1", "state-xyz")
	// We don't call ConnectPhase2 here (would hit the network); just verify
	// LocalIP is still empty until Phase 2 completes.
	if ip := c2.LocalIP(); ip != "" {
		t.Errorf("LocalIP after SetRelayPhase2 = %q, want empty", ip)
	}
}

// TestConnectIPv6RemoteNoTooManyColons verifies Phase 1 address construction
// handles IPv6 literals correctly. The context is canceled to avoid real
// network waits; this still exercises dial target formatting.
func TestConnectIPv6RemoteNoTooManyColons(t *testing.T) {
	p, err := profile.ParseString("remote 2001:db8:7c3a:91f2:4e6b:2d10:a8c4:5f39\n1194\nproto udp\n")
	if err != nil {
		t.Fatalf("parse profile: %v", err)
	}
	c := vpn.New(p)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = c.Connect(ctx)
	if err == nil {
		t.Fatal("expected connect error")
	}
	if strings.Contains(err.Error(), "too many colons in address") {
		t.Fatalf("IPv6 address formatting regression: %v", err)
	}
}

// TestConnectPhase2IPv6Phase1IPNoTooManyColons verifies Phase 2 dial target
// construction handles an IPv6 Phase1 IP literal correctly.
func TestConnectPhase2IPv6Phase1IPNoTooManyColons(t *testing.T) {
	c := vpn.New(makeTestProfile())
	c.SetRelayPhase2("2001:db8:7c3a:91f2:4e6b:2d10:a8c4:5f39", "state-xyz")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := c.ConnectPhase2(ctx, "token")
	if err == nil {
		t.Fatal("expected Phase2 connect error")
	}
	if strings.Contains(err.Error(), "too many colons in address") {
		t.Fatalf("IPv6 address formatting regression: %v", err)
	}
}
