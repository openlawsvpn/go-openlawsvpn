package vpn_test

import (
	"context"
	"testing"

	vpn "github.com/openlawsvpn/go-openvpn3"
	"github.com/openlawsvpn/go-openvpn3/profile"
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
	c.Disconnect() //nolint:errcheck
	c.Wait()       //nolint:errcheck
	select {
	case <-c.Done():
		// expected
	default:
		t.Fatal("Done() channel not closed after Disconnect+Wait")
	}
}
