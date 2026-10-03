package vpn

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/auth/saml"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
)

func securityTestClient(t *testing.T) *Client {
	t.Helper()
	p, err := profile.ParseString("remote vpn.example.com 443\nproto tcp-client\n")
	if err != nil {
		t.Fatal(err)
	}
	c := New(p)
	c.cachedSAMLToken = "CANARY_SAML_ASSERTION"
	c.cachedSAMLExpiry = time.Now().Add(time.Minute)
	c.cachedStateID = "CANARY_STATE"
	c.cachedPhase1IP = "192.0.2.1"
	c.challenge = &saml.Challenge{StateID: "CANARY_STATE", SAMLURL: "https://idp.example/canary"}
	c.pushOpts = &routing.PushOptions{AuthToken: "CANARY_AUTH_TOKEN"}
	return c
}

func TestReconnectAfterSessionExpiryDoesNotReuseAssertion(t *testing.T) {
	c := securityTestClient(t)
	c.state = stateDisconnected
	c.doneErr = &saml.SessionExpiredError{Msg: saml.MsgKindAuthFailed.String(), Kind: saml.MsgKindAuthFailed}
	c.reauthRequired = true
	close(c.doneCh)

	err := c.Reconnect(context.Background())
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("Reconnect error = %v, want ErrReauthRequired", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedSAMLToken != "" || c.cachedStateID != "" || c.cachedPhase1IP != "" {
		t.Fatal("Reconnect retained a server-rejected authentication context")
	}
}

func TestReauthRequiredStateString(t *testing.T) {
	if got := StateReauthRequired.String(); got != "reauth_required" {
		t.Fatalf("StateReauthRequired.String() = %q", got)
	}
}

func TestConcurrentSessionExpiryEmitsOneReauthOutcome(t *testing.T) {
	c := securityTestClient(t)
	c.state = stateTunnelUp
	var outcomes atomic.Int32
	c.EventFn = func(event Event) {
		if event.Type == EventStateChanged && event.State == StateReauthRequired {
			outcomes.Add(1)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.cancelFn = cancel
	c.wg.Add(2)
	go c.sessionMonitorFor(ctx, strings.NewReader("AUTH_FAILED\x00"))
	go c.sessionMonitorFor(ctx, strings.NewReader("AUTH_FAILED,CRV1:R:state::https://idp.example\x00"))

	select {
	case <-c.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for concurrent expiry teardown")
	}
	if got := outcomes.Load(); got != 1 {
		t.Fatalf("reauth outcomes = %d, want 1", got)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedSAMLToken != "" || c.cachedStateID != "" {
		t.Fatal("expiry retained consumed authentication credentials")
	}
}

func TestExplicitDisconnectClearsCredentials(t *testing.T) {
	c := securityTestClient(t)
	if err := c.Disconnect(); err != nil {
		t.Fatal(err)
	}
	if err := c.WaitForDisconnect(); err != nil {
		t.Fatal(err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedSAMLToken != "" || !c.cachedSAMLExpiry.IsZero() ||
		c.cachedStateID != "" || c.cachedPhase1IP != "" || c.challenge != nil {
		t.Fatal("explicit disconnect retained SAML credentials")
	}
	if c.pushOpts.AuthToken != "" {
		t.Fatal("explicit disconnect retained server auth-token")
	}
}

func TestTransientDisconnectPreservesCredentialsForReconnect(t *testing.T) {
	c := securityTestClient(t)
	if err := c.disconnect(true); err != nil {
		t.Fatal(err)
	}
	if err := c.WaitForDisconnect(); err != nil {
		t.Fatal(err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedSAMLToken == "" || c.cachedStateID == "" || c.cachedPhase1IP == "" {
		t.Fatal("transient disconnect cleared credentials required by Reconnect")
	}
}

func TestIsPhase2CredentialsRejected(t *testing.T) {
	for _, kind := range []saml.MsgKind{saml.MsgKindAuthFailed, saml.MsgKindAuthFailedCRV1} {
		if !isPhase2CredentialsRejected(&saml.ControlMessage{Kind: kind}) {
			t.Errorf("kind %s was not classified as a rejected Phase 2 credential", kind)
		}
	}
	if isPhase2CredentialsRejected(&saml.ControlMessage{Kind: saml.MsgKindPushReply}) {
		t.Error("PUSH_REPLY was classified as a rejected Phase 2 credential")
	}
	if isPhase2CredentialsRejected(nil) {
		t.Error("nil control message was classified as a rejected Phase 2 credential")
	}
}

func TestSetupFailureClearsCredentials(t *testing.T) {
	c := securityTestClient(t)
	c.setDisconnected(assertionError("setup failed"))

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedSAMLToken != "" || c.cachedStateID != "" || c.challenge != nil {
		t.Fatal("connection-setup failure retained SAML credentials")
	}
}

type assertionError string

func (e assertionError) Error() string { return string(e) }
