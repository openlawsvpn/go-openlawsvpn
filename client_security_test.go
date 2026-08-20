package vpn

import (
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
