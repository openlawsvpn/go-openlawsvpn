package saml_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/auth/saml"
)

// --- ParseCRV1 tests ---

func TestParseCRV1Basic(t *testing.T) {
	msg := "AUTH_FAILED,CRV1:R:myStateID::https://idp.example.com/saml"
	c, err := saml.ParseCRV1(msg)
	if err != nil {
		t.Fatal(err)
	}
	if c.StateID != "myStateID" {
		t.Errorf("StateID = %q, want %q", c.StateID, "myStateID")
	}
	if c.SAMLURL != "https://idp.example.com/saml" {
		t.Errorf("SAMLURL = %q", c.SAMLURL)
	}
	if c.RemoteIP != "" {
		t.Errorf("RemoteIP = %q, want empty", c.RemoteIP)
	}
}

func TestParseCRV1WithRemoteIP(t *testing.T) {
	msg := "AUTH_FAILED,CRV1:R,52.1.2.3:stateABC::https://login.microsoftonline.com/sso"
	c, err := saml.ParseCRV1(msg)
	if err != nil {
		t.Fatal(err)
	}
	if c.RemoteIP != "52.1.2.3" {
		t.Errorf("RemoteIP = %q, want 52.1.2.3", c.RemoteIP)
	}
	if c.StateID != "stateABC" {
		t.Errorf("StateID = %q", c.StateID)
	}
	if !strings.HasPrefix(c.SAMLURL, "https://") {
		t.Errorf("SAMLURL = %q", c.SAMLURL)
	}
}

func TestParseCRV1Errors(t *testing.T) {
	bad := []string{
		"AUTH_FAILED",
		"AUTH_FAILED,CRV1:R",         // no separator
		"AUTH_FAILED,CRV1:R:noSep",   // no :: separator
		"AUTH_FAILED,CRV1:R:::url",   // empty state_id
		"AUTH_FAILED,CRV1:R:state::", // empty saml_url
	}
	for _, m := range bad {
		_, err := saml.ParseCRV1(m)
		if err == nil {
			t.Errorf("expected error for %q", m)
		}
	}
}

func TestBuildPhase2Username(t *testing.T) {
	got := saml.BuildPhase2Username("myState", "base64token==")
	want := "CRV1::myState::base64token=="
	if got != want {
		t.Errorf("BuildPhase2Username = %q, want %q", got, want)
	}
}

// --- ACSServer tests ---

// TestACSServerReceivesToken starts the ACS server on a free port by using
// a custom approach: since ACSPort (35001) may be in use in CI, we test
// the HTTP handler logic independently.
func TestACSHandlerSAMLResponse(t *testing.T) {
	// We can't bind 35001 reliably in tests; exercise the HTTP handler via
	// the exported ParseCRV1 + BuildPhase2Username path, and separately
	// test the server with a context-cancel path.
	srv, err := saml.NewACSServer()
	if err != nil {
		t.Skipf("cannot bind port %d (may be in use): %v", saml.ACSPort, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	token := "PHNhbWxwOlJlc3BvbnNl"

	// Send the POST from a goroutine.
	go func() {
		time.Sleep(100 * time.Millisecond)
		data := url.Values{"SAMLResponse": {token}}
		resp, err := http.PostForm(fmt.Sprintf("http://127.0.0.1:%d/", saml.ACSPort), data)
		if err != nil {
			return
		}
		resp.Body.Close()
	}()

	got, err := srv.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if got != token {
		t.Errorf("token = %q, want %q", got, token)
	}
}

func TestACSServerContextCancel(t *testing.T) {
	srv, err := saml.NewACSServer()
	if err != nil {
		t.Skipf("cannot bind port %d: %v", saml.ACSPort, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	_, err = srv.Wait(ctx)
	if err == nil {
		t.Fatal("expected error on immediate cancel")
	}
}
