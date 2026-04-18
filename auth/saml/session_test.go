package saml_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/openlawsvpn/go-openvpn3/auth/saml"
)

// readWriter couples a bytes.Buffer (for Read) with another buffer (for Write).
type readWriter struct {
	r *strings.Reader
	w *bytes.Buffer
}

func (rw *readWriter) Read(b []byte) (int, error)  { return rw.r.Read(b) }
func (rw *readWriter) Write(b []byte) (int, error) { return rw.w.Write(b) }

func TestHandlePhase1PushReply(t *testing.T) {
	r := strings.NewReader("PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5\x00")
	cm, err := saml.HandlePhase1(r)
	if err != nil {
		t.Fatal(err)
	}
	if cm.Kind != saml.MsgKindPushReply {
		t.Errorf("Kind = %v", cm.Kind)
	}
}

func TestHandlePhase1CRV1(t *testing.T) {
	msg := "AUTH_FAILED,CRV1:R,52.1.2.3:stateXYZ::https://idp.example.com/sso\x00"
	r := strings.NewReader(msg)
	cm, err := saml.HandlePhase1(r)
	if err != nil {
		t.Fatal(err)
	}
	if cm.Kind != saml.MsgKindAuthFailedCRV1 {
		t.Errorf("Kind = %v", cm.Kind)
	}
	if cm.Challenge.StateID != "stateXYZ" {
		t.Errorf("StateID = %q", cm.Challenge.StateID)
	}
}

func TestHandlePhase1AuthFailed(t *testing.T) {
	r := strings.NewReader("AUTH_FAILED\x00")
	_, err := saml.HandlePhase1(r)
	if err == nil {
		t.Fatal("expected error for AUTH_FAILED")
	}
}

func TestCompletePhase2Success(t *testing.T) {
	// Server responds with PUSH_REPLY after receiving credentials.
	serverResponse := "PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5\x00"
	rw := &readWriter{
		r: strings.NewReader(serverResponse),
		w: &bytes.Buffer{},
	}

	cm, err := saml.CompletePhase2(rw, "stateABC", "base64tok==", false)
	if err != nil {
		t.Fatal(err)
	}
	if cm.Kind != saml.MsgKindPushReply {
		t.Errorf("Kind = %v", cm.Kind)
	}

	// Verify the correct credential was written.
	written := rw.w.String()
	if !strings.Contains(written, "AUTH_REPLY,") {
		t.Errorf("expected AUTH_REPLY in written: %q", written)
	}
	if !strings.Contains(written, "CRV1::stateABC::base64tok==") {
		t.Errorf("expected CRV1 credential in written: %q", written)
	}
}

func TestCompletePhase2AuthFailed(t *testing.T) {
	serverResponse := "AUTH_FAILED\x00"
	rw := &readWriter{
		r: strings.NewReader(serverResponse),
		w: &bytes.Buffer{},
	}

	_, err := saml.CompletePhase2(rw, "state", "token", false)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCompletePhase2SessionExpired(t *testing.T) {
	serverResponse := "AUTH_FAILED\x00"
	rw := &readWriter{
		r: strings.NewReader(serverResponse),
		w: &bytes.Buffer{},
	}

	_, err := saml.CompletePhase2(rw, "state", "token", true)
	var se *saml.SessionExpiredError
	if err == nil {
		t.Fatal("expected error")
	}
	// SessionActive=true means it should be a *SessionExpiredError.
	import_errors_as := func() bool {
		_, ok := err.(*saml.SessionExpiredError)
		return ok
	}
	_ = se
	if !import_errors_as() {
		t.Errorf("expected *SessionExpiredError, got %T: %v", err, err)
	}
}

func TestParsePhase2Credential(t *testing.T) {
	msg := "AUTH_REPLY,CRV1::stateABC::base64token==\x00"
	stateID, token, err := saml.ParsePhase2Credential(msg)
	if err != nil {
		t.Fatal(err)
	}
	if stateID != "stateABC" {
		t.Errorf("stateID = %q", stateID)
	}
	if token != "base64token==" {
		t.Errorf("token = %q", token)
	}
}

func TestParsePhase2CredentialErrors(t *testing.T) {
	bad := []string{
		"PUSH_REPLY,foo",
		"AUTH_REPLY,CRV1::noSeparatorHere",
		"AUTH_REPLY,CRV1::::token", // empty stateID
	}
	for _, m := range bad {
		_, _, err := saml.ParsePhase2Credential(m)
		if err == nil {
			t.Errorf("expected error for %q", m)
		}
	}
}
