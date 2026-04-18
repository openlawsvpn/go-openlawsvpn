package saml_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/openlawsvpn/go-openvpn3/auth/saml"
)

func TestClassifyMsg(t *testing.T) {
	cases := []struct {
		msg  string
		want saml.MsgKind
	}{
		{"PUSH_REPLY,ifconfig 10.0.0.1 10.0.0.2\x00", saml.MsgKindPushReply},
		{"PUSH_REPLY,ifconfig 10.0.0.1 10.0.0.2", saml.MsgKindPushReply},
		{"AUTH_FAILED,CRV1:R:state::https://idp.example.com\x00", saml.MsgKindAuthFailedCRV1},
		{"AUTH_FAILED\x00", saml.MsgKindAuthFailed},
		{"AUTH_FAILED", saml.MsgKindAuthFailed},
		{"", saml.MsgKindUnknown},
		{"HELLO", saml.MsgKindUnknown},
	}
	for _, tc := range cases {
		got := saml.ClassifyMsg(tc.msg)
		if got != tc.want {
			t.Errorf("ClassifyMsg(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}

func TestParseControlMsgCRV1(t *testing.T) {
	raw := "AUTH_FAILED,CRV1:R,52.1.2.3:myState::https://idp.example.com/sso\x00"
	cm, err := saml.ParseControlMsg(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cm.Kind != saml.MsgKindAuthFailedCRV1 {
		t.Fatalf("Kind = %v, want MsgKindAuthFailedCRV1", cm.Kind)
	}
	if cm.Challenge == nil {
		t.Fatal("Challenge is nil")
	}
	if cm.Challenge.StateID != "myState" {
		t.Errorf("StateID = %q", cm.Challenge.StateID)
	}
	if cm.Challenge.RemoteIP != "52.1.2.3" {
		t.Errorf("RemoteIP = %q", cm.Challenge.RemoteIP)
	}
}

func TestParseControlMsgPushReply(t *testing.T) {
	raw := "PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5\x00"
	cm, err := saml.ParseControlMsg(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cm.Kind != saml.MsgKindPushReply {
		t.Fatalf("Kind = %v, want MsgKindPushReply", cm.Kind)
	}
	if cm.Challenge != nil {
		t.Error("Challenge should be nil for PUSH_REPLY")
	}
}

func TestReadControlMsg(t *testing.T) {
	payload := "PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5\x00"
	r := strings.NewReader(payload)
	cm, err := saml.ReadControlMsg(r, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cm.Kind != saml.MsgKindPushReply {
		t.Errorf("Kind = %v", cm.Kind)
	}
}

func TestWritePhase2Credentials(t *testing.T) {
	var buf bytes.Buffer
	username := saml.BuildPhase2Username("stateABC", "tok123")
	if err := saml.WritePhase2Credentials(&buf, username); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.HasPrefix(got, "AUTH_REPLY,") {
		t.Errorf("expected AUTH_REPLY prefix, got %q", got)
	}
	if !strings.HasSuffix(got, "\x00") {
		t.Errorf("expected NUL terminator, got %q", got)
	}
	if !strings.Contains(got, "CRV1::stateABC::tok123") {
		t.Errorf("username not found in %q", got)
	}
}

func TestSessionExpiredError(t *testing.T) {
	err := saml.WrapAuthFailed("AUTH_FAILED", true)
	var se *saml.SessionExpiredError
	if !errors.As(err, &se) {
		t.Fatalf("expected *SessionExpiredError, got %T: %v", err, err)
	}
	if se.Msg != "AUTH_FAILED" {
		t.Errorf("Msg = %q", se.Msg)
	}

	// Non-active session → plain error, not SessionExpiredError.
	err2 := saml.WrapAuthFailed("AUTH_FAILED", false)
	var se2 *saml.SessionExpiredError
	if errors.As(err2, &se2) {
		t.Error("expected plain error, got *SessionExpiredError")
	}
}
