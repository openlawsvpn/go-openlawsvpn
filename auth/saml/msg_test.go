package saml_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/auth/saml"
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
		{"CR_TEXT,enter the one-time code", saml.MsgKindCRText},
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

func TestParseDynamicChallenges(t *testing.T) {
	const secret = "SECRET_PROMPT_CANARY"
	cm, err := saml.ParseControlMsg("AUTH_FAILED,CRV1:R,E:state:user:" + secret)
	if err != nil {
		t.Fatal(err)
	}
	if cm.Kind != saml.MsgKindAuthFailedCRV1 || cm.DynamicChallenge == nil {
		t.Fatalf("dynamic challenge = %#v", cm)
	}
	if !cm.DynamicChallenge.Metadata.ResponseRequired || !cm.DynamicChallenge.Metadata.Echo || !cm.DynamicChallenge.Metadata.PromptPresent {
		t.Fatalf("metadata = %#v", cm.DynamicChallenge)
	}
	if cm.DynamicChallenge.Secrets.Prompt != secret {
		t.Fatal("secret prompt was not preserved in the sensitive field")
	}

	text, err := saml.ParseControlMsg("CR_TEXT," + secret)
	if err != nil {
		t.Fatal(err)
	}
	if text.Kind != saml.MsgKindCRText || text.DynamicChallenge == nil || text.DynamicChallenge.Secrets.Prompt != secret {
		t.Fatalf("CR_TEXT = %#v", text)
	}
}

func TestMalformedDynamicChallengeErrorIsSecretSafe(t *testing.T) {
	const secret = "SECRET_CHALLENGE_CANARY"
	_, err := saml.ParseControlMsg("AUTH_FAILED,CRV1:R:" + secret)
	if err == nil {
		t.Fatal("expected malformed challenge error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error disclosed challenge: %v", err)
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

type oneByteReader struct{ r *strings.Reader }

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.r.Read(p)
}

func TestReadDynamicChallengeFragmented(t *testing.T) {
	const wire = "CR_TEXT,fragmented secret prompt\x00"
	cm, err := saml.ReadControlMsg(oneByteReader{r: strings.NewReader(wire)}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cm.Kind != saml.MsgKindCRText || cm.DynamicChallenge == nil || !cm.DynamicChallenge.Metadata.PromptPresent {
		t.Fatalf("message = %#v", cm)
	}
}

func TestReadControlMsgPreservesFollowingMessage(t *testing.T) {
	r := strings.NewReader("CR_TEXT,first\x00INFO,second\x00")
	first, err := saml.ReadControlMsg(r, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := saml.ReadControlMsg(r, 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.Raw != "CR_TEXT,first" || second.Raw != "INFO,second" {
		t.Fatalf("messages = (%q, %q)", first.Raw, second.Raw)
	}
}

func TestReadControlMsgLimit(t *testing.T) {
	_, err := saml.ReadControlMsg(strings.NewReader("12345\x00"), 4)
	if err == nil || !strings.Contains(err.Error(), "exceeds 4 bytes") {
		t.Fatalf("ReadControlMsg error = %v", err)
	}
}

func TestWriteControlMsg(t *testing.T) {
	var buf bytes.Buffer
	if err := saml.WriteControlMsg(&buf, "AWS_CC_MSG,1,1,0,payload", 0); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "AWS_CC_MSG,1,1,0,payload\x00"; got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
	if err := saml.WriteControlMsg(&buf, "bad\x00message", 0); err == nil {
		t.Fatal("expected embedded-NUL error")
	}
	if err := saml.WriteControlMsg(&buf, "12345", 4); err == nil {
		t.Fatal("expected size-limit error")
	}
}

func TestWritePhase2Credential(t *testing.T) {
	var buf bytes.Buffer
	credential := saml.BuildPhase2Password("stateABC", "tok123")
	if err := saml.WritePhase2Credential(&buf, credential); err != nil {
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

func TestWrapAuthFailedDoesNotDiscloseServerMessage(t *testing.T) {
	const canary = "CANARY_AUTH_MATERIAL_MUST_NOT_BE_LOGGED"
	for _, active := range []bool{false, true} {
		err := saml.WrapAuthFailed("AUTH_FAILED,"+canary, active)
		if strings.Contains(err.Error(), canary) {
			t.Fatalf("active=%v: error disclosed server authentication material: %v", active, err)
		}
		var expired *saml.SessionExpiredError
		if errors.As(err, &expired) && strings.Contains(expired.Msg, canary) {
			t.Fatalf("active=%v: structured error retained server authentication material", active)
		}
	}
}
