package saml_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/openlawsvpn/go-openvpn3/auth/saml"
)

// FuzzParseCRV1 feeds random strings to ParseCRV1 to verify it never panics.
func FuzzParseCRV1(f *testing.F) {
	// Seed: realistic CRV1 message.
	f.Add("AUTH_FAILED,CRV1:R:instance-1/abc:b'XXXX':https://portal.sso.us-east-1.amazonaws.com/saml")
	// Seed: with remote IP.
	f.Add("AUTH_FAILED,CRV1:R,52.1.2.3:state-xyz:b'AA==':https://example.com/sso?foo=bar")
	// Seed: not a CRV1 message.
	f.Add("AUTH_FAILED,Invalid username or password")
	// Seed: minimal valid structure.
	f.Add("AUTH_FAILED,CRV1:R:s:u:https://x")
	// Seed: missing colons.
	f.Add("AUTH_FAILED,CRV1:R")
	// Seed: empty string.
	f.Add("")

	f.Fuzz(func(t *testing.T, msg string) {
		_, _ = saml.ParseCRV1(msg)
	})
}

// FuzzHandlePhase1 feeds random byte slices to HandlePhase1 to verify it
// never panics regardless of the reader content.
func FuzzHandlePhase1(f *testing.F) {
	// Seed: PUSH_REPLY.
	f.Add([]byte("PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5,route 10.0.0.0\x00"))
	// Seed: AUTH_FAILED,CRV1.
	f.Add([]byte("AUTH_FAILED,CRV1:R:stateid:user:https://idp.example.com/sso\x00"))
	// Seed: plain AUTH_FAILED.
	f.Add([]byte("AUTH_FAILED,Invalid username or password\x00"))
	// Seed: empty.
	f.Add([]byte{})
	// Seed: no null terminator.
	f.Add([]byte("PUSH_REPLY,ifconfig 10.0.0.1 10.0.0.2"))
	// Seed: random garbage.
	f.Add([]byte{0xff, 0xfe, 0x00, 0x01, 0x80})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = saml.HandlePhase1(bytes.NewReader(data))
	})
}

// FuzzParseControlMsg feeds random strings to ParseControlMsg.
func FuzzParseControlMsg(f *testing.F) {
	f.Add("PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5")
	f.Add("AUTH_FAILED,CRV1:R:state:user:https://example.com")
	f.Add("AUTH_FAILED")
	f.Add("")
	f.Add(strings.Repeat("A", 1024))
	f.Add("PUSH_REPLY," + strings.Repeat("x,", 500))

	f.Fuzz(func(t *testing.T, msg string) {
		_, _ = saml.ParseControlMsg(msg)
	})
}
