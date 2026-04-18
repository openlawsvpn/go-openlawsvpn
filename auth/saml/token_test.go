package saml

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestTokenExpiry(t *testing.T) {
	// Minimal SAML assertion with a SubjectConfirmationData NotOnOrAfter.
	samlXML := `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Conditions NotBefore="2024-01-01T10:00:00Z" NotOnOrAfter="2024-01-01T10:05:00Z"/>
    <saml:AuthnStatement/>
  </saml:Assertion>
</samlp:Response>`

	token := base64.StdEncoding.EncodeToString([]byte(samlXML))
	got := TokenExpiry(token)

	want := time.Date(2024, 1, 1, 10, 5, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("TokenExpiry = %v, want %v", got, want)
	}
}

func TestTokenExpiryMultiple(t *testing.T) {
	// When multiple NotOnOrAfter attributes exist, the earliest wins.
	samlXML := `<Assertion>
  <Conditions NotOnOrAfter="2024-06-01T12:00:00Z"/>
  <SubjectConfirmationData NotOnOrAfter="2024-06-01T11:30:00Z"/>
</Assertion>`

	token := base64.StdEncoding.EncodeToString([]byte(samlXML))
	got := TokenExpiry(token)

	want := time.Date(2024, 6, 1, 11, 30, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("TokenExpiry = %v, want %v (should pick earliest)", got, want)
	}
}

func TestTokenExpiryMissing(t *testing.T) {
	// No NotOnOrAfter → zero time.
	samlXML := `<Assertion><AuthnStatement/></Assertion>`
	token := base64.StdEncoding.EncodeToString([]byte(samlXML))
	got := TokenExpiry(token)
	if !got.IsZero() {
		t.Errorf("expected zero time, got %v", got)
	}
}

func TestTokenExpiryInvalidBase64(t *testing.T) {
	got := TokenExpiry("not-valid-base64!!!")
	if !got.IsZero() {
		t.Errorf("expected zero time for invalid base64, got %v", got)
	}
}

func TestTokenExpiryMilliseconds(t *testing.T) {
	// Some IdPs include milliseconds.
	samlXML := `<Conditions NotOnOrAfter="2024-03-15T08:45:30.500Z"/>`
	token := base64.StdEncoding.EncodeToString([]byte(samlXML))
	got := TokenExpiry(token)
	if got.IsZero() {
		t.Error("expected non-zero time for millisecond timestamp")
	}
	want := time.Date(2024, 3, 15, 8, 45, 30, 500_000_000, time.UTC)
	if !got.Equal(want) {
		t.Errorf("TokenExpiry = %v, want %v", got, want)
	}
}
