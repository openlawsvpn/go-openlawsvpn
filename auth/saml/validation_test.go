package saml

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const validResponseXML = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="canary"></samlp:Response>`

const demoSAMLResponse = "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJvcGVubGF3c3Zwbi1kZW1vIj48L3NhbWxwOlJlc3BvbnNlPg=="

func encodedValidResponse() string {
	return base64.StdEncoding.EncodeToString([]byte(validResponseXML))
}

func TestNormalizeAndValidateResponse(t *testing.T) {
	token := encodedValidResponse()
	got, err := normalizeAndValidateResponse(token)
	if err != nil {
		t.Fatal(err)
	}
	if got != token {
		t.Fatalf("normalized token differs from input")
	}
}

func TestDemoSAMLResponsePassesACSValidation(t *testing.T) {
	s := &ACSServer{token: make(chan string, 1)}
	req := httptest.NewRequest(
		http.MethodPost,
		"http://127.0.0.1/",
		strings.NewReader(url.Values{"SAMLResponse": {demoSAMLResponse}}.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.handleACS(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := <-s.token; got != demoSAMLResponse {
		t.Fatal("ACS returned a response other than the canonical demo response")
	}
}

func TestNormalizeAndValidateResponseRejectsMalformedInputWithoutDisclosure(t *testing.T) {
	const canary = "CANARY_SECRET_NOT_FOR_ERRORS"
	bad := base64.StdEncoding.EncodeToString([]byte(`<not-saml>` + canary + `</not-saml>`))
	_, err := normalizeAndValidateResponse(bad)
	if err == nil {
		t.Fatal("expected malformed response to be rejected")
	}
	if strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), bad) {
		t.Fatalf("validation error disclosed response data: %v", err)
	}
}

func TestNormalizeAndValidateResponseRejectsOversize(t *testing.T) {
	_, err := normalizeAndValidateResponse(strings.Repeat("A", MaxSAMLResponseBytes+1))
	if err == nil {
		t.Fatal("expected oversized response to be rejected")
	}
}

func TestACSHandlerValidation(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		wantStatus  int
		wantToken   bool
	}{
		{
			name:        "valid",
			contentType: "application/x-www-form-urlencoded",
			body:        url.Values{"SAMLResponse": {encodedValidResponse()}}.Encode(),
			wantStatus:  http.StatusOK,
			wantToken:   true,
		},
		{
			name:        "wrong content type",
			contentType: "text/plain",
			body:        encodedValidResponse(),
			wantStatus:  http.StatusUnsupportedMediaType,
		},
		{
			name:        "invalid response",
			contentType: "application/x-www-form-urlencoded",
			body:        url.Values{"SAMLResponse": {"not-base64!"}}.Encode(),
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:        "oversized form",
			contentType: "application/x-www-form-urlencoded",
			body:        strings.Repeat("x", maxSAMLFormBytes+1),
			wantStatus:  http.StatusRequestEntityTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &ACSServer{token: make(chan string, 1)}
			req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			rec := httptest.NewRecorder()
			s.handleACS(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			select {
			case <-s.token:
				if !tt.wantToken {
					t.Fatal("invalid request delivered a token")
				}
			default:
				if tt.wantToken {
					t.Fatal("valid request did not deliver a token")
				}
			}
		})
	}
}
