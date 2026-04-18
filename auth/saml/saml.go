// Package saml handles the AWS Client VPN CRV1 SAML challenge-response flow.
//
// AWS Client VPN authentication works in two phases:
//
//  1. The server sends AUTH_FAILED with a CRV1 challenge string that contains
//     a SAML URL. The client opens that URL in a browser.
//
//  2. The IdP redirects the browser to the ACS URL
//     (http://127.0.0.1:35001 — hardcoded by AWS). This package listens on
//     that port, captures the SAMLResponse POST parameter, and returns the
//     token to the caller so it can start Phase 2.
//
// Reference: openvpn3-core client/ovpncli.cpp (CRV1 parsing),
// openlawsvpn-android SamlCallbackServer.kt (ACS server)
package saml

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ACSPort is the TCP port that AWS hardcodes for the SAML ACS callback.
// This is fixed across all AWS regions and all IdPs.
const ACSPort = 35001

// Challenge contains the parsed fields from an AUTH_FAILED,CRV1 message.
type Challenge struct {
	// StateID is the opaque session identifier that must be echoed back in
	// Phase 2 as the username: "CRV1::<StateID>::<SAMLToken>".
	StateID string
	// SAMLURL is the identity-provider URL the user must visit to authenticate.
	SAMLURL string
	// RemoteIP is the VPN server IP (informational, extracted when present).
	RemoteIP string
}

// ParseCRV1 parses the CRV1 challenge string from an AUTH_FAILED message.
//
// Wire format (openvpn3-core auth/cr.hpp):
//
//	AUTH_FAILED,CRV1:<flags>:<state_id>:<base64_username>:<saml_url>
//
// All fields are separated by a single colon.  The SAML URL itself may contain
// colons (e.g. "https://..."), so parsing uses fixed-position splits: strip the
// flags field, then consume state_id and base64_username as the next two
// colon-delimited tokens; everything remaining is the URL.
//
// Examples:
//
//	AUTH_FAILED,CRV1:R:instance-1/...:b'XXXX':https://portal.sso.us-east-1.amazonaws.com/...
//	AUTH_FAILED,CRV1:R,52.1.2.3:instance-1/...:b'XXXX':https://...
func ParseCRV1(msg string) (*Challenge, error) {
	const prefix = "AUTH_FAILED,CRV1:"
	if !strings.HasPrefix(msg, prefix) {
		return nil, fmt.Errorf("saml: not a CRV1 message: %q", msg)
	}
	rest := msg[len(prefix):]

	// Field 1: flags (before first colon); may be "R" or "R,<remote_ip>"
	colonIdx := strings.Index(rest, ":")
	if colonIdx < 0 {
		return nil, fmt.Errorf("saml: malformed CRV1 (no colon after flags): %q", msg)
	}
	flagsAndIP := rest[:colonIdx]
	rest = rest[colonIdx+1:]

	c := &Challenge{}
	if commaIdx := strings.Index(flagsAndIP, ","); commaIdx >= 0 {
		c.RemoteIP = flagsAndIP[commaIdx+1:]
	}

	// Field 2: state_id (before next colon)
	colonIdx = strings.Index(rest, ":")
	if colonIdx < 0 {
		return nil, fmt.Errorf("saml: malformed CRV1 (no colon after state_id): %q", msg)
	}
	c.StateID = rest[:colonIdx]
	rest = rest[colonIdx+1:]

	// Field 3: base64_username (before next colon); may be empty
	colonIdx = strings.Index(rest, ":")
	if colonIdx < 0 {
		return nil, fmt.Errorf("saml: malformed CRV1 (no colon after username): %q", msg)
	}
	// username field is informational; skip it
	rest = rest[colonIdx+1:]

	// Field 4: saml_url (remainder — may contain colons)
	c.SAMLURL = rest

	if c.StateID == "" {
		return nil, fmt.Errorf("saml: empty state_id in CRV1 message")
	}
	if c.SAMLURL == "" {
		return nil, fmt.Errorf("saml: empty saml_url in CRV1 message")
	}
	return c, nil
}

// BuildPhase2Username returns the username string that Phase 2 must send to
// the VPN server after successful SAML authentication.
//
//	Format: "CRV1::<state_id>::<base64_saml_token>"
func BuildPhase2Username(stateID, samlToken string) string {
	return "CRV1::" + stateID + "::" + samlToken
}

// normalizeBase64 sanitises a SAMLResponse value received from a browser POST.
//
// application/x-www-form-urlencoded encodes '+' as either '%2B' or as a raw
// '+'.  Go's http.Request.FormValue URL-decodes the body, turning both into
// either '+' or ' ' (space).  This function:
//   - converts spaces back to '+' (undoes the URL-decode artifact)
//   - strips all non-base64 characters (newlines, nulls, etc.)
//   - converts URL-safe base64 ('-' → '+', '_' → '/')
//   - re-adds '=' padding to make the length a multiple of 4
//
// Mirrors saml_capture.cpp normalize_base64() and SamlCallbackServer.kt normalizeBase64().
func normalizeBase64(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ':
			out = append(out, '+')
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/':
			out = append(out, c)
		case c == '-':
			out = append(out, '+') // URL-safe → standard
		case c == '_':
			out = append(out, '/') // URL-safe → standard
		// strip '=', '\n', '\r', and anything else
		}
	}
	for len(out)%4 != 0 {
		out = append(out, '=')
	}
	return string(out)
}

// ACSServer listens on 127.0.0.1:35001 for the browser's SAML POST callback.
// It captures the SAMLResponse form field and returns it via the returned
// channel, then shuts down.
//
// The caller must cancel ctx to abort the server if no callback arrives in time.
type ACSServer struct {
	ln     net.Listener
	token  chan string
	errCh  chan error
}

// NewACSServer creates and starts the ACS server.
// It binds to 127.0.0.1:ACSPort immediately so callers know whether the
// port is available before opening the browser.
func NewACSServer() (*ACSServer, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ACSPort))
	if err != nil {
		return nil, fmt.Errorf("saml: ACS listen: %w", err)
	}
	s := &ACSServer{
		ln:    ln,
		token: make(chan string, 1),
		errCh: make(chan error, 1),
	}
	return s, nil
}

// Wait starts serving and blocks until a SAMLResponse is received or ctx is
// cancelled. It returns the raw SAMLResponse value (base64-encoded by the IdP).
func (s *ACSServer) Wait(ctx context.Context) (string, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleACS)

	srv := &http.Server{Handler: mux}

	// Shut down the HTTP server when ctx is done.
	go func() {
		<-ctx.Done()
		srv.Close() //nolint:errcheck
	}()

	go func() {
		if err := srv.Serve(s.ln); err != nil && err != http.ErrServerClosed {
			s.errCh <- err
		}
	}()

	select {
	case tok := <-s.token:
		srv.Close() //nolint:errcheck
		return tok, nil
	case err := <-s.errCh:
		return "", fmt.Errorf("saml: ACS server error: %w", err)
	case <-ctx.Done():
		return "", fmt.Errorf("saml: ACS timeout: %w", ctx.Err())
	}
}

func (s *ACSServer) handleACS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	// r.FormValue URL-decodes the POST body, which converts base64 '+' characters
	// (submitted as '%2B' or as raw '+' in application/x-www-form-urlencoded) into
	// spaces.  normalizeBase64 converts those spaces back to '+', strips non-base64
	// chars, and fixes padding — matching saml_capture.cpp normalize_base64().
	tok := normalizeBase64(r.FormValue("SAMLResponse"))
	if tok == "" {
		http.Error(w, "missing SAMLResponse", http.StatusBadRequest)
		return
	}
	// Return a minimal HTML page that tells the user to close the browser.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<html><body><h2>Authentication successful.</h2><p>You may close this window.</p></body></html>")
	// Non-blocking send — if the channel already has a value, discard duplicate.
	select {
	case s.token <- tok:
	default:
	}
}
