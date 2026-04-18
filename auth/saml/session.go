// Package saml — session-level coordination for SAML/CRV1 two-phase auth.
package saml

import (
	"fmt"
	"io"
	"strings"
)

// HandlePhase1 reads the first control message from r (typically a *tls.Conn
// or any io.Reader over the OpenVPN TLS session) and classifies it.
//
// Possible outcomes:
//   - MsgKindPushReply: no SAML required; the returned message holds the
//     PUSH_REPLY options string.
//   - MsgKindAuthFailedCRV1: SAML required; the returned message's Challenge
//     field is populated with the stateID and SAML URL.
//   - MsgKindAuthFailed: server rejected the connection outright (no CRV1).
//   - MsgKindUnknown: unexpected server message.
func HandlePhase1(r io.Reader) (*ControlMessage, error) {
	cm, err := ReadControlMsg(r, 0)
	if err != nil {
		return nil, fmt.Errorf("saml: Phase1 read: %w", err)
	}
	if cm.Kind == MsgKindAuthFailed {
		return cm, fmt.Errorf("saml: Phase1 auth failed: %s", cm.Raw)
	}
	return cm, nil
}

// CompletePhase2 sends the SAML credential to the server over the TLS
// connection w, then reads back the server response.
//
// stateID must match the Challenge.StateID returned by Phase 1.
// samlToken is the base64-encoded SAMLResponse received from the IdP via the
// ACS callback.
//
// On success, the returned ControlMessage is MsgKindPushReply and the caller
// should parse its Raw field for tunnel configuration.
// On failure (AUTH_FAILED), an error is returned; if sessionActive is true the
// error is a *SessionExpiredError.
func CompletePhase2(rw io.ReadWriter, stateID, samlToken string, sessionActive bool) (*ControlMessage, error) {
	username := BuildPhase2Username(stateID, samlToken)
	if err := WritePhase2Credentials(rw, username); err != nil {
		return nil, err
	}

	cm, err := ReadControlMsg(rw, 0)
	if err != nil {
		return nil, fmt.Errorf("saml: Phase2 read response: %w", err)
	}

	switch cm.Kind {
	case MsgKindPushReply:
		return cm, nil
	case MsgKindAuthFailedCRV1:
		// Server re-challenged; treat as auth failure.
		return nil, fmt.Errorf("saml: Phase2 unexpected CRV1 re-challenge")
	default:
		return nil, WrapAuthFailed(cm.Raw, sessionActive)
	}
}

// ParsePhase2Credential parses a Phase 2 client credential message sent by the
// client during Phase 2.
//
// Expected format: "AUTH_REPLY,CRV1::<state_id>::<saml_token>\x00"
//
// Returns (stateID, samlToken, nil) on success.
// Used by the server side (e.g. mock server) to validate Phase 2 credentials.
func ParsePhase2Credential(msg string) (stateID, samlToken string, err error) {
	msg = strings.TrimRight(msg, "\x00")
	const prefix = "AUTH_REPLY,CRV1::"
	if !strings.HasPrefix(msg, prefix) {
		return "", "", fmt.Errorf("saml: ParsePhase2Credential: not an AUTH_REPLY,CRV1 message: %q", msg)
	}
	rest := msg[len(prefix):]
	sepIdx := strings.Index(rest, "::")
	if sepIdx < 0 {
		return "", "", fmt.Errorf("saml: ParsePhase2Credential: missing '::' in credential: %q", msg)
	}
	stateID = rest[:sepIdx]
	samlToken = rest[sepIdx+2:]
	if stateID == "" {
		return "", "", fmt.Errorf("saml: ParsePhase2Credential: empty state_id")
	}
	return stateID, samlToken, nil
}
