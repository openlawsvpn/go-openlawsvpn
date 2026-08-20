// Package saml — control channel message classification and session error types.
package saml

import (
	"fmt"
	"io"
	"strings"
)

// MsgKind classifies a control-channel plaintext message received from the VPN
// server after TLS negotiation.
type MsgKind int

const (
	// MsgKindUnknown is returned for messages that do not match any known pattern.
	MsgKindUnknown MsgKind = iota
	// MsgKindPushReply is a successful "PUSH_REPLY,..." tunnel configuration message.
	MsgKindPushReply
	// MsgKindAuthFailedCRV1 is an "AUTH_FAILED,CRV1:..." SAML challenge.
	MsgKindAuthFailedCRV1
	// MsgKindAuthFailed is a plain "AUTH_FAILED" rejection with no SAML challenge.
	MsgKindAuthFailed
)

// String returns a non-sensitive description of the control-message kind.
func (k MsgKind) String() string {
	switch k {
	case MsgKindPushReply:
		return "PUSH_REPLY"
	case MsgKindAuthFailedCRV1:
		return "AUTH_FAILED_CRV1"
	case MsgKindAuthFailed:
		return "AUTH_FAILED"
	default:
		return "UNKNOWN"
	}
}

// ClassifyMsg classifies the raw control-channel message msg.
// Trailing NUL bytes (OpenVPN's message terminator) are stripped before matching.
func ClassifyMsg(msg string) MsgKind {
	msg = strings.TrimRight(msg, "\x00")
	switch {
	case strings.HasPrefix(msg, "PUSH_REPLY"):
		return MsgKindPushReply
	case strings.HasPrefix(msg, "AUTH_FAILED,CRV1:"):
		return MsgKindAuthFailedCRV1
	case strings.HasPrefix(msg, "AUTH_FAILED"):
		return MsgKindAuthFailed
	default:
		return MsgKindUnknown
	}
}

// ControlMessage holds a classified control-channel message.
type ControlMessage struct {
	// Kind is the classified message type.
	Kind MsgKind
	// Raw is the original message text with the trailing NUL stripped. It can
	// contain authentication challenge material; never include it in logs or
	// generic errors.
	Raw string
	// Challenge is non-nil for MsgKindAuthFailedCRV1 messages.
	Challenge *Challenge
}

// ParseControlMsg classifies and, for CRV1 messages, fully parses a raw
// control-channel message.  msg may include a trailing NUL byte.
func ParseControlMsg(msg string) (*ControlMessage, error) {
	stripped := strings.TrimRight(msg, "\x00")
	kind := ClassifyMsg(stripped)

	cm := &ControlMessage{Kind: kind, Raw: stripped}
	if kind == MsgKindAuthFailedCRV1 {
		ch, err := ParseCRV1(stripped)
		if err != nil {
			return nil, err
		}
		cm.Challenge = ch
	}
	return cm, nil
}

// ReadControlMsg reads one NUL-terminated control message from r (typically a
// *tls.Conn) and returns the classified ControlMessage.
// At most maxBytes bytes are read; pass 0 to use the default (4096).
func ReadControlMsg(r io.Reader, maxBytes int) (*ControlMessage, error) {
	if maxBytes <= 0 {
		maxBytes = 65536
	}
	buf := make([]byte, maxBytes)
	n, err := r.Read(buf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("saml: ReadControlMsg: %w", err)
	}
	return ParseControlMsg(string(buf[:n]))
}

// WritePhase2Credential writes the legacy AUTH_REPLY form used by the package
// test harness. credential must be the result of BuildPhase2Password. The
// production Client sends the same credential in a key-method-2 password field.
//
// Wire format: "AUTH_REPLY,<credential>\x00"
//
// This helper is not used by the production AWS connection path.
func WritePhase2Credential(w io.Writer, credential string) error {
	msg := "AUTH_REPLY," + credential + "\x00"
	_, err := w.Write([]byte(msg))
	if err != nil {
		return fmt.Errorf("saml: WritePhase2Credential: %w", err)
	}
	return nil
}

// WritePhase2Credentials is retained for source compatibility.
// Deprecated: use WritePhase2Credential.
func WritePhase2Credentials(w io.Writer, credential string) error {
	return WritePhase2Credential(w, credential)
}

// SessionExpiredError is returned when the VPN server sends AUTH_FAILED
// mid-session (i.e. after PUSH_REPLY was already received), indicating that the
// VPN session has expired and must be re-authenticated via a new SAML flow.
type SessionExpiredError struct {
	// Msg is the non-sensitive classification of the AUTH_FAILED message.
	Msg string
}

// Error implements the error interface.
func (e *SessionExpiredError) Error() string {
	return "saml: session expired: authentication rejected"
}

// WrapAuthFailed returns an error appropriate to the session state.
//
// If sessionActive is true (PUSH_REPLY was already received), the server's
// AUTH_FAILED indicates expiry and a *SessionExpiredError is returned.
// Otherwise a plain formatted error is returned.
func WrapAuthFailed(msg string, sessionActive bool) error {
	kind := ClassifyMsg(msg).String()
	if sessionActive {
		return &SessionExpiredError{Msg: kind}
	}
	return fmt.Errorf("saml: authentication failed (%s)", kind)
}
