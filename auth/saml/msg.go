// Package saml — control channel message classification and session error types.
package saml

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// MaxControlMessageBytes is the maximum control-channel application-message
// payload accepted by AWS's patched OpenVPN3 client.
const MaxControlMessageBytes = 128 * 1024

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
	// MsgKindCRText is a generic challenge text application message. Its body
	// is authentication material and must not be logged.
	MsgKindCRText
	// MsgKindAWSCC is an AWS device-posture response fragment. Its fragment
	// payload is sensitive and must not be logged.
	MsgKindAWSCC
	// MsgKindPostureCheckInterval is an AWS device-posture refresh interval.
	MsgKindPostureCheckInterval
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
	case MsgKindCRText:
		return "CR_TEXT"
	case MsgKindAWSCC:
		return "AWS_CC_MSG"
	case MsgKindPostureCheckInterval:
		return "POSTURE_CHECK_INTERVAL"
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
	case msg == "CR_TEXT" || strings.HasPrefix(msg, "CR_TEXT,") || strings.HasPrefix(msg, "CR_TEXT:"):
		return MsgKindCRText
	case strings.HasPrefix(msg, "AWS_CC_MSG,"):
		return MsgKindAWSCC
	case strings.HasPrefix(msg, "CRV1::POSTURE_CHECK_INTERVAL::"):
		return MsgKindPostureCheckInterval
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
	// DynamicChallenge describes authentication challenge metadata. Secret
	// fields are kept in a distinct value and must not be logged.
	DynamicChallenge *DynamicChallenge
	// AWSCC contains safe fragment metadata for an AWS_CC_MSG. The fragment
	// itself remains only in Raw and must not be logged.
	AWSCC *AWSCCMetadata
	// PostureCheckIntervalSeconds is set for a posture refresh directive.
	PostureCheckIntervalSeconds *uint64
}

// AWSCCMetadata contains the non-secret header fields of an AWS device-posture
// response fragment.
type AWSCCMetadata struct {
	TimestampMicros uint64
	FragmentCount   uint64
	FragmentIndex   uint64
	FragmentBytes   int
}

// DynamicChallengeKind identifies a published OpenVPN dynamic-challenge wire
// form without exposing its authentication material.
type DynamicChallengeKind int

const (
	// DynamicChallengeCRV1 is an AUTH_FAILED,CRV1 challenge.
	DynamicChallengeCRV1 DynamicChallengeKind = iota + 1
	// DynamicChallengeText is a CR_TEXT application message.
	DynamicChallengeText
)

// DynamicChallenge holds parsed dynamic-authentication data with safe metadata
// separated from sensitive server-provided values.
type DynamicChallenge struct {
	Metadata DynamicChallengeMetadata
	Secrets  DynamicChallengeSecrets
}

// DynamicChallengeMetadata contains fields safe for logs and telemetry.
type DynamicChallengeMetadata struct {
	Kind             DynamicChallengeKind
	Flags            []string
	ResponseRequired bool
	Echo             bool
	PromptPresent    bool
}

// DynamicChallengeSecrets contains untrusted authentication material. None of
// these fields may be placed in logs, events, or generic errors.
type DynamicChallengeSecrets struct {
	StateID  string
	Username string
	Prompt   string
}

func parseDynamicCRV1(msg string) (*DynamicChallenge, error) {
	const prefix = "AUTH_FAILED,CRV1:"
	if !strings.HasPrefix(msg, prefix) {
		return nil, fmt.Errorf("saml: not a CRV1 dynamic challenge")
	}
	fields := strings.SplitN(msg[len(prefix):], ":", 4)
	if len(fields) != 4 {
		return nil, fmt.Errorf("saml: malformed CRV1 dynamic challenge")
	}
	if fields[1] == "" {
		return nil, fmt.Errorf("saml: malformed CRV1 dynamic challenge (empty state)")
	}
	d := &DynamicChallenge{
		Metadata: DynamicChallengeMetadata{
			Kind:          DynamicChallengeCRV1,
			Flags:         splitChallengeFlags(fields[0]),
			PromptPresent: fields[3] != "",
		},
		Secrets: DynamicChallengeSecrets{StateID: fields[1], Username: fields[2], Prompt: fields[3]},
	}
	for _, flag := range d.Metadata.Flags {
		switch flag {
		case "R":
			d.Metadata.ResponseRequired = true
		case "E":
			d.Metadata.Echo = true
		}
	}
	return d, nil
}

func splitChallengeFlags(value string) []string {
	var flags []string
	for _, flag := range strings.Split(value, ",") {
		if flag == "R" || flag == "E" {
			flags = append(flags, flag)
		}
	}
	return flags
}

// ParseControlMsg classifies and, for CRV1 messages, fully parses a raw
// control-channel message.  msg may include a trailing NUL byte.
func ParseControlMsg(msg string) (*ControlMessage, error) {
	stripped := strings.TrimRight(msg, "\x00")
	kind := ClassifyMsg(stripped)

	cm := &ControlMessage{Kind: kind, Raw: stripped}
	if kind == MsgKindAuthFailedCRV1 {
		dynamic, err := parseDynamicCRV1(stripped)
		if err != nil {
			return nil, err
		}
		cm.DynamicChallenge = dynamic
		ch, err := ParseCRV1(stripped)
		if err != nil {
			return nil, err
		}
		cm.Challenge = ch
	} else if kind == MsgKindCRText {
		prompt := ""
		if len(stripped) > len("CR_TEXT") {
			prompt = stripped[len("CR_TEXT")+1:]
		}
		cm.DynamicChallenge = &DynamicChallenge{
			Metadata: DynamicChallengeMetadata{Kind: DynamicChallengeText, PromptPresent: prompt != ""},
			Secrets:  DynamicChallengeSecrets{Prompt: prompt},
		}
	} else if kind == MsgKindAWSCC {
		fields := strings.SplitN(stripped, ",", 5)
		if len(fields) != 5 {
			return nil, fmt.Errorf("saml: malformed AWS_CC_MSG header")
		}
		timestamp, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("saml: malformed AWS_CC_MSG timestamp")
		}
		count, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil || count == 0 {
			return nil, fmt.Errorf("saml: malformed AWS_CC_MSG fragment count")
		}
		index, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil || index >= count {
			return nil, fmt.Errorf("saml: malformed AWS_CC_MSG fragment index")
		}
		cm.AWSCC = &AWSCCMetadata{
			TimestampMicros: timestamp,
			FragmentCount:   count,
			FragmentIndex:   index,
			FragmentBytes:   len(fields[4]),
		}
	} else if kind == MsgKindPostureCheckInterval {
		value := strings.TrimPrefix(stripped, "CRV1::POSTURE_CHECK_INTERVAL::")
		seconds, err := strconv.ParseUint(value, 10, 64)
		if err != nil || seconds == 0 {
			return nil, fmt.Errorf("saml: malformed posture check interval")
		}
		cm.PostureCheckIntervalSeconds = &seconds
	}
	return cm, nil
}

// ReadControlMsg reads one NUL-terminated control message from r (typically a
// *tls.Conn) and returns the classified ControlMessage.
// At most maxBytes payload bytes are read; pass 0 to use
// MaxControlMessageBytes. The reader may return a message in any number of
// fragments; bytes after the first NUL terminator are left unread.
func ReadControlMsg(r io.Reader, maxBytes int) (*ControlMessage, error) {
	if maxBytes <= 0 {
		maxBytes = MaxControlMessageBytes
	}
	buf := make([]byte, 0, min(maxBytes, 4096))
	var one [1]byte
	byteReader, readsBytes := r.(io.ByteReader)
	for {
		var n int
		var err error
		if readsBytes {
			one[0], err = byteReader.ReadByte()
			if err == nil {
				n = 1
			}
		} else {
			n, err = r.Read(one[:])
		}
		if n > 0 {
			if one[0] == 0 {
				return ParseControlMsg(string(buf))
			}
			if len(buf) == maxBytes {
				return nil, fmt.Errorf("saml: control message exceeds %d bytes", maxBytes)
			}
			buf = append(buf, one[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(buf) > 0 {
				return ParseControlMsg(string(buf))
			}
			return nil, fmt.Errorf("saml: ReadControlMsg: %w", err)
		}
		if n == 0 {
			return nil, fmt.Errorf("saml: ReadControlMsg: %w", io.ErrNoProgress)
		}
	}
}

// WriteControlMsg writes one NUL-terminated application message to the
// OpenVPN TLS control channel. The message must not already contain NUL.
// Pass maxBytes <= 0 to enforce MaxControlMessageBytes.
func WriteControlMsg(w io.Writer, message string, maxBytes int) error {
	if maxBytes <= 0 {
		maxBytes = MaxControlMessageBytes
	}
	if strings.IndexByte(message, 0) >= 0 {
		return fmt.Errorf("saml: control message contains NUL")
	}
	if len(message) > maxBytes {
		return fmt.Errorf("saml: control message exceeds %d bytes", maxBytes)
	}
	wire := message + "\x00"
	n, err := io.WriteString(w, wire)
	if err != nil {
		return fmt.Errorf("saml: write control message: %w", err)
	}
	if n != len(wire) {
		return fmt.Errorf("saml: write control message: %w", io.ErrShortWrite)
	}
	return nil
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
	// Deprecated: use Kind.
	Msg string
	// Kind is the non-sensitive classification of the server outcome.
	Kind MsgKind
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
		return &SessionExpiredError{Msg: kind, Kind: ClassifyMsg(msg)}
	}
	return fmt.Errorf("saml: authentication failed (%s)", kind)
}
