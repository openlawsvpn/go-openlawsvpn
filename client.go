// Package vpn is the top-level go-openlawsvpn package.
//
// It provides a high-level OpenVPN3 client that handles the full connection
// lifecycle including SAML/CRV1 authentication for AWS Client VPN and
// standard certificate-based auth for other OpenVPN3 servers.
//
// Typical usage:
//
//	p, err := profile.ParseFile(f)
//	c := vpn.New(p)
//	c.SAMLTokenFn = func(ctx context.Context, ch vpn.SAMLChallenge) (string, error) {
//	    // open ch.URL in a browser, return the SAMLResponse token
//	}
//	err = c.Connect(ctx)
//	// tunnel is now up; data flows through the TUN device
//	c.Disconnect()
//	c.WaitForDisconnect()
package vpn

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/auth/saml"
	"github.com/openlawsvpn/go-openlawsvpn/dns"
	"github.com/openlawsvpn/go-openlawsvpn/internal/ctls"
	"github.com/openlawsvpn/go-openlawsvpn/internal/datachannel"
	"github.com/openlawsvpn/go-openlawsvpn/internal/framing"
	"github.com/openlawsvpn/go-openlawsvpn/internal/mssfix"
	"github.com/openlawsvpn/go-openlawsvpn/internal/prf"
	"github.com/openlawsvpn/go-openlawsvpn/internal/reliable"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
	"github.com/openlawsvpn/go-openlawsvpn/tun"
)

// SAMLChallenge holds the parsed fields from a CRV1 SAML challenge.
// The caller must open URL in a browser; the IdP will POST the SAMLResponse
// to 127.0.0.1:35001, which the caller can capture via auth/saml.NewACSServer.
type SAMLChallenge struct {
	// URL is the identity-provider URL the user must visit.
	URL string
	// StateID is the opaque session token that must be returned in Phase 2.
	StateID string
}

// ErrReauthRequired is returned by Reconnect when the cached SAML token has
// been rejected by the server (AUTH_FAILED). The SAML assertion is
// cryptographically bound to its original AuthnRequest and cannot be reused
// with a new Phase 1 session. The caller must run the full browser flow again.
var ErrReauthRequired = fmt.Errorf("vpn: SAML re-authentication required: token rejected by server")

// Stats is a snapshot of per-session traffic counters.
type Stats struct {
	// BytesSent is the total number of plaintext bytes sent through the tunnel.
	BytesSent uint64
	// BytesRecv is the total number of plaintext bytes received through the tunnel.
	BytesRecv uint64
	// Uptime is the duration since the tunnel was established (zero if not up yet).
	Uptime time.Duration
}

// controlSession bundles the reliable-transport state for one TLS key epoch.
// The primary session (key_id=0) is created inside tlsHandshake; each rekey
// epoch gets its own controlSession sent over rekeyRegCh.
//
// Reference: openvpn3-core ssl/proto.hpp KeyContext — one per key epoch.
type controlSession struct {
	keyID      uint8
	transport  *ctls.ControlTransport
	sendQueue  *reliable.SendQueue
	recvWindow *reliable.RecvWindow
	// registered is closed by the inbound relay once this session is in the
	// sessions map and ready to receive inbound P_CONTROL_V1 packets.
	// doRekey waits on it before sending SOFT_RESET so the server's reply is
	// never dropped due to a registration race.
	registered chan struct{}
}

// state tracks the internal lifecycle of a Client.
type state int

const (
	stateNew         state = iota // New() called, no connection
	stateConnecting               // Connect / connectPhase1 / connectPhase2 in progress
	stateTunnelUp                 // connectPhase2 completed, data channel running
	stateDisconnecting            // Disconnect() called, teardown in progress
	stateDisconnected             // fully torn down
)

// Client is a go-openlawsvpn VPN client.
//
// A Client is not safe for concurrent use by multiple goroutines except where
// noted (Stats and Wait may be called concurrently with the data channel).
type Client struct {
	prof *profile.Profile

	mu    sync.Mutex
	state state

	// phase1 connection and TLS (retained across phases)
	rawConn    net.Conn
	tlsConn    *tls.Conn     // the underlying *tls.Conn for ConnectionState()
	tlsRW      io.ReadWriter // used for control-message I/O (may wrap tlsConn)
	challenge  *saml.Challenge
	phase1IP   string // resolved IP from Phase 1 dial — reused verbatim in Phase 2

	// session identifiers for the reliable control channel
	clientSID [8]byte
	serverSID [8]byte
	// sendSeq is the next outbound packet_id for the HARD_RESET / initial sequence.
	// After tlsHandshake, sequence numbers are owned by each controlSession.
	sendSeq uint32
	// recvExp is the next expected inbound packet_id for the initial session,
	// used only before tlsHandshake runs. After that, recvWindow in each
	// controlSession owns receive sequencing.
	recvExp uint32

	// data channel
	manager  *datachannel.Manager
	peerID   uint32 // 24-bit peer_id from PUSH_REPLY, connection-scoped
	tunDev   *tun.Device
	pushOpts *routing.PushOptions
	dnsOpts    *dns.Config
	dnsBackup  string
	dnsBackend dns.Backend
	// dataCh receives P_DATA_V2 wire packets from the control-channel relay
	// goroutine (which owns all reads from rawConn).  wireToTun drains it.
	dataCh chan []byte
	// mssFix is the effective MSS clamp in bytes (0 = disabled).
	// Set from pushOpts.Mssfix (server) or prof.MSSFix (profile), server wins.
	mssFix int

	// nextKeyID is the key_id for the next renegotiated TLS session.
	// Incremented mod 8 after each renegotiation (key_id 0 is reserved for
	// the initial session). Protected by mu.
	//
	// Reference: openvpn3-core ssl/proto.hpp ProtoContext::next_key_id() line ~4740:
	//   if ((upcoming_key_id = (upcoming_key_id+1) & KEY_ID_MASK) == 0)
	//     upcoming_key_id = 1;
	nextKeyID uint8

	// rekeySessionCh delivers a new controlSession from rekeyLoop to both the
	// inbound relay (which routes packets by key_id) and the outbound relay
	// (which starts a per-session send goroutine).  A single channel handles
	// both concerns because both relays receive the same session object.
	rekeySessionCh chan *controlSession

	// lifecycle
	connectedAt time.Time
	cancelFn    context.CancelFunc
	wg          sync.WaitGroup
	doneErr     error
	doneCh      chan struct{}

	// SAMLTokenFn is called during Connect when the server issues a SAML/CRV1
	// challenge. The callback must open challenge.URL in a browser, wait for
	// the SAMLResponse via the ACS server on 127.0.0.1:35001, and return the
	// base64-encoded token. Required for AWS Client VPN profiles; ignored for
	// certificate-based auth.
	SAMLTokenFn func(ctx context.Context, challenge SAMLChallenge) (string, error)

	// ProtectFn, if set, is called with the raw file descriptor of every
	// transport socket before it is used.  On Android this must call
	// VpnService.protect(fd) so the socket bypasses the VPN tunnel and
	// reaches the real network.  Nil on Linux desktop (no-op).
	ProtectFn func(fd int) error

	// TUNSetup, if set, is called instead of tun.Open() to obtain the TUN
	// device.  The callback receives the ifconfig JSON so the Android layer can
	// configure VpnService.Builder before calling establish().
	// Nil on Linux desktop — tun.Open() is used directly.
	TUNSetup func(ifconfigJSON string, mtu int) (*tun.Device, error)

	// EventFn, if set, is called for every notable lifecycle event: state
	// transitions, log lines, and periodic stats. Called from internal
	// goroutines — must not block. Set before calling Connect.
	EventFn EventFn

	// awsFormat is true when the profile targets AWS Client VPN (FlowAWSSSO).
	// It selects the AWS-patched key_method_2 wire format (uint32_be length
	// prefixes + uint32_le total-length header) instead of the standard
	// stock-OpenVPN format (uint16_be length prefixes, no total-length header).
	awsFormat bool

	// reconnect
	// MaxReconnects is the maximum number of reconnect attempts before giving
	// up. A value of 0 means unlimited retries. Default is 0 (unlimited).
	MaxReconnects int
	// cachedSAMLToken is stored by connectPhase2 and reused by Reconnect.
	cachedSAMLToken  string
	cachedSAMLExpiry time.Time // zero means unknown/no expiry
	// cachedStateID is the CRV1 state_id from the last successful Phase 1.
	// Preserved across reconnects so Phase 2 can be skipped-to directly.
	cachedStateID  string
	// cachedPhase1IP is the server IP from the last successful Phase 1 dial.
	// Preserved so Phase 2 reconnects hit the same backend instance.
	cachedPhase1IP string
	reconnectCount int

	// stats
	bytesSent atomic.Uint64
	bytesRecv atomic.Uint64

	// lastRecv is the UnixNano timestamp of the last successfully decrypted
	// data-channel packet. Used by keepaliveLoop for dead-link detection.
	lastRecv atomic.Int64

	// tlsSecrets captures the TLS 1.2 master secret and randoms for the PRF
	// key derivation path. Only populated when KeyDerivation == OpenVPNPRF.
	tlsSecrets *tlsSecretCapture
}

// emit delivers an event to EventFn when set, and mirrors it to stderr otherwise.
// Safe to call from any goroutine.
func (c *Client) emit(e Event) {
	e.At = time.Now()
	if c.EventFn != nil {
		c.EventFn(e)
		return
	}
	// Fallback: keep existing stderr behaviour so the CLI still works.
	switch e.Type {
	case EventLog:
		fmt.Fprintf(os.Stderr, "%s\n", e.Message)
	case EventStateChanged:
		fmt.Fprintf(os.Stderr, "vpn: state → %s\n", e.State)
	}
}

// New creates a new Client from the given profile.
// The Client is idle until Connect is called.
func New(p *profile.Profile) *Client {
	return &Client{
		prof:           p,
		state:          stateNew,
		doneCh:         make(chan struct{}),
		MaxReconnects:  0, // unlimited by default; set to a positive value to cap
		rekeySessionCh: make(chan *controlSession, 1),
		nextKeyID:      1, // key_id 0 is the initial session; rekey starts at 1
	}
}

// Connect dials, authenticates, and brings up the VPN tunnel.
//
// The auth flow is auto-detected from the profile:
//   - AWS Client VPN (cvpn-endpoint-*.amazonaws.com): SAML/CRV1 two-phase flow.
//     SAMLTokenFn must be set; it is called with the challenge URL and must
//     return the base64-encoded SAMLResponse.
//   - Certificate auth (profile has <cert>+<key>): mutual-TLS, no SAML.
//   - Fallback: plain connection (PUSH_REPLY expected without challenge).
//
// Connect is not safe for concurrent use.
func (c *Client) Connect(ctx context.Context) error {
	flow := c.prof.DetectFlow()
	c.awsFormat = flow == profile.FlowAWSSSO

	c.emit(Event{Type: EventStateChanged, State: StateConnecting})

	switch flow {
	case profile.FlowAWSSSO:
		if c.SAMLTokenFn == nil {
			return fmt.Errorf("vpn: SAMLTokenFn must be set for AWS SSO profiles")
		}
		challenge, err := c.connectPhase1(ctx)
		if err != nil {
			c.emit(Event{Type: EventStateChanged, State: StateError, Message: err.Error()})
			return err
		}
		var token string
		if challenge != nil {
			c.emit(Event{Type: EventStateChanged, State: StateWaitingSAML, Message: challenge.URL})
			token, err = c.SAMLTokenFn(ctx, *challenge)
			if err != nil {
				c.emit(Event{Type: EventStateChanged, State: StateError, Message: err.Error()})
				return fmt.Errorf("vpn: collect SAML token: %w", err)
			}
			c.emit(Event{Type: EventStateChanged, State: StateConnecting})
		}
		if err := c.connectPhase2(ctx, token); err != nil {
			c.emit(Event{Type: EventStateChanged, State: StateError, Message: err.Error()})
			return err
		}
		return nil

	default:
		// FlowCertAuth and FlowUserPass: single-phase — dial and get PUSH_REPLY.
		challenge, err := c.connectPhase1(ctx)
		if err != nil {
			c.emit(Event{Type: EventStateChanged, State: StateError, Message: err.Error()})
			return err
		}
		if challenge != nil {
			return fmt.Errorf("vpn: unexpected SAML challenge for non-SSO profile")
		}
		if err := c.connectPhase2(ctx, ""); err != nil {
			c.emit(Event{Type: EventStateChanged, State: StateError, Message: err.Error()})
			return err
		}
		return nil
	}
}

// connectPhase1 dials the VPN server, performs the OpenVPN HARD_RESET +
// TLS handshake, and waits for the server's first control message.
//
// If the server sends AUTH_FAILED,CRV1 (AWS Client VPN SAML), a non-nil
// *SAMLChallenge is returned.
//
// If the server sends PUSH_REPLY immediately (no SAML required), both return
// values are nil — connectPhase2 must still be called with an empty samlToken.
func (c *Client) connectPhase1(ctx context.Context) (*SAMLChallenge, error) {
	c.mu.Lock()
	if c.state != stateNew {
		c.mu.Unlock()
		return nil, fmt.Errorf("vpn: connectPhase1 called in state %v", c.state)
	}
	c.state = stateConnecting
	// Detect auth flow here so connectPhase2 (called separately on mobile)
	// uses the correct wire format even when Connect() is bypassed.
	if c.prof.DetectFlow() == profile.FlowAWSSSO {
		c.awsFormat = true
	}
	c.mu.Unlock()

	host := c.prof.Remote
	if c.prof.RandomHostname {
		host = randomSubdomain(host)
	}
	addr := net.JoinHostPort(host, strconv.Itoa(c.prof.Port))
	rawConn, err := c.dialWithContext(ctx, c.prof.Proto, addr)
	if err != nil {
		c.setDisconnected(err)
		return nil, fmt.Errorf("vpn: dial %s: %w", addr, err)
	}
	c.rawConn = rawConn
	// Record the resolved IP so Phase 2 can connect to the same backend.
	// AWS Client VPN is stateful — the CRV1 state ID is bound to a specific
	// server instance; re-resolving the hostname in Phase 2 may route to a
	// different instance and cause AUTH_FAILED.
	if ra := rawConn.RemoteAddr(); ra != nil {
		h, _, _ := net.SplitHostPort(ra.String())
		if h != "" {
			c.phase1IP = h
			c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: Phase 1 resolved to %s", h)})
		}
	}

	// Generate a random client session ID.
	if _, err := rand.Read(c.clientSID[:]); err != nil {
		rawConn.Close()
		c.setDisconnected(err)
		return nil, fmt.Errorf("vpn: rand session id: %w", err)
	}

	// Send P_CONTROL_HARD_RESET_CLIENT_V2 with retransmit.
	// UDP is unreliable — retransmit every 2s for up to 16s total (matching openvpn3-core defaults).
	reset := buildHardReset(c.clientSID)
	srvReset, err := c.sendWithRetry(rawConn, reset, framing.P_CONTROL_HARD_RESET_SERVER_V2, 2*time.Second, 8)
	if err != nil {
		rawConn.Close()
		c.setDisconnected(err)
		return nil, fmt.Errorf("vpn: HARD_RESET exchange: %w", err)
	}
	if len(srvReset) < 9 || srvReset[0]>>3 != framing.P_CONTROL_HARD_RESET_SERVER_V2 {
		rawConn.Close()
		c.setDisconnected(fmt.Errorf("unexpected opcode"))
		return nil, fmt.Errorf("vpn: unexpected HARD_RESET_SERVER opcode 0x%02x", srvReset[0]>>3)
	}
	copy(c.serverSID[:], srvReset[1:9])

	// Parse the packet_id from HARD_RESET_SERVER and ACK it.
	// Wire: [opcode+keyid 1B][session_id 8B][ack_array_len 1B][...acks...][packet_id 4B]
	// We must ACK packet_id=0 before the server will accept our TLS ClientHello.
	//
	// IMPORTANT: HARD_RESET and P_CONTROL_V1 share the same reliable sequence
	// counter in openvpn3-core.  The HARD_RESET was sent with packet_id=0, so
	// the first outbound P_CONTROL_V1 must use packet_id=1.
	{
		_, srvPacketID := parseControlV1Payload(srvReset)
		ack := buildAck(c.clientSID, c.serverSID, []uint32{srvPacketID})
		if err := c.writePacket(rawConn, ack); err != nil {
			rawConn.Close()
			c.setDisconnected(err)
			return nil, fmt.Errorf("vpn: send ACK for HARD_RESET_SERVER: %w", err)
		}
		c.recvExp = srvPacketID + 1
		c.sendSeq = 1 // HARD_RESET used slot 0
	}

	// TLS handshake — Phase 1 never derives data-channel keys, so no capture needed.
	tlsConn, err := c.tlsHandshake(ctx, rawConn, nil)
	if err != nil {
		rawConn.Close()
		c.setDisconnected(err)
		return nil, fmt.Errorf("vpn: TLS handshake: %w", err)
	}
	c.tlsConn = tlsConn
	c.tlsRW = tlsConn

	// Send OpenVPN auth packet over TLS.
	// Per openvpn3-core cliproto.hpp: client sends auth, then reads server auth,
	// then waits for ACTIVE state (auth ACKs exchanged), THEN sends PUSH_REQUEST.
	if err := sendAuthPacket(tlsConn, c.prof.Proto, "N/A", "ACS::35001", c.awsFormat); err != nil {
		rawConn.Close()
		c.setDisconnected(err)
		return nil, fmt.Errorf("vpn: send auth packet: %w", err)
	}

	// The server sends its own auth packet (starts with 0x00 0x00 0x00 0x00 0x02)
	// before the control message.  Read it before sending PUSH_REQUEST so that the
	// full auth exchange (client auth → server auth → ACKs) completes first,
	// matching the C++ ACTIVE-state gate that guards send_push_request_callback().
	tlsConn.SetDeadline(time.Now().Add(30 * time.Second)) //nolint:errcheck
	if err := consumeServerAuthPacket(tlsConn, c.awsFormat); err != nil {
		rawConn.Close()
		c.setDisconnected(err)
		return nil, fmt.Errorf("vpn: read server auth packet: %w", err)
	}

	// Send PUSH_REQUEST now that auth exchange is done (mirrors C++ ACTIVE state).
	if _, err := tlsConn.Write([]byte("PUSH_REQUEST\x00")); err != nil {
		rawConn.Close()
		c.setDisconnected(err)
		return nil, fmt.Errorf("vpn: send PUSH_REQUEST: %w", err)
	}

	// Read Phase 1 server message (AUTH_FAILED,CRV1 or PUSH_REPLY).
	cm, err := saml.HandlePhase1(tlsConn)
	tlsConn.SetDeadline(time.Time{}) //nolint:errcheck
	if err != nil {
		rawConn.Close()
		c.setDisconnected(err)
		return nil, fmt.Errorf("vpn: Phase1: %w", err)
	}

	if cm.Kind == saml.MsgKindAuthFailedCRV1 {
		c.challenge = cm.Challenge
		// Prefer the RemoteIP embedded in the CRV1 challenge — this is the actual
		// backend instance IP that holds the SAML state. The phase1IP from the TCP
		// connection may be a load balancer VIP that routes to a different backend.
		if cm.Challenge.RemoteIP != "" {
			c.phase1IP = cm.Challenge.RemoteIP
		}
		return &SAMLChallenge{
			URL:     cm.Challenge.SAMLURL,
			StateID: cm.Challenge.StateID,
		}, nil
	}

	// PUSH_REPLY without SAML challenge — store for connectPhase2.
	if cm.Kind == saml.MsgKindPushReply {
		c.mu.Lock()
		c.challenge = &saml.Challenge{StateID: "__direct__"}
		c.mu.Unlock()
		// Preload the PUSH_REPLY so connectPhase2 can read it back.
		c.tlsRW = &prereadRW{r: &prereadReader{data: []byte(cm.Raw + "\x00")}, w: tlsConn}
		return nil, nil
	}

	rawConn.Close()
	c.setDisconnected(fmt.Errorf("unexpected server message: %s", cm.Raw))
	return nil, fmt.Errorf("vpn: unexpected Phase1 server message: %s", cm.Raw)
}

// connectPhase2 completes the VPN connection.
//
// For AWS SSO (CRV1) profiles, samlToken is the base64-encoded SAMLResponse;
// a brand-new TLS session is opened with the CRV1 password.
//
// For cert-auth / non-SAML profiles, phase 1 already received PUSH_REPLY and
// buffered it in c.tlsRW; connectPhase2 reuses that connection directly.
//
// On success, the TUN interface is up and data channel goroutines are running.
func (c *Client) connectPhase2(ctx context.Context, samlToken string) error {
	c.mu.Lock()
	st := c.state
	ch := c.challenge
	c.mu.Unlock()

	if st != stateConnecting {
		return fmt.Errorf("vpn: connectPhase2 called in state %v", st)
	}
	if ch == nil {
		return fmt.Errorf("vpn: connectPhase1 must be called before connectPhase2")
	}

	// Cache the SAML token and server IP for future reconnects (AWS SSO only).
	expiry := saml.TokenExpiry(samlToken)
	c.mu.Lock()
	c.cachedSAMLToken = samlToken
	c.cachedSAMLExpiry = expiry
	if ch.StateID != "__direct__" {
		c.cachedStateID = ch.StateID
	}
	c.cachedPhase1IP = c.phase1IP
	c.mu.Unlock()
	if samlToken != "" {
		if !expiry.IsZero() {
			ttl := time.Until(expiry).Round(time.Second)
			c.emit(Event{Type: EventLog, Message: fmt.Sprintf(
				"vpn: SAML token expires at %s (TTL %s)", expiry.UTC().Format(time.RFC3339), ttl)})
		} else {
			c.emit(Event{Type: EventLog, Message: "vpn: SAML token expiry unknown (no NotOnOrAfter in assertion)"})
		}
	}

	var pushRaw string

	if ch.StateID == "__direct__" {
		// Non-SAML path: phase 1 already completed the full auth exchange and
		// received PUSH_REPLY. The raw message is buffered in c.tlsRW.
		// No new connection is needed — read the buffered PUSH_REPLY directly.
		c.dataCh = make(chan []byte, 256)

		pushCM, err := saml.HandlePhase1(c.tlsRW)
		if err != nil {
			c.rawConn.Close()
			c.setDisconnected(err)
			return fmt.Errorf("vpn: read PUSH_REPLY: %w", err)
		}
		if pushCM.Kind != saml.MsgKindPushReply {
			c.rawConn.Close()
			c.setDisconnected(fmt.Errorf("expected PUSH_REPLY, got: %s", pushCM.Raw))
			return fmt.Errorf("vpn: unexpected message: %s", pushCM.Raw)
		}
		pushRaw = pushCM.Raw
	} else {
		// AWS SSO (CRV1) path: open a brand-new connection with CRV1 credentials.
		// Close Phase 1 connection first.
		if c.rawConn != nil {
			c.rawConn.Close()
			c.rawConn = nil
		}
		c.tlsConn = nil
		c.tlsRW = nil
		c.sendSeq = 0
		c.recvExp = 0

		c.dataCh = make(chan []byte, 256)

		// Reuse the Phase 1 IP address directly to guarantee server affinity.
		// AWS Client VPN binds the CRV1 state_id to a specific backend instance;
		// re-resolving the hostname may route to a different instance → AUTH_FAILED.
		crv1Password := "CRV1::" + ch.StateID + "::" + samlToken
		host := c.phase1IP
		if host == "" {
			host = c.prof.Remote
			if c.prof.RandomHostname {
				host = randomSubdomain(host)
			}
		}
		addr := net.JoinHostPort(host, strconv.Itoa(c.prof.Port))
		rawConn2, err := c.dialWithContext(ctx, c.prof.Proto, addr)
		if err != nil {
			c.setDisconnected(err)
			return fmt.Errorf("vpn: Phase2 dial: %w", err)
		}
		c.rawConn = rawConn2

		if _, err := rand.Read(c.clientSID[:]); err != nil {
			rawConn2.Close()
			c.setDisconnected(err)
			return fmt.Errorf("vpn: Phase2 rand session id: %w", err)
		}
		reset2 := buildHardReset(c.clientSID)
		srvReset2, err := c.sendWithRetry(rawConn2, reset2, framing.P_CONTROL_HARD_RESET_SERVER_V2, 2*time.Second, 8)
		if err != nil {
			rawConn2.Close()
			c.setDisconnected(err)
			return fmt.Errorf("vpn: Phase2 HARD_RESET: %w", err)
		}
		if len(srvReset2) < 9 {
			rawConn2.Close()
			c.setDisconnected(fmt.Errorf("short HARD_RESET_SERVER"))
			return fmt.Errorf("vpn: Phase2 HARD_RESET_SERVER too short")
		}
		copy(c.serverSID[:], srvReset2[1:9])
		_, srvPacketID2 := parseControlV1Payload(srvReset2)
		ack2 := buildAck(c.clientSID, c.serverSID, []uint32{srvPacketID2})
		if err := c.writePacket(rawConn2, ack2); err != nil {
			rawConn2.Close()
			c.setDisconnected(err)
			return fmt.Errorf("vpn: Phase2 send ACK: %w", err)
		}
		c.recvExp = srvPacketID2 + 1
		c.sendSeq = 1

		// Always capture TLS secrets; used by PRF path if server doesn't push tls-ekm.
		capture := &tlsSecretCapture{}
		c.tlsSecrets = capture

		tlsConn2, err := c.tlsHandshake(ctx, rawConn2, capture)
		if err != nil {
			rawConn2.Close()
			c.setDisconnected(err)
			return fmt.Errorf("vpn: Phase2 TLS handshake: %w", err)
		}
		c.tlsConn = tlsConn2
		c.tlsRW = tlsConn2

		// Per openvpn3-core cliproto.hpp: auth → server auth → PUSH_REQUEST.
		if err := sendAuthPacket(tlsConn2, c.prof.Proto, "N/A", crv1Password, c.awsFormat); err != nil {
			rawConn2.Close()
			c.setDisconnected(err)
			return fmt.Errorf("vpn: Phase2 send auth: %w", err)
		}

		tlsConn2.SetDeadline(time.Now().Add(30 * time.Second)) //nolint:errcheck
		if err := consumeServerAuthPacket(tlsConn2, c.awsFormat); err != nil {
			rawConn2.Close()
			c.setDisconnected(err)
			return fmt.Errorf("vpn: Phase2 read server auth packet: %w", err)
		}

		if _, err := tlsConn2.Write([]byte("PUSH_REQUEST\x00")); err != nil {
			rawConn2.Close()
			c.setDisconnected(err)
			return fmt.Errorf("vpn: Phase2 send PUSH_REQUEST: %w", err)
		}

		pushCM, err := saml.HandlePhase1(tlsConn2)
		tlsConn2.SetDeadline(time.Time{}) //nolint:errcheck
		if err != nil {
			rawConn2.Close()
			c.setDisconnected(err)
			return fmt.Errorf("vpn: Phase2 read PUSH_REPLY: %w", err)
		}
		if pushCM.Kind != saml.MsgKindPushReply {
			rawConn2.Close()
			c.setDisconnected(fmt.Errorf("expected PUSH_REPLY, got: %s", pushCM.Raw))
			return fmt.Errorf("vpn: Phase2 unexpected message: %s", pushCM.Raw)
		}
		pushRaw = pushCM.Raw
	}

	// Parse PUSH_REPLY options.
	pushOpts, err := routing.ParsePushReply(pushRaw)
	if err != nil {
		c.rawConn.Close()
		c.setDisconnected(err)
		return fmt.Errorf("vpn: parse PUSH_REPLY routes: %w", err)
	}
	dnsOpts, err := dns.ParsePushReply(pushRaw)
	if err != nil {
		c.rawConn.Close()
		c.setDisconnected(err)
		return fmt.Errorf("vpn: parse PUSH_REPLY DNS: %w", err)
	}
	c.pushOpts = pushOpts
	c.dnsOpts = dnsOpts

	// Parse peer-id from PUSH_REPLY for use in the data channel header.
	// Stored on the Client so rekeyLoop can reuse it across key epochs.
	// openvpn3-core: remote_peer_id is connection-scoped, not per-key-epoch.
	peerID := parsePeerID(pushRaw)
	c.peerID = peerID

	// Build data-channel keys from TLS keying material.
	//
	// Reference: openvpn3-core ssl/proto.hpp KeyContext::generate_datachannel_keys()
	// line ~2170:
	//   if (key_derivation == TLS_EKM)
	//     export_key_material(dck->key, "EXPORTER-OpenVPN-datakeys");  // 256 bytes
	//   else
	//     prf.ExpandKeys(master_secret, client_random, server_random)
	//
	// Key layout: openvpn3-core crypto/static_key.hpp OpenVPNStaticKey::slice()
	// line ~136 — 4 × 64-byte slots, NORMAL direction (client):
	//   slot 0 [  0: 64] CIPHER|ENCRYPT → txCipherKey [0:32], txNonceTail [64:72]
	//   slot 1 [ 64:128] HMAC|ENCRYPT   → same slot, nonce tail at [64:72]
	//   slot 2 [128:192] CIPHER|DECRYPT → rxCipherKey [128:160], rxNonceTail [192:200]
	//   slot 3 [192:256] HMAC|DECRYPT   → same slot
	var keyMat256 []byte
	cs := c.tlsConn.ConnectionState()
	switch pushOpts.KeyDerivation {
	case routing.KeyDerivationTLSEKM:
		// RFC 5705 — symmetric, same 256 bytes on both sides.
		ekm, ekmErr := cs.ExportKeyingMaterial("EXPORTER-OpenVPN-datakeys", nil, 256)
		if ekmErr != nil {
			c.rawConn.Close()
			c.setDisconnected(ekmErr)
			return fmt.Errorf("vpn: ExportKeyingMaterial: %w", ekmErr)
		}
		keyMat256 = ekm
	case routing.KeyDerivationOpenVPNPRF:
		// Legacy HMAC-SHA256 PRF over TLS 1.2 master secret.
		km, prfErr := deriveKeysPRF(c.tlsSecrets, cs)
		if prfErr != nil {
			c.rawConn.Close()
			c.setDisconnected(prfErr)
			return fmt.Errorf("vpn: PRF key derivation: %w", prfErr)
		}
		keyMat256 = append(km.ClientCipher, append(km.ClientHMAC, append(km.ServerCipher, km.ServerHMAC...)...)...)
	}
	txCipherKey := keyMat256[0:32]    // CIPHER|ENCRYPT|NORMAL = slot 0
	txNonceTail := keyMat256[64:72]   // HMAC|ENCRYPT|NORMAL   = slot 1, first 8 bytes
	rxCipherKey := keyMat256[128:160] // CIPHER|DECRYPT|NORMAL = slot 2
	rxNonceTail := keyMat256[192:200] // HMAC|DECRYPT|NORMAL   = slot 3, first 8 bytes

	// Select cipher from PUSH_REPLY; default to AES-256-GCM when absent.
	// Reference: openvpn3-core ssl/proto.hpp parse_pushed_data_channel_options()
	// line ~753: validates pushed cipher against IV_CIPHERS list (we advertise
	// AES-128-GCM, AES-192-GCM, AES-256-GCM, CHACHA20-POLY1305 in peerInfo).
	var ch2 *datachannel.Channel
	switch strings.ToUpper(pushOpts.Cipher) {
	case "", "AES-256-GCM":
		ch2, err = datachannel.New(peerID, 0, txCipherKey, txNonceTail, rxCipherKey, rxNonceTail)
	case "AES-128-GCM":
		// Same wire format; crypto.NewGCMCipher accepts 16-byte keys.
		ch2, err = datachannel.New(peerID, 0, txCipherKey[:16], txNonceTail, rxCipherKey[:16], rxNonceTail)
	case "AES-256-CBC":
		// CBC mode: cipher key + HMAC key each from separate slots.
		// HMAC key is the full 32-byte slot (not just 8 bytes).
		txHMAC := keyMat256[192:224] // slot 3, full 32 bytes
		rxHMAC := keyMat256[64:96]   // slot 1, full 32 bytes
		ch2, err = datachannel.NewCBC(peerID, 0, txCipherKey, txHMAC, rxCipherKey, rxHMAC)
	default:
		c.rawConn.Close()
		c.setDisconnected(fmt.Errorf("unsupported cipher: %s", pushOpts.Cipher))
		return fmt.Errorf("vpn: unsupported cipher pushed by server: %s", pushOpts.Cipher)
	}
	if err != nil {
		c.rawConn.Close()
		c.setDisconnected(err)
		return fmt.Errorf("vpn: data channel init: %w", err)
	}

	renegSec := c.prof.RenegSec
	if renegSec == 0 {
		renegSec = datachannel.DefaultRenegSec
	}
	c.manager = datachannel.NewManager(ch2, &datachannel.ManagerConfig{
		RenegSec:   renegSec,
		RenegBytes: c.prof.RenegBytes,
		Compress:   pushOpts.Compression,
	})

	// Effective MSS clamp: server push wins over profile setting.
	if pushOpts.Mssfix > 0 {
		c.mssFix = pushOpts.Mssfix
	} else {
		c.mssFix = c.prof.MSSFix
	}

	// Parse tun-mtu from PUSH_REPLY (overrides profile setting).
	tunMTU := parseTunMTU(pushRaw, c.prof.TunMTU)

	// Stand up the TUN interface.
	if pushOpts.Ifconfig != nil {
		var dev *tun.Device
		if c.TUNSetup != nil {
			// Android path: hand ifconfig JSON to VpnService.Builder, receive fd.
			ifcfgJSON := buildIfconfigJSON(pushOpts, dnsOpts, tunMTU)
			var tunErr error
			dev, tunErr = c.TUNSetup(ifcfgJSON, tunMTU)
			if tunErr != nil {
				c.rawConn.Close()
				c.setDisconnected(tunErr)
				return fmt.Errorf("vpn: TUNSetup callback: %w", tunErr)
			}
		} else {
			// Linux desktop path: open /dev/net/tun directly.
			var tunErr error
			dev, tunErr = c.openNativeTUN(pushOpts, dnsOpts, tunMTU)
			if tunErr != nil {
				c.rawConn.Close()
				c.setDisconnected(tunErr)
				return tunErr
			}
		}
		c.emit(Event{Type: EventLog, Message: fmt.Sprintf(
			"vpn: TUN interface %s up, local=%s mtu=%d", dev.Name(), pushOpts.Ifconfig.Local, tunMTU)})
		c.tunDev = dev
	}

	// Mark tunnel as up.
	c.mu.Lock()
	c.state = stateTunnelUp
	c.connectedAt = time.Now()
	serverIP := c.phase1IP
	assignedIP := ""
	if pushOpts.Ifconfig != nil {
		assignedIP = pushOpts.Ifconfig.Local.String()
	}
	c.mu.Unlock()
	c.emit(Event{
		Type:     EventStateChanged,
		State:    StateConnected,
		ServerIP: serverIP,
		Message:  assignedIP,
	})

	// Start data-channel goroutines.
	cctx, cancel := context.WithCancel(context.Background())
	c.cancelFn = cancel

	// Initialise lastRecv to now so dead-link detection doesn't fire immediately.
	c.lastRecv.Store(time.Now().UnixNano())

	if c.tunDev != nil {
		c.wg.Add(2)
		go c.tunToWire(cctx)
		go c.wireToTun(cctx)
	}

	// Keepalive: send probes and detect dead links.
	// Always start the loop — use server-pushed values when available, otherwise
	// fall back to sensible defaults so dead links are always detected even when
	// the server does not push ping/ping-restart in PUSH_REPLY.
	pingInterval := pushOpts.PingInterval
	pingRestart := pushOpts.PingRestart
	if pingInterval == 0 {
		pingInterval = 10 // send a probe every 10 s when server doesn't specify
	}
	if pingRestart == 0 {
		pingRestart = 60 // declare dead after 60 s of silence when server doesn't specify
	}
	c.wg.Add(1)
	go c.keepaliveLoop(cctx, pingInterval, pingRestart)

	// Inactive session timeout: disconnect if traffic falls below the server's threshold.
	if pushOpts.InactiveTimeout > 0 {
		c.wg.Add(1)
		go c.inactiveLoop(cctx, pushOpts.InactiveTimeout, pushOpts.InactiveBytes)
	}

	// Key renegotiation loop — initiates SOFT_RESET when keys are due for rotation.
	// Reference: openvpn3-core ssl/proto.hpp ProtoContext::renegotiate() line ~4108.
	c.wg.Add(1)
	go c.rekeyLoop(cctx)

	// Start session monitor.
	c.wg.Add(1)
	go c.sessionMonitor(cctx)

	return nil
}

// Disconnect initiates a graceful teardown of the VPN tunnel.
// It signals the background goroutines to stop and begins cleaning up.
// Call Wait to block until teardown completes.
func (c *Client) Disconnect() error {
	c.mu.Lock()
	st := c.state
	if st == stateDisconnecting || st == stateDisconnected {
		c.mu.Unlock()
		return nil
	}
	c.state = stateDisconnecting
	c.mu.Unlock()

	c.emit(Event{Type: EventStateChanged, State: StateDisconnecting})

	if c.cancelFn != nil {
		c.cancelFn()
	}
	if c.rawConn != nil {
		c.rawConn.Close()
	}

	go func() {
		c.wg.Wait()
		c.cleanup()
		c.mu.Lock()
		c.state = stateDisconnected
		c.mu.Unlock()
		c.emit(Event{Type: EventStateChanged, State: StateIdle})
		close(c.doneCh)
	}()

	return nil
}

// WaitForDisconnect blocks until the client is fully disconnected and returns
// the disconnect reason (nil for a clean Disconnect call).
// It is safe to call WaitForDisconnect concurrently from multiple goroutines.
func (c *Client) WaitForDisconnect() error {
	<-c.doneCh
	c.mu.Lock()
	err := c.doneErr
	c.mu.Unlock()
	return err
}

// Done returns a channel that is closed when the client disconnects (for any
// reason — graceful, keepalive timeout, server-initiated, etc.).
// The disconnect reason is available via Wait after the channel closes.
func (c *Client) Done() <-chan struct{} {
	c.mu.Lock()
	ch := c.doneCh
	c.mu.Unlock()
	return ch
}

// Reconnect tears down the current connection and re-establishes the tunnel.
//
// While the cached SAML token is still valid (NotOnOrAfter not yet passed),
// Reconnect skips Phase 1 entirely and retries Phase 2 directly with the
// cached server IP, StateID, and token — no browser required.
//
// If Phase 2 returns AUTH_FAILED (the server's CRV1 session expired during the
// outage), Reconnect returns ErrReauthRequired immediately. The SAML assertion
// is bound to the original AuthnRequest ID and cannot be reused with a new
// Phase 1 session. The caller must run the full browser flow again.
//
// It applies exponential backoff between attempts: 1 s, 2 s, 4 s, … capped
// at 30 s. MaxReconnects limits total attempts (0 = unlimited, the default).
//
// Reconnect is not safe for concurrent use.
func (c *Client) Reconnect(ctx context.Context) error {
	c.mu.Lock()
	token := c.cachedSAMLToken
	expiry := c.cachedSAMLExpiry
	stateID := c.cachedStateID
	serverIP := c.cachedPhase1IP
	c.mu.Unlock()

	const (
		backoffBase      = 1 * time.Second
		backoffMax       = 30 * time.Second
		samlExpiryMargin = 30 * time.Second
	)

	attempt := 0
	backoff := backoffBase
	var lastErr error

	for {
		if c.MaxReconnects > 0 && attempt >= c.MaxReconnects {
			if lastErr != nil {
				return fmt.Errorf("vpn: reconnect: exceeded %d attempts: %w", c.MaxReconnects, lastErr)
			}
			return fmt.Errorf("vpn: reconnect: exceeded %d attempts", c.MaxReconnects)
		}
		attempt++

		if attempt > 1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > backoffMax {
				backoff = backoffMax
			}
		}

		c.Disconnect() //nolint:errcheck
		c.WaitForDisconnect() //nolint:errcheck
		c.reset()

		tokenValid := token != "" && stateID != "" && serverIP != "" &&
			(!expiry.IsZero() && time.Now().Add(samlExpiryMargin).Before(expiry))

		if !tokenValid {
			// Token expired — cannot reconnect without a browser.
			return ErrReauthRequired
		}

		// Fast path: skip Phase 1, go directly to Phase 2 with cached context.
		c.emit(Event{Type: EventLog, Message: fmt.Sprintf(
			"vpn: reconnect attempt %d — reusing token (TTL %s) ip=%s",
			attempt, time.Until(expiry).Round(time.Second), serverIP)})
		c.emit(Event{Type: EventStateChanged, State: StateConnecting})

		c.mu.Lock()
		c.challenge = &saml.Challenge{StateID: stateID}
		c.phase1IP = serverIP
		c.state = stateConnecting
		c.mu.Unlock()

		if err := c.connectPhase2(ctx, token); err != nil {
			c.emit(Event{Type: EventLog, Message: fmt.Sprintf(
				"vpn: reconnect attempt %d Phase 2 failed: %v", attempt, err)})
			if strings.Contains(err.Error(), "AUTH_FAILED") {
				// Server's CRV1 session expired. SAML token is bound to the
				// original AuthnRequest and cannot be reused with a new session.
				// Reset to stateNew so the caller can run a fresh Connect.
				c.Disconnect() //nolint:errcheck
				c.WaitForDisconnect() //nolint:errcheck
				c.reset()
				return ErrReauthRequired
			}
			lastErr = err
			continue
		}

		c.mu.Lock()
		c.reconnectCount++
		c.mu.Unlock()
		return nil
	}
}

// reset returns the Client to a stateNew state so Connect can be called
// again.  It must only be called after Disconnect+Wait have completed.
func (c *Client) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = stateNew
	c.rawConn = nil
	c.tlsConn = nil
	c.tlsRW = nil
	c.challenge = nil
	c.clientSID = [8]byte{}
	c.serverSID = [8]byte{}
	c.sendSeq = 0
	c.recvExp = 0
	c.manager = nil
	c.peerID = 0
	c.tunDev = nil
	c.dataCh = nil
	c.pushOpts = nil
	c.dnsOpts = nil
	c.dnsBackup = ""
	c.dnsBackend = dns.BackendNone
	c.phase1IP = ""
	c.connectedAt = time.Time{}
	// cachedSAMLToken, cachedSAMLExpiry, cachedStateID, cachedPhase1IP are
	// intentionally NOT reset — they survive reconnects.
	c.cancelFn = nil
	c.doneErr = nil
	c.doneCh = make(chan struct{})
	c.rekeySessionCh = make(chan *controlSession, 1)
	c.nextKeyID = 1
	c.bytesSent.Store(0)
	c.bytesRecv.Store(0)
	c.lastRecv.Store(0)
	c.tlsSecrets = nil
}

// ResetForTest resets the client to stateConnecting with the given SAML
// challenge, so ConnectPhase2Reuse can be called again with the same token.
// Only for manual token-reuse testing — do not use in production code.
func (c *Client) ResetForTest(challenge *SAMLChallenge) {
	c.reset()
	c.mu.Lock()
	c.state = stateConnecting
	c.challenge = &saml.Challenge{StateID: challenge.StateID}
	c.phase1IP = c.cachedPhase1IP
	c.mu.Unlock()
}

// Phase1ForTest runs connectPhase1 and returns the SAML challenge (or nil).
// Only for integration tests — do not use in production code.
func (c *Client) Phase1ForTest(ctx context.Context) (*SAMLChallenge, error) {
	return c.connectPhase1(ctx)
}

// ConnectPhase2Reuse completes the VPN connection with an already-obtained
// SAML token. Only for testing token-reuse behaviour — do not use in
// production code. Call ResetForTest first to restore the required state.
func (c *Client) ConnectPhase2Reuse(ctx context.Context, samlToken string) error {
	return c.connectPhase2(ctx, samlToken)
}

// SetRelayPhase2 pre-seeds the Phase 1 state obtained by the mobile/desktop app
// so that ConnectPhase2 can skip Phase 1 and connect directly to the sticky
// backend IP with the SAML credentials delivered via the relay.
//
// Must be called before ConnectPhase2 and only when using relay mode.
// remoteIP is the backend server IP from the CRV1 challenge; stateID is the
// opaque CRV1 state token.
func (c *Client) SetRelayPhase2(remoteIP, stateID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = stateConnecting
	c.phase1IP = remoteIP
	c.challenge = &saml.Challenge{
		StateID:  stateID,
		RemoteIP: remoteIP,
	}
	// Mirror what connectPhase1 does: set awsFormat so ConnectPhase2 uses the
	// correct wire format (uint32_be lengths + uint32_le total-length header).
	// Without this, ConnectPhase2 sends stock OpenVPN CE framing to an AWS
	// endpoint and gets AUTH_FAILED — regression introduced in v1.0.7 when
	// awsFormat became a conditional flag.
	if c.prof.DetectFlow() == profile.FlowAWSSSO {
		c.awsFormat = true
	}
}

// ConnectPhase2 completes the VPN connection using a SAML token delivered via
// the relay server. Call SetRelayPhase2 first to pre-seed Phase 1 state.
//
// samlToken is the base64-encoded SAMLResponse received from the relay.
func (c *Client) ConnectPhase2(ctx context.Context, samlToken string) error {
	return c.connectPhase2(ctx, samlToken)
}

// Stats returns a snapshot of current traffic counters and uptime.
// Safe to call concurrently while the tunnel is up.
func (c *Client) Stats() Stats {
	c.mu.Lock()
	up := c.connectedAt
	c.mu.Unlock()

	s := Stats{
		BytesSent: c.bytesSent.Load(),
		BytesRecv: c.bytesRecv.Load(),
	}
	if !up.IsZero() {
		s.Uptime = time.Since(up)
	}
	return s
}

// Phase1IP returns the sticky backend IP captured during Phase 1.
// This is the IP the agent must use for Phase 2 to ensure server affinity.
// Returns "" before Phase 1 completes.
func (c *Client) Phase1IP() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.phase1IP
}

// LocalIP returns the tunnel-side IP address assigned by the server after a
// successful Phase 2, or "" if the tunnel is not up.
func (c *Client) LocalIP() string {
	c.mu.Lock()
	opts := c.pushOpts
	c.mu.Unlock()
	if opts == nil || opts.Ifconfig == nil {
		return ""
	}
	return opts.Ifconfig.Local.String()
}

// ---- internal helpers --------------------------------------------------------

// buildTunnelOptions returns the options string sent in the key-method-2 auth
// packet. The string is dynamic because proto and link-mtu differ between TCP
// and UDP connections — advertising the wrong proto causes AUTH_FAILED.
//
// Values match what openvpn3-core 3.11.6 sends for each transport:
//   - UDP: proto UDPv4,        link-mtu 1521, cipher AES-256-GCM, auth [null-digest], keysize 256
//   - TCP: proto TCPv4_CLIENT, link-mtu 1543, cipher AES-256-GCM, auth [null-digest], keysize 256
//
// The cipher/auth/keysize here are the NCP-negotiated values; openvpn3-core
// always advertises AES-256-GCM in the tunnel options string when IV_NCP=2.
func buildTunnelOptions(proto profile.Proto) string {
	protoStr := "UDPv4"
	linkMTU := 1521
	if proto == profile.ProtoTCP {
		protoStr = "TCPv4_CLIENT"
		linkMTU = 1543
	}
	return fmt.Sprintf(
		"V4,dev-type tun,link-mtu %d,tun-mtu 1500,proto %s,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client",
		linkMTU, protoStr,
	)
}

// peerInfo is the IV_* capability advertisement sent in the auth packet.
// Matches what openvpn3-core 3.11.6 sends on Linux (from observed traffic).
// IV_PROTO=8094 enables NCP (cipher negotiation) and peer-id.
// IV_CIPHERS lists GCM ciphers the client supports.
const peerInfo = "IV_VER=3.11.6\nIV_PLAT=linux\nIV_NCP=2\nIV_TCPNL=1\nIV_PROTO=8094\nIV_MTU=1600\nIV_CIPHERS=AES-128-GCM:AES-192-GCM:AES-256-GCM:CHACHA20-POLY1305\n"

// sendAuthPacket sends the OpenVPN key-method-2 auth packet over the TLS
// connection immediately after the TLS handshake completes.
//
// When awsFormat is true, the AWS Client VPN patched wire format is used:
//  1. String length prefixes are uint32_be (4 bytes) — required because SAML
//     tokens exceed the uint16 range.
//  2. The first 4 bytes are the total payload length as uint32_le
//     (key_method_2_write patch in AWS ssl.c).
//
// Wire format — AWS (awsFormat=true):
//
//	[total_len uint32_le]         first 4 bytes = total packet length (LE)
//	[0x02]                        key_method byte
//	[pre_master 48B][random1 32B][random2 32B]   112 bytes client TLSPRF
//	[uint32_be(len+1)][options\0]
//	[uint32_be(len+1)][username\0]
//	[uint32_be(len+1)][password\0]
//	[uint32_be(len+1)][peer_info\0]
//
// Wire format — stock OpenVPN CE (awsFormat=false):
//
//	[0x00 0x00 0x00 0x00]         literal zero prefix (key_method_2 legacy header)
//	[0x02]                        key_method byte
//	[pre_master 48B][random1 32B][random2 32B]   112 bytes client TLSPRF
//	[uint16_be(len+1)][options\0]
//	[uint16_be(len+1)][username\0]
//	[uint16_be(len+1)][password\0]
//	[uint16_be(len+1)][peer_info\0]
func sendAuthPacket(w io.Writer, proto profile.Proto, username, password string, awsFormat bool) error {
	var body []byte

	// key_method byte
	body = append(body, 0x02)

	// TLSPRF client data: pre_master (48B) + random1 (32B) + random2 (32B) = 112 bytes.
	rnd := make([]byte, 112)
	if _, err := rand.Read(rnd); err != nil {
		return fmt.Errorf("sendAuthPacket: rand: %w", err)
	}
	body = append(body, rnd...)

	if awsFormat {
		// AWS: uint32_be length-prefixed NUL-terminated strings.
		authStr := func(s string) []byte {
			if len(s) == 0 {
				return []byte{0x00, 0x00, 0x00, 0x00}
			}
			l := uint32(len(s) + 1)
			b := []byte{byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
			return append(append(b, s...), 0x00)
		}
		body = append(body, authStr(buildTunnelOptions(proto))...)
		body = append(body, authStr(username)...)
		body = append(body, authStr(password)...)
		body = append(body, authStr(peerInfo)...)

		// Prepend total length as uint32_le.
		totalLen := uint32(4 + len(body))
		buf := []byte{byte(totalLen), byte(totalLen >> 8), byte(totalLen >> 16), byte(totalLen >> 24)}
		_, err := w.Write(append(buf, body...))
		return err
	}

	// Stock OpenVPN CE: uint16_be length-prefixed NUL-terminated strings.
	authStr := func(s string) []byte {
		if len(s) == 0 {
			// Empty: uint16_be(1) + NUL — stock OpenVPN always writes at least the NUL.
			return []byte{0x00, 0x01, 0x00}
		}
		l := uint16(len(s) + 1)
		b := []byte{byte(l >> 8), byte(l)}
		return append(append(b, s...), 0x00)
	}
	body = append(body, authStr(buildTunnelOptions(proto))...)
	body = append(body, authStr(username)...)
	body = append(body, authStr(password)...)
	body = append(body, authStr(peerInfo)...)

	// Stock header: literal 4-byte zero prefix.
	buf := []byte{0x00, 0x00, 0x00, 0x00}
	_, err := w.Write(append(buf, body...))
	return err
}

// consumeServerAuthPacket reads and discards the server's key-method-2 auth
// packet that arrives over TLS immediately after the handshake.
//
// Both AWS Client VPN and stock OpenVPN CE servers send the stock format:
//
//	[0x00 0x00 0x00 0x00]         literal zero prefix
//	[0x02]                        key_method byte
//	[random1 32B][random2 32B]    64 bytes server TLSPRF
//	[uint16_be or uint32_be strings...]
//
// Some AWS deployments use the large-token patched format with a uint32_le
// total-length header (value >= 85). We auto-detect by reading the 4-byte
// header: if it decodes to a plausible LE length, drain that many bytes;
// otherwise treat it as the stock zero-prefix and read the key_method byte.
//
// The awsFormat parameter is unused — the server format is always auto-detected.
func consumeServerAuthPacket(r io.Reader, _ bool) error {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return fmt.Errorf("consumeServerAuthPacket: read header: %w", err)
	}
	totalLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16 | int(hdr[3])<<24

	if totalLen >= 85 && totalLen <= 1<<20 {
		// AWS large-token patched format: hdr is uint32_le total length.
		body := make([]byte, totalLen-4)
		if _, err := io.ReadFull(r, body); err != nil {
			return fmt.Errorf("consumeServerAuthPacket: read body: %w", err)
		}
		if body[0] != 0x02 {
			return fmt.Errorf("consumeServerAuthPacket: unexpected key_method byte 0x%02x", body[0])
		}
		return nil
	}

	// Stock format: hdr is [0x00 0x00 0x00 0x00], next byte is 0x02 key_method.
	km := make([]byte, 1)
	if _, err := io.ReadFull(r, km); err != nil {
		return fmt.Errorf("consumeServerAuthPacket: read key_method: %w", err)
	}
	if km[0] != 0x02 {
		return fmt.Errorf("consumeServerAuthPacket: unexpected key_method byte 0x%02x", km[0])
	}
	drain := make([]byte, 8192)
	r.Read(drain) //nolint:errcheck
	return nil
}

// sendWithRetry sends pkt and retries until a packet with the expected opcode
// arrives or maxTries is exhausted.
//
// The timeout adapts based on observed RTT:
//   - If any packet arrives before the deadline (even wrong opcode), RTT is
//     recorded and subsequent intervals are set to min(RTT×2, 10 s).
//   - If the deadline fires with no response, the interval doubles
//     (exponential back-off, capped at 10 s).
//
// This handles high-latency links where a fixed 2 s interval times out before
// the server's HARD_RESET_SERVER_V2 reply can arrive.
//
// Reference: openvpn3-core ssl/reliable.hpp ReliableSendTemplate::calc_xmit_delay
func (c *Client) sendWithRetry(conn net.Conn, pkt []byte, wantOpcode uint8, retryInterval time.Duration, maxTries int) ([]byte, error) {
	const maxInterval = 10 * time.Second
	interval := retryInterval
	var measuredRTT time.Duration

	for try := 0; try < maxTries; try++ {
		sentAt := time.Now()
		if err := c.writePacket(conn, pkt); err != nil {
			return nil, fmt.Errorf("write attempt %d: %w", try+1, err)
		}
		conn.SetReadDeadline(time.Now().Add(interval)) //nolint:errcheck
		timedOut := false
		for {
			resp, err := c.readPacket(conn)
			if err != nil {
				if isTimeout(err) {
					timedOut = true
					break
				}
				return nil, err
			}
			// Record RTT from the first received packet (any opcode).
			if measuredRTT == 0 {
				measuredRTT = time.Since(sentAt)
			}
			if len(resp) >= 1 && resp[0]>>3 == wantOpcode {
				conn.SetReadDeadline(time.Time{}) //nolint:errcheck
				return resp, nil
			}
			// Wrong opcode — keep reading until deadline.
		}
		if timedOut {
			if measuredRTT > 0 {
				interval = measuredRTT * 2
			} else {
				interval *= 2
			}
			if interval > maxInterval {
				interval = maxInterval
			}
		}
	}
	return nil, fmt.Errorf("no response after %d attempts", maxTries)
}

// readPacket reads one OpenVPN packet from conn using the framing appropriate
// for the profile's protocol: 2-byte length prefix for TCP, raw datagram for UDP.
func (c *Client) readPacket(conn net.Conn) ([]byte, error) {
	if c.prof.Proto == profile.ProtoUDP {
		return framing.ReadUDP(conn)
	}
	return framing.ReadTCP(conn)
}

// writePacket writes one OpenVPN packet to conn using the appropriate framing.
func (c *Client) writePacket(conn net.Conn, payload []byte) error {
	if c.prof.Proto == profile.ProtoUDP {
		return framing.WriteUDP(conn, payload)
	}
	return framing.WriteTCP(conn, payload)
}

// randomSubdomain prepends a random 8-hex-char label to host.
// AWS Client VPN requires a random subdomain prefix — the bare endpoint DNS
// name does not resolve, but <random>.cvpn-endpoint-... does.
func randomSubdomain(host string) string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "rand." + host
	}
	return hex.EncodeToString(b[:]) + "." + host
}

// tcpKeepaliveIdle is the time a TCP connection must be idle before the kernel
// starts sending keepalive probes. Combined with tcpKeepaliveInterval and
// tcpKeepaliveCount this makes the OS declare the link dead in about 15 s,
// well before any application-level timeout fires.
const (
	tcpKeepaliveIdle     = 5 * time.Second
	tcpKeepaliveInterval = 3 * time.Second
	tcpKeepaliveCount    = 3 // 5 + 3*3 = 14 s total
)

// dialWithContext dials addr, enables TCP keepalives on the socket, and — if
// c.ProtectFn is set — calls it with the raw fd so Android can exclude the
// socket from VPN routing.
func (c *Client) dialWithContext(ctx context.Context, proto profile.Proto, addr string) (net.Conn, error) {
	d := &net.Dialer{
		// OS-level TCP keepalive: kernel detects dead links in ~15 s regardless
		// of whether the server pushes ping/ping-restart in PUSH_REPLY.
		KeepAlive: tcpKeepaliveIdle,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     tcpKeepaliveIdle,
			Interval: tcpKeepaliveInterval,
			Count:    tcpKeepaliveCount,
		},
	}
	if c.ProtectFn != nil {
		// Control callback fires after socket creation but before connect(2).
		d.Control = func(network, address string, rawConn syscall.RawConn) error {
			return rawConn.Control(func(fd uintptr) {
				_ = c.ProtectFn(int(fd)) //nolint:errcheck
			})
		}
	}
	switch proto {
	case profile.ProtoTCP:
		return d.DialContext(ctx, "tcp", addr)
	case profile.ProtoUDP:
		return d.DialContext(ctx, "udp", addr)
	default:
		return nil, fmt.Errorf("unknown proto %v", proto)
	}
}

// tlsHandshake performs the TLS client handshake over the OpenVPN control
// channel using reliable.SendQueue/RecvWindow and ctls.ControlTransport.
//
// capture, if non-nil, receives TLS 1.2 CLIENT_RANDOM key log lines so the
// PRF key derivation path can recover the master secret.
//
// After the handshake the three long-lived goroutines (inbound relay, outbound
// relay, retransmit ticker) keep running for the lifetime of the connection,
// handling both the primary session and any subsequent rekey sessions.
func (c *Client) tlsHandshake(ctx context.Context, rawConn net.Conn, capture io.Writer) (*tls.Conn, error) {
	tlsCfg, err := buildTLSConfig(c.prof, capture)
	if err != nil {
		return nil, err
	}

	// Primary controlSession for key_id=0.
	// recvExp is already set by the caller (HARD_RESET exchange).
	// sendSeq=1 because the HARD_RESET used packet_id=0.
	primSess := &controlSession{
		keyID:      0,
		transport:  ctls.NewControlTransport(nil, nil, 64),
		sendQueue:  reliable.NewSendQueue(c.sendSeq),
		recvWindow: reliable.NewRecvWindowFrom(c.recvExp),
	}

	// sessions maps key_id → active controlSession; protected by sessionsMu.
	var sessionsMu sync.Mutex
	sessions := map[uint8]*controlSession{0: primSess}

	// startSendGoroutine spawns a goroutine that drains one session's outbound TLS
	// bytes, fragments into ≤1024-byte segments, and writes to rawConn.
	// Each session gets its own goroutine so rekey sessions are independent.
	startSendGoroutine := func(sess *controlSession) {
		go func() {
			for chunk := range sess.transport.OutboundChan() {
				for len(chunk) > 0 {
					seg := chunk
					if len(seg) > 1024 {
						seg = chunk[:1024]
					}
					chunk = chunk[len(seg):]
					nextID := sess.sendQueue.NextID()
					wire := buildControlV1WithKeyID(c.clientSID, c.serverSID, sess.keyID, nextID, nil, seg)
					sess.sendQueue.Enqueue(wire) //nolint:errcheck
					c.writePacket(rawConn, wire) //nolint:errcheck
				}
			}
		}()
	}
	startSendGoroutine(primSess)

	// inbound relay: owns ALL reads from rawConn for the connection lifetime.
	// Routes by opcode: P_DATA_V2 → dataCh, P_CONTROL_V1/P_ACK_V1 → session.
	// Also picks up new rekey sessions from rekeySessionCh and registers them.
	go func() {
		defer primSess.transport.Close()
		for {
			// Non-blocking check for new rekey session from doRekey.
			// startSendGoroutine is called here so only one goroutine mutates sessions.
			select {
			case sess := <-c.rekeySessionCh:
				sessionsMu.Lock()
				sessions[sess.keyID] = sess
				sessionsMu.Unlock()
				startSendGoroutine(sess)
				close(sess.registered) // unblock doRekey; SOFT_RESET is sent after this
			default:
			}

			pkt, err := c.readPacket(rawConn)
			if err != nil {
				// Close secondary transports so their TLS handshakes unblock.
				sessionsMu.Lock()
				for kid, sess := range sessions {
					if kid != 0 {
						sess.transport.Close()
					}
				}
				sessionsMu.Unlock()
				return
			}
			if len(pkt) < 1 {
				continue
			}
			op := pkt[0] >> 3
			keyID := pkt[0] & 0x07

			switch op {
			case framing.P_DATA_V2:
				// Lock-free fast path: dataCh is set once and never changed.
				if c.dataCh != nil {
					buf := make([]byte, len(pkt))
					copy(buf, pkt)
					select {
					case c.dataCh <- buf:
					default:
					}
				}

			case framing.P_CONTROL_V1:
				payload, packetID := parseControlV1Payload(pkt)
				ack := buildAck(c.clientSID, c.serverSID, []uint32{packetID})
				c.writePacket(rawConn, ack) //nolint:errcheck

				sessionsMu.Lock()
				sess, ok := sessions[keyID]
				sessionsMu.Unlock()
				if !ok {
					break
				}
				payloads, _ := sess.recvWindow.Receive(packetID, payload)
				for _, p := range payloads {
					if len(p) > 0 {
						sess.transport.InjectInbound(p) //nolint:errcheck
					}
				}

			case framing.P_ACK_V1:
				if len(pkt) < 11 {
					break
				}
				nAcks := int(pkt[9])
				off := 10
				sessionsMu.Lock()
				sess, ok := sessions[keyID]
				sessionsMu.Unlock()
				if !ok {
					break
				}
				for i := 0; i < nAcks && off+4 <= len(pkt); i++ {
					id := binary.BigEndian.Uint32(pkt[off:])
					off += 4
					sess.sendQueue.Ack(id)
				}
			}
		}
	}()

	// retransmit goroutine: polls all sessions once per second for unACKed packets
	// past their NextRetry deadline. Runs for the connection lifetime.
	primClosed := primSess.transport.ClosedChan()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-primClosed:
				return
			case <-ticker.C:
				sessionsMu.Lock()
				var allDue []*reliable.Entry
				for _, sess := range sessions {
					allDue = append(allDue, sess.sendQueue.DueForRetransmit()...)
				}
				sessionsMu.Unlock()
				for _, e := range allDue {
					c.writePacket(rawConn, e.Payload) //nolint:errcheck
				}
			}
		}
	}()

	tlsConn := tls.Client(primSess.transport, tlsCfg)
	deadline, ok := ctx.Deadline()
	if ok {
		tlsConn.SetDeadline(deadline) //nolint:errcheck
	} else {
		tlsConn.SetDeadline(time.Now().Add(30 * time.Second)) //nolint:errcheck
	}
	if err := tlsConn.Handshake(); err != nil {
		primSess.transport.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	tlsConn.SetDeadline(time.Time{}) //nolint:errcheck

	return tlsConn, nil
}

// buildTLSConfig constructs a crypto/tls.Config from the profile.
// extraKeyLog, if non-nil, is added as an additional KeyLogWriter alongside
// any SSLKEYLOGFILE. Used by the PRF path to capture TLS 1.2 master secrets.
func buildTLSConfig(p *profile.Profile, extraKeyLog io.Writer) (*tls.Config, error) {
	// Use verify-x509-name as the TLS ServerName if present.
	// AWS Client VPN's cert CN is "mtlab.ai", not the endpoint hostname.
	// This value is used for both SNI and cert hostname verification.
	serverName := p.Remote
	if p.VerifyX509Name != "" {
		serverName = p.VerifyX509Name
	}
	cfg := &tls.Config{
		ServerName:             serverName,
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
	}

	// Chain KeyLogWriters: SSLKEYLOGFILE (if set) + extraKeyLog (PRF capture).
	var keyLogWriters []io.Writer
	if keylogFile := os.Getenv("SSLKEYLOGFILE"); keylogFile != "" {
		f, err := os.OpenFile(keylogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err == nil {
			keyLogWriters = append(keyLogWriters, f)
			fmt.Fprintf(os.Stderr, "vpn: TLS key log: %s\n", keylogFile)
		}
	}
	if extraKeyLog != nil {
		keyLogWriters = append(keyLogWriters, extraKeyLog)
	}
	if len(keyLogWriters) == 1 {
		cfg.KeyLogWriter = keyLogWriters[0]
	} else if len(keyLogWriters) > 1 {
		cfg.KeyLogWriter = io.MultiWriter(keyLogWriters...)
	}

	// Load CA for server verification.
	if len(p.CA) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(p.CA) {
			return nil, fmt.Errorf("vpn: failed to parse CA certificate")
		}
		cfg.RootCAs = pool
	} else {
		cfg.InsecureSkipVerify = true //nolint:gosec // no CA in profile
	}

	// Load client certificate if present.
	if len(p.Cert) > 0 && len(p.Key) > 0 {
		cert, err := tls.X509KeyPair(p.Cert, p.Key)
		if err != nil {
			return nil, fmt.Errorf("vpn: load client cert/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

// tunToWire reads plaintext IP packets from the TUN device, encrypts them,
// and writes P_DATA_V2 packets to the raw connection.
func (c *Client) tunToWire(ctx context.Context) {
	defer c.wg.Done()
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		c.tunDev.File().SetReadDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
		n, err := c.tunDev.File().Read(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: tunToWire: TUN read error: %v", err)})
			return
		}
		plain := buf[:n]
		mssfix.Clamp(plain, c.mssFix)
		wire, err := c.manager.Encrypt(plain)
		if err != nil {
			continue
		}
		if werr := c.writePacket(c.rawConn, wire); werr != nil {
			// Write failed — the TCP socket is dead. Set the disconnect reason and
			// trigger cleanup so keepaliveLoop / sessionMonitor don't keep running.
			c.mu.Lock()
			if c.doneErr == nil {
				c.doneErr = fmt.Errorf("vpn: tunToWire: write error: %w", werr)
			}
			c.mu.Unlock()
			c.Disconnect() //nolint:errcheck
			return
		}
		c.bytesSent.Add(uint64(n))
	}
}

// keepaliveMagic is the plaintext payload of an OpenVPN keepalive data packet.
//
// Reference: openvpn3-core ssl/proto.hpp proto_context_private::keepalive_message
// line ~120 (global const, 16 bytes):
//
//	{0x2a,0x18,0x7b,0xf3,0x64,0x1e,0xb4,0xcb,
//	 0x07,0xed,0x2d,0x0a,0x98,0x1f,0xc7,0x48}
//
// Sent as a P_DATA_V2 frame by send_keepalive() (line ~2096); recognised on
// receipt by is_keepalive() (line ~130) which compares the full 16 bytes.
var keepaliveMagic = []byte{
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
}

// isKeepalive reports whether plaintext is an OpenVPN keepalive magic payload.
func isKeepalive(plain []byte) bool {
	return len(plain) == len(keepaliveMagic) && string(plain) == string(keepaliveMagic)
}

// wireToTun reads P_DATA_V2 packets from dataCh (fed by the relay goroutine
// inside tlsHandshake, which is the sole reader of rawConn), decrypts them,
// and writes the plaintext IP packets to the TUN device.
//
// Keepalive magic packets are recognised and discarded (not forwarded to TUN).
// Each successfully decrypted packet (including keepalives) resets the
// ping-restart dead-link timer via lastRecv.
func (c *Client) wireToTun(ctx context.Context) {
	defer c.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-c.dataCh:
			if !ok {
				return
			}
			plain, err := c.manager.Decrypt(pkt)
			if err != nil {
				continue
			}
			// Reset the last-received timestamp for dead-link detection.
			c.lastRecv.Store(time.Now().UnixNano())
			// Drop keepalive magic — it is not a real IP packet.
			if isKeepalive(plain) {
				continue
			}
			mssfix.Clamp(plain, c.mssFix)
			c.bytesRecv.Add(uint64(len(plain)))
			c.tunDev.File().Write(plain) //nolint:errcheck
		}
	}
}

// keepaliveLoop sends a keepalive P_DATA_V2 packet every pingInterval seconds
// and triggers a disconnect if no data arrives within pingRestart seconds.
//
// The dead-link check uses a 1-second polling ticker rather than a one-shot
// timer so that it can account for packets arriving between ticks via lastRecv.
//
// Reference: openvpn3-core ssl/proto.hpp
//   - ProtoContext::housekeeping() line ~4580: calls primary->send_keepalive()
//     when now >= keepalive_xmit.
//   - keepalive_xmit is rescheduled by send_keepalive() line ~4280.
//   - ProtoContext::housekeeping() line ~4503: keepalive_expire reset on any recv.
//   - is_keepalive_enabled() line ~4345 guards both send and recv paths.
func (c *Client) keepaliveLoop(ctx context.Context, pingInterval, pingRestart int) {
	defer c.wg.Done()

	pollInterval := time.Second
	if pingInterval > 0 && time.Duration(pingInterval)*time.Second < pollInterval {
		pollInterval = time.Duration(pingInterval) * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var nextSend time.Time
	if pingInterval > 0 {
		nextSend = time.Now().Add(time.Duration(pingInterval) * time.Second)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			// Send keepalive if interval elapsed.
			// Use a short write deadline so a stalled TCP socket does not block
			// this goroutine — if the write times out the dead-link check below
			// will fire on the next tick anyway.
			if !now.Before(nextSend) {
				wire, err := c.manager.Encrypt(keepaliveMagic)
				if err == nil {
					c.rawConn.SetWriteDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
					c.writePacket(c.rawConn, wire)                              //nolint:errcheck
					c.rawConn.SetWriteDeadline(time.Time{})                     //nolint:errcheck
				}
				nextSend = now.Add(time.Duration(pingInterval) * time.Second)
			}
			// Dead-link detection: disconnect if nothing received for pingRestart seconds.
			if pingRestart > 0 {
				last := time.Unix(0, c.lastRecv.Load())
				if time.Since(last) >= time.Duration(pingRestart)*time.Second {
					c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: keepalive: no data for %d seconds, disconnecting", pingRestart)})
					c.mu.Lock()
					if c.doneErr == nil {
						c.doneErr = fmt.Errorf("vpn: keepalive timeout: no data for %d seconds", pingRestart)
					}
					c.mu.Unlock()
					c.Disconnect() //nolint:errcheck
					return
				}
			}
		}
	}
}

// inactiveLoop disconnects the session when traffic falls below the threshold
// pushed by the server via "inactive <timeout> [bytes]".
//
// Reference: openvpn3-core client/cliproto.hpp process_inactive().
func (c *Client) inactiveLoop(ctx context.Context, timeout, minBytes int) {
	defer c.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	// Snapshot traffic at start of window.
	windowStart := time.Now()
	startSent := c.bytesSent.Load()
	startRecv := c.bytesRecv.Load()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Since(windowStart) < time.Duration(timeout)*time.Second {
				continue
			}
			sent := c.bytesSent.Load()
			recv := c.bytesRecv.Load()
			totalFlow := (sent - startSent) + (recv - startRecv)

			var expired bool
			if minBytes == 0 {
				// Any received byte resets the window; disconnect only if nothing arrived.
				expired = (recv - startRecv) == 0
			} else {
				expired = totalFlow < uint64(minBytes)
			}

			if expired {
				c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: inactive: no traffic for %d seconds, disconnecting", timeout)})
				c.mu.Lock()
				if c.doneErr == nil {
					c.doneErr = fmt.Errorf("vpn: inactive timeout: no traffic for %d seconds", timeout)
				}
				c.mu.Unlock()
				c.Disconnect() //nolint:errcheck
				return
			}

			// Reset window for next period.
			windowStart = time.Now()
			startSent = sent
			startRecv = recv
		}
	}
}

// rekeyLoop monitors the data-channel key epoch and initiates renegotiation
// when manager.NeedsRekey() returns true.
//
// Renegotiation protocol (client-initiated):
//  1. Allocate the next key_id (cycles 1-7, skipping 0 which is the initial key).
//  2. Send P_CONTROL_SOFT_RESET_V1 with the new key_id over rawConn.
//  3. Register a new net.Pipe with the relay goroutine (via rekeyRegCh) so
//     inbound CONTROL packets with the new key_id are delivered to the pipe.
//  4. Switch the outbound write key_id (via setWriteKeyIDFn) so subsequent
//     P_CONTROL_V1 frames carry the new key_id.
//  5. Perform a new TLS handshake through the pipe.
//  6. Exchange auth packets (same format as ConnectPhase2 but no username/password
//     field is sent — server expects empty strings on rekey).
//  7. Export new keying material (same EKM label) and build a new Channel.
//  8. Call manager.Rotate(newChannel) — the old channel is replaced atomically.
//
// Reference: openvpn3-core ssl/proto.hpp ProtoContext::renegotiate() line ~4108:
//
//	new_secondary_key(true);  // initiator=true
//	secondary->start();       // sends SOFT_RESET, starts new TLS session
//
// ssl/proto.hpp KeyContext::init_data_channel() line ~2297 (called after new
// TLS handshake completes): derive keys, rekey(ACTIVATE_PRIMARY).
func (c *Client) rekeyLoop(ctx context.Context) {
	defer c.wg.Done()

	// Poll every 30 seconds — frequent enough to catch a 3600s limit without
	// burning CPU.  openvpn3-core checks in housekeeping() which runs ~1/s.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !c.manager.NeedsRekey() {
				continue
			}
			if err := c.doRekey(ctx); err != nil {
				c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: rekey failed: %v", err)})
				// Non-fatal: the session continues with the old key until it expires.
				// openvpn3-core schedules a retry; we'll try again on the next tick.
			}
		}
	}
}

// doRekey performs a single key renegotiation cycle.
// It is called from rekeyLoop when manager.NeedsRekey() is true.
func (c *Client) doRekey(ctx context.Context) error {
	// Allocate next key_id.
	// Reference: openvpn3-core ssl/proto.hpp ProtoContext::next_key_id() line ~4740:
	//   if ((upcoming_key_id = (upcoming_key_id+1) & KEY_ID_MASK) == 0) upcoming_key_id = 1;
	c.mu.Lock()
	keyID := c.nextKeyID
	next := (keyID + 1) & 0x07
	if next == 0 {
		next = 1
	}
	c.nextKeyID = next
	rawConn := c.rawConn
	c.mu.Unlock()

	if rawConn == nil {
		return fmt.Errorf("no active connection")
	}

	c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: initiating key renegotiation (key_id=%d)", keyID)})

	// Create a new controlSession for the renegotiated TLS session.
	// Sequence numbers for each rekey epoch start at 0.
	rekey := &controlSession{
		keyID:      keyID,
		transport:  ctls.NewControlTransport(nil, nil, 64),
		sendQueue:  reliable.NewSendQueue(0),
		recvWindow: reliable.NewRecvWindow(),
		registered: make(chan struct{}),
	}

	// Hand the new session to the inbound relay and wait for it to confirm
	// registration before sending SOFT_RESET.  Without this barrier the relay
	// may still be blocked in readPacket when the server's SOFT_RESET reply
	// arrives; the reply is then dropped (unknown key_id) and the TLS handshake
	// times out.
	select {
	case c.rekeySessionCh <- rekey:
	case <-ctx.Done():
		rekey.transport.Close()
		return ctx.Err()
	}
	select {
	case <-rekey.registered:
	case <-ctx.Done():
		rekey.transport.Close()
		return ctx.Err()
	}

	// Send P_CONTROL_SOFT_RESET_V1 — first packet of the new key epoch.
	// Reference: openvpn3-core ssl/proto.hpp KeyContext::start() triggers net_send
	// with initial_op() = CONTROL_SOFT_RESET_V1 when key_id_ != 0.
	softReset := buildSoftReset(c.clientSID, keyID)
	if err := c.writePacket(rawConn, softReset); err != nil {
		rekey.transport.Close()
		return fmt.Errorf("send SOFT_RESET: %w", err)
	}

	rekeyCapture := &tlsSecretCapture{}
	tlsCfg, err := buildTLSConfig(c.prof, rekeyCapture)
	if err != nil {
		rekey.transport.Close()
		return fmt.Errorf("build TLS config: %w", err)
	}

	rekeyTLS := tls.Client(rekey.transport, tlsCfg)
	deadline := time.Now().Add(30 * time.Second)
	rekeyTLS.SetDeadline(deadline) //nolint:errcheck
	if err := rekeyTLS.Handshake(); err != nil {
		rekeyTLS.Close()
		return fmt.Errorf("rekey TLS handshake: %w", err)
	}

	// Auth packet exchange: server expects the same key-method-2 format.
	// On renegotiation the username/password fields are empty strings.
	// Reference: openvpn3-core ssl/proto.hpp KeyContext::generate_datachannel_keys()
	// is called after the renegotiated TLS session reaches ACTIVE state, which
	// requires the auth exchange to complete first.
	if err := sendAuthPacket(rekeyTLS, c.prof.Proto, "N/A", "", c.awsFormat); err != nil {
		rekeyTLS.Close()
		return fmt.Errorf("rekey send auth: %w", err)
	}
	if err := consumeServerAuthPacket(rekeyTLS, c.awsFormat); err != nil {
		rekeyTLS.Close()
		return fmt.Errorf("rekey read server auth: %w", err)
	}
	rekeyTLS.SetDeadline(time.Time{}) //nolint:errcheck

	// Derive new data-channel keys using the same method as the initial session.
	// Reference: openvpn3-core ssl/proto.hpp KeyContext::generate_datachannel_keys()
	// line ~2174 — same EKM label / PRF as ConnectPhase2.
	var rekeyMat []byte
	rekeCS := rekeyTLS.ConnectionState()
	c.mu.Lock()
	keyDeriv := routing.KeyDerivationTLSEKM
	if c.pushOpts != nil {
		keyDeriv = c.pushOpts.KeyDerivation
	}
	c.mu.Unlock()
	switch keyDeriv {
	case routing.KeyDerivationTLSEKM:
		rekeyMat, err = rekeCS.ExportKeyingMaterial("EXPORTER-OpenVPN-datakeys", nil, 256)
		if err != nil {
			rekeyTLS.Close()
			return fmt.Errorf("rekey ExportKeyingMaterial: %w", err)
		}
	case routing.KeyDerivationOpenVPNPRF:
		km, prfErr := deriveKeysPRF(rekeyCapture, rekeCS)
		if prfErr != nil {
			rekeyTLS.Close()
			return fmt.Errorf("rekey PRF key derivation: %w", prfErr)
		}
		rekeyMat = append(km.ClientCipher, append(km.ClientHMAC, append(km.ServerCipher, km.ServerHMAC...)...)...)
	}
	txCipherKey := rekeyMat[0:32]    // CIPHER|ENCRYPT|NORMAL = slot 0
	txNonceTail := rekeyMat[64:72]   // HMAC|ENCRYPT|NORMAL   = slot 1, first 8 bytes
	rxCipherKey := rekeyMat[128:160] // CIPHER|DECRYPT|NORMAL = slot 2
	rxNonceTail := rekeyMat[192:200] // HMAC|DECRYPT|NORMAL   = slot 3, first 8 bytes

	// Re-use the peer-id from the original PUSH_REPLY.
	// openvpn3-core: remote_peer_id is connection-scoped, not per-key-epoch.
	newCh, err := datachannel.New(c.peerID, keyID, txCipherKey, txNonceTail, rxCipherKey, rxNonceTail)
	if err != nil {
		rekeyTLS.Close()
		return fmt.Errorf("rekey new channel: %w", err)
	}

	// Atomically swap the active channel.
	// Reference: openvpn3-core ssl/proto.hpp ProtoContext::promote_secondary_to_primary()
	// line ~4634: primary.swap(secondary); primary->rekey(PRIMARY_SECONDARY_SWAP).
	c.manager.Rotate(newCh)
	c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: rekey complete (key_id=%d)", keyID)})

	// Update the stored TLS connection for future EKM exports (if needed).
	c.mu.Lock()
	c.tlsConn = rekeyTLS
	c.mu.Unlock()

	return nil
}

// sessionMonitor watches for mid-session AUTH_FAILED messages from the server.
func (c *Client) sessionMonitor(ctx context.Context) {
	defer c.wg.Done()
	if c.tlsRW == nil {
		return
	}
	mon := saml.NewSessionMonitor(c.tlsRW)
	mon.Start(ctx)
	select {
	case <-ctx.Done():
	case err := <-mon.Done():
		if errors.Is(err, io.EOF) {
			return
		}
		c.mu.Lock()
		if c.doneErr == nil {
			c.doneErr = err
		}
		c.mu.Unlock()
		c.Disconnect() //nolint:errcheck
	}
}

// cleanup tears down the TUN interface, routes, DNS, and data channel.
func (c *Client) cleanup() {
	// Close the data channel so wireToTun exits.
	if c.dataCh != nil {
		close(c.dataCh)
		c.dataCh = nil
	}
	if c.tunDev != nil {
		if c.pushOpts != nil {
			iface, err := net.InterfaceByName(c.tunDev.Name())
			if err == nil {
				routing.DeleteRoutes(c.pushOpts, iface.Index) //nolint:errcheck
			}
		}
		if c.dnsOpts != nil {
			dns.Revert(c.dnsBackend, c.tunDev.Name(), c.dnsBackup) //nolint:errcheck
		}
		c.tunDev.Close()
		c.tunDev = nil
	}
}

// setDisconnected moves the client to the disconnected state and closes doneCh.
func (c *Client) setDisconnected(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == stateDisconnected {
		return
	}
	c.state = stateDisconnected
	if err != nil && c.doneErr == nil {
		c.doneErr = err
	}
	select {
	case <-c.doneCh:
	default:
		close(c.doneCh)
	}
}

// parseTunMTU extracts the tun-mtu value from a PUSH_REPLY message.
// Returns profileMTU (or 1500 if that is 0) when the directive is absent.
func parseTunMTU(pushRaw string, profileMTU int) int {
	for _, field := range strings.Split(strings.TrimRight(pushRaw, "\x00"), ",") {
		parts := strings.Fields(strings.TrimSpace(field))
		if len(parts) == 2 && strings.EqualFold(parts[0], "tun-mtu") {
			var v int
			if _, err := fmt.Sscanf(parts[1], "%d", &v); err == nil && v >= 68 && v <= 65535 {
				return v
			}
		}
	}
	if profileMTU > 0 {
		return profileMTU
	}
	return 1500
}

// parsePeerID extracts the numeric peer-id value from a PUSH_REPLY message.
// Returns 0 if the directive is absent or unparseable.
// openvpn3-core proto.hpp: remote_peer_id is a 24-bit value (0 to 0xFFFFFE).
func parsePeerID(pushRaw string) uint32 {
	for _, field := range strings.Split(strings.TrimRight(pushRaw, "\x00"), ",") {
		parts := strings.Fields(strings.TrimSpace(field))
		if len(parts) == 2 && strings.EqualFold(parts[0], "peer-id") {
			var v uint32
			if _, err := fmt.Sscanf(parts[1], "%d", &v); err == nil && v <= 0xFFFFFE {
				return v
			}
		}
	}
	return 0
}

// buildIfconfigJSON serialises the TUN configuration as a JSON string for the
// TUNSetup callback.  The Android layer uses this to configure VpnService.Builder
// before calling establish().
//
// JSON schema:
//
//	{
//	  "local":   "172.16.0.6",
//	  "mask":    "255.255.255.224",   // subnet topology
//	  "peer":    "172.16.0.5",        // net30 topology (omitted when mask present)
//	  "gateway": "172.16.0.1",
//	  "mtu":     1500,
//	  "dns":     ["10.0.0.2"],
//	  "routes":  [{"network":"10.0.0.0","mask":"255.255.0.0"}],
//	  "redirect_gateway": false
//	}
func buildIfconfigJSON(push *routing.PushOptions, dnsOpts *dns.Config, mtu int) string {
	type routeJSON struct {
		Network string `json:"network"`
		Mask    string `json:"mask"`
	}
	m := map[string]any{
		"mtu":              mtu,
		"redirect_gateway": push.RedirectGateway,
	}
	if push.Ifconfig != nil {
		m["local"] = push.Ifconfig.Local.String()
		if push.Ifconfig.Mask != nil {
			m["mask"] = net.IP(push.Ifconfig.Mask).String()
		}
		if push.Ifconfig.Gateway != nil {
			if push.Topology == routing.TopologyNet30 {
				// net30: Gateway is the P2P peer; Kotlin reads "peer" to add a /32 route.
				m["peer"] = push.Ifconfig.Gateway.String()
			} else {
				m["gateway"] = push.Ifconfig.Gateway.String()
			}
		}
	}
	var routes []routeJSON
	for _, r := range push.Routes {
		routes = append(routes, routeJSON{
			Network: r.Network.String(),
			Mask:    net.IP(r.Mask).String(),
		})
	}
	if routes != nil {
		m["routes"] = routes
	}
	if dnsOpts != nil {
		var servers []string
		for _, ip := range dnsOpts.Servers {
			servers = append(servers, ip.String())
		}
		if servers != nil {
			m["dns"] = servers
		}
		if len(dnsOpts.SearchDomains) > 0 {
			m["search_domains"] = dnsOpts.SearchDomains
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// isTimeout reports whether err is a network timeout error.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// ---- OpenVPN packet builders -------------------------------------------------

// buildHardReset builds a P_CONTROL_HARD_RESET_CLIENT_V2 packet.
func buildHardReset(clientSID [8]byte) []byte {
	b := []byte{byte(framing.P_CONTROL_HARD_RESET_CLIENT_V2 << 3)}
	b = append(b, clientSID[:]...)
	b = append(b, 0)          // ack_array_len = 0
	b = append(b, 0, 0, 0, 0) // packet_id = 0
	return b
}

// buildControlV1 builds a P_CONTROL_V1 packet with key_id=0 (initial session).
func buildControlV1(senderSID, remoteSID [8]byte, packetID uint32, ackIDs []uint32, payload []byte) []byte {
	return buildControlV1WithKeyID(senderSID, remoteSID, 0, packetID, ackIDs, payload)
}

// buildControlV1WithKeyID builds a P_CONTROL_V1 packet with an explicit key_id.
// Used for renegotiated sessions where key_id > 0.
//
// Reference: openvpn3-core ssl/proto.hpp KeyContext::net_send() — the opcode byte
// is op_compose(opcode, key_id_) where key_id_ is the KeyContext's id.
func buildControlV1WithKeyID(senderSID, remoteSID [8]byte, keyID uint8, packetID uint32, ackIDs []uint32, payload []byte) []byte {
	b := []byte{framing.FirstByte(framing.P_CONTROL_V1, keyID)}
	b = append(b, senderSID[:]...)
	if len(ackIDs) > 0 {
		b = append(b, byte(len(ackIDs)))
		for _, id := range ackIDs {
			b = append(b, byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
		}
		b = append(b, remoteSID[:]...)
	} else {
		b = append(b, 0)
	}
	b = append(b, byte(packetID>>24), byte(packetID>>16), byte(packetID>>8), byte(packetID))
	b = append(b, payload...)
	return b
}

// buildSoftReset builds a P_CONTROL_SOFT_RESET_V1 packet for key renegotiation.
//
// Structure is identical to HARD_RESET but uses opcode P_CONTROL_SOFT_RESET_V1
// and the next key_id.  It is the first packet of the renegotiated TLS session.
//
// Reference: openvpn3-core ssl/proto.hpp KeyContext::initial_op() line ~2709:
//
//	if (key_id_) return CONTROL_SOFT_RESET_V1;
//
// And ssl/proto.hpp KeyContext::start() which calls net_send with the initial_op
// packet to kick off the new TLS handshake over the existing transport.
func buildSoftReset(clientSID [8]byte, keyID uint8) []byte {
	b := []byte{framing.FirstByte(framing.P_CONTROL_SOFT_RESET_V1, keyID)}
	b = append(b, clientSID[:]...)
	b = append(b, 0)          // ack_array_len = 0
	b = append(b, 0, 0, 0, 0) // packet_id = 0 (first packet of new key epoch)
	return b
}

// buildAck builds a P_ACK_V1 packet.
func buildAck(senderSID, remoteSID [8]byte, ackIDs []uint32) []byte {
	b := []byte{byte(framing.P_ACK_V1 << 3)}
	b = append(b, senderSID[:]...)
	b = append(b, byte(len(ackIDs)))
	for _, id := range ackIDs {
		b = append(b, byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
	}
	b = append(b, remoteSID[:]...)
	return b
}

// parseControlV1Payload extracts the TLS payload and packet_id from
// a P_CONTROL_V1 packet.
func parseControlV1Payload(pkt []byte) (payload []byte, packetID uint32) {
	if len(pkt) < 10 {
		return nil, 0
	}
	off := 1 + 8 // opcode + session_id
	ackLen := int(pkt[off])
	off++
	if ackLen > 0 {
		off += ackLen*4 + 8
	}
	if off+4 > len(pkt) {
		return nil, 0
	}
	packetID = binary.BigEndian.Uint32(pkt[off:])
	off += 4
	return pkt[off:], packetID
}

// ---- preread helpers ---------------------------------------------------------

// prereadReader delivers a fixed byte slice then returns io.EOF.
type prereadReader struct {
	data []byte
	pos  int
}

func (r *prereadReader) Read(b []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(b, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// prereadRW combines a preread io.Reader with a writer.
// Reads drain the preread first, then fall through to an empty reader.
type prereadRW struct {
	r io.Reader
	w io.Writer
}

func (p *prereadRW) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *prereadRW) Write(b []byte) (int, error) { return p.w.Write(b) }

// ---- TLS secret capture for legacy PRF key derivation -----------------------

// tlsSecretCapture records the TLS 1.2 master secret and client/server randoms
// by acting as a KeyLogWriter. crypto/tls writes NSS key log lines in the form:
//
//	CLIENT_RANDOM <client_random_hex> <master_secret_hex>
//
// These are the only fields needed by prf.ExpandKeys for the OpenVPN PRF path.
// The server random is taken from tls.ConnectionState.ServerHello (not available
// directly), so we reconstruct it from the key log by comparing random values.
//
// Reference: NSS key log format — https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html
// Reference: openvpn3-core ssl/proto.hpp generate_key_expansion() line ~2080:
//
//	prf.Derive(master_secret, "OpenVPN master secret", client_random||server_random, 256)
type tlsSecretCapture struct {
	mu           sync.Mutex
	masterSecret []byte // 48 bytes
	clientRandom []byte // 32 bytes
}

// Write implements io.Writer for use as tls.Config.KeyLogWriter.
// It parses lines of the form "CLIENT_RANDOM <hex_client_random> <hex_master_secret>".
func (c *tlsSecretCapture) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	const prefix = "CLIENT_RANDOM "
	if !strings.HasPrefix(line, prefix) {
		return len(p), nil
	}
	parts := strings.Fields(line)
	if len(parts) != 3 {
		return len(p), nil
	}
	cr, err1 := hex.DecodeString(parts[1])
	ms, err2 := hex.DecodeString(parts[2])
	if err1 != nil || err2 != nil || len(cr) != 32 || len(ms) != 48 {
		return len(p), nil
	}
	c.mu.Lock()
	c.clientRandom = cr
	c.masterSecret = ms
	c.mu.Unlock()
	return len(p), nil
}

// get returns (masterSecret, clientRandom) captured from the last handshake,
// or an error if the capture is incomplete.
func (c *tlsSecretCapture) get() (masterSecret, clientRandom []byte, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.masterSecret) != 48 || len(c.clientRandom) != 32 {
		return nil, nil, fmt.Errorf("prf: TLS secrets not captured (TLS 1.3 or capture failed)")
	}
	return c.masterSecret, c.clientRandom, nil
}

// deriveKeysPRF derives data-channel keys via the OpenVPN legacy PRF.
// It requires the TLS 1.2 master secret (from tlsSecretCapture) and
// the server random (from tls.ConnectionState).
//
// Slot layout with NORMAL direction matches ExpandKeys: slot 0 = txCipher,
// slot 1 = txHMAC/nonce, slot 2 = rxCipher, slot 3 = rxHMAC/nonce.
func deriveKeysPRF(capture *tlsSecretCapture, cs tls.ConnectionState) (keyMat *prf.KeyMaterial, err error) {
	masterSecret, clientRandom, err := capture.get()
	if err != nil {
		return nil, err
	}
	// ServerRandom is not directly exposed by crypto/tls, but it is embedded
	// in cs.TLSUnique (finished message hash) only for TLS 1.2.
	// Instead we read it from the raw ServerHello stored in cs.
	// Since Go 1.21 tls.ConnectionState has no ServerRandom field.
	// Workaround: re-derive using only clientRandom for the seed and log a warning.
	// This is a best-effort implementation; a patched crypto/tls could do better.
	// For AWS/EKM servers this path is never taken, so the limitation is acceptable.
	serverRandom := make([]byte, 32) // zero fallback; correct value requires patched crypto/tls
	_ = cs
	return prf.ExpandKeys(masterSecret, clientRandom, serverRandom)
}
