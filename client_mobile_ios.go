//go:build ios

// iOS-specific wrappers for the go-openlawsvpn client.
//
// gomobile bind compiles with GOOS=darwin and the "ios" build tag set.
// This file is included in gomobile xcframework builds and excluded from
// regular macOS/Linux/desktop builds.
//
// gomobile bind requires that exported types use only basic types and slices;
// channels, maps, and function values are not supported across the language
// boundary.  This file wraps the Client API into a simpler MobileClient type
// that communicates exclusively via strings (JSON for structured data, plain
// error strings for failures).
package vpn

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/tun"
)

// MobileCallbacks is a gomobile interface implemented by the iOS/macOS layer.
//
// gomobile generates an Objective-C protocol from this; the Swift
// PacketTunnelProvider implements it and passes it to NewMobileClient.
type MobileCallbacks interface {
	// Protect excludes the socket identified by fd from VPN routing.
	// On iOS/macOS this calls NEPacketTunnelProvider.socketProtect(socket:).
	// Must return true on success, false on failure.
	Protect(fd int) bool

	// EstablishTUN is called with the VPN network config as a JSON string
	// (see buildIfconfigJSON for the schema) and the negotiated MTU.
	// The Swift PacketTunnelProvider calls setTunnelNetworkSettings and then
	// extracts the TUN fd via (packetFlow as AnyObject).value(forKey:
	// "mTunFileDescriptor"). Return -1 on failure.
	EstablishTUN(ifconfigJSON string, mtu int) int

	// Log receives diagnostic log messages from the Go layer.
	Log(message string)
}

// MobileClient is a gomobile-compatible VPN client.
//
// Usage from iOS/Swift (AWS SSO profile):
//
//	let mc = VpnNewMobileClient(profile.configContent, callbacks)!
//	// start SAML flow — returns JSON {"saml_url":"...","state_id":"..."} or error
//	let result = mc.startSAMLFlow()
//	if result.hasPrefix("{") {
//	    let json = try JSONSerialization.jsonObject(with: result.data(using: .utf8)!)
//	    let samlURL = (json as! [String:String])["saml_url"]!
//	    // open samlURL in browser, collect SAMLResponse via ACS server on :35001
//	    let err = mc.completeSAMLFlow(samlToken)
//	    guard err.isEmpty else { return }
//	} else if !result.isEmpty { return }
//
// For non-SSO profiles (cert-auth) call Connect() directly.
type MobileClient struct {
	inner  *Client
	ctx    context.Context
	cancel context.CancelFunc
	cb     MobileCallbacks
}

// NewMobileClient creates a MobileClient from the .ovpn profile content string.
// cb may be nil (callbacks are skipped — useful in tests).
// Panics (and causes an NSException via gomobile) if the profile cannot be
// parsed; callers should validate the content before calling this.
func NewMobileClient(profileContent string, cb MobileCallbacks) *MobileClient {
	p, err := profile.ParseString(profileContent)
	if err != nil {
		panic("vpn: NewMobileClient: " + err.Error())
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := New(p)

	if cb != nil {
		c.ProtectFn = func(fd int) error {
			if !cb.Protect(fd) {
				return fmt.Errorf("vpn: Protect(%d) returned false", fd)
			}
			return nil
		}

		c.TUNSetup = func(ifconfigJSON string, mtu int) (*tun.Device, error) {
			cb.Log(fmt.Sprintf("vpn: establishing TUN, config=%s", ifconfigJSON))
			fd := cb.EstablishTUN(ifconfigJSON, mtu)
			if fd < 0 {
				return nil, fmt.Errorf("vpn: EstablishTUN returned fd=%d", fd)
			}
			return tun.OpenFd(fd)
		}

		c.EventFn = func(e Event) {
			switch e.Type {
			case EventLog:
				cb.Log(e.Message)
			case EventStateChanged:
				if e.Message != "" {
					cb.Log(fmt.Sprintf("vpn: state → %s: %s", e.State, e.Message))
				} else {
					cb.Log(fmt.Sprintf("vpn: state → %s", e.State))
				}
			}
		}
	}

	return &MobileClient{
		inner:  c,
		ctx:    ctx,
		cancel: cancel,
		cb:     cb,
	}
}

// Connect dials, authenticates, and brings up the VPN tunnel.
//
// For non-SSO profiles (cert auth) this is the only call needed.
// For AWS SSO profiles, use StartSAMLFlow + CompleteSAMLFlow instead.
//
// Returns "" on success, or an error description on failure.
func (m *MobileClient) Connect() string {
	if err := m.inner.Connect(m.ctx); err != nil {
		return err.Error()
	}
	return ""
}

// StartSAMLFlow dials the server and retrieves the SAML challenge.
//
// Return values:
//   - JSON object {"saml_url":"...","state_id":"...","remote_ip":"..."}: SAML challenge.
//     Open saml_url in a browser, collect the SAMLResponse, call CompleteSAMLFlow.
//   - JSON object {} (empty): no SAML challenge — call CompleteSAMLFlow("") to finish.
//   - "error: <message>": connection failure.
func (m *MobileClient) StartSAMLFlow() string {
	challenge, err := m.inner.connectPhase1(m.ctx)
	if err != nil {
		return "error: " + err.Error()
	}
	if challenge == nil {
		return "{}"
	}
	b, err := json.Marshal(map[string]string{
		"saml_url":  challenge.URL,
		"state_id":  challenge.StateID,
		"remote_ip": m.inner.Phase1IP(),
	})
	if err != nil {
		return fmt.Sprintf("error: marshal challenge: %v", err)
	}
	return string(b)
}

// CompleteSAMLFlow finishes the VPN connection after a SAML challenge.
//
// samlToken is the base64-encoded SAMLResponse from the identity provider.
// Pass an empty string when StartSAMLFlow returned "{}" (no SAML challenge).
//
// Returns "" on success, or an error description on failure.
func (m *MobileClient) CompleteSAMLFlow(samlToken string) string {
	if err := m.inner.connectPhase2(m.ctx, samlToken); err != nil {
		return err.Error()
	}
	return ""
}

// Disconnect begins a graceful teardown of the VPN tunnel.
// Returns "" on success, or an error description on failure.
func (m *MobileClient) Disconnect() string {
	m.cancel()
	if err := m.inner.Disconnect(); err != nil {
		return err.Error()
	}
	return ""
}

// WaitForDisconnect blocks until the tunnel is fully torn down.
// Returns "" for a clean disconnect, or an error description otherwise.
// Call this after Disconnect to ensure resources are freed.
func (m *MobileClient) WaitForDisconnect() string {
	if err := m.inner.WaitForDisconnect(); err != nil {
		return err.Error()
	}
	return ""
}

// Stats returns a JSON string with the current tunnel statistics.
// Keys: "bytes_sent" (int), "bytes_recv" (int), "uptime_sec" (int), "local_ip" (string).
func (m *MobileClient) Stats() string {
	s := m.inner.Stats()
	b, err := json.Marshal(map[string]any{
		"bytes_sent": s.BytesSent,
		"bytes_recv": s.BytesRecv,
		"uptime_sec": int64(s.Uptime.Seconds()),
		"local_ip":   m.inner.LocalIP(),
	})
	if err != nil {
		return fmt.Sprintf("vpn: marshal stats: %v", err)
	}
	return string(b)
}
