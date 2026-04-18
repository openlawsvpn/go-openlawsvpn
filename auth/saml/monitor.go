// Package saml — session expiry monitor.
package saml

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

// SessionMonitor watches an active VPN control channel for server-side
// AUTH_FAILED messages that indicate session expiry.
//
// After PUSH_REPLY has been received and the tunnel is up, the VPN server may
// send AUTH_FAILED at any time to signal that the session has expired and must
// be re-authenticated.  SessionMonitor reads control messages from an
// io.Reader in a goroutine and delivers a *SessionExpiredError (or any other
// read error) via its Done channel.
//
// Usage:
//
//	mon := saml.NewSessionMonitor(tlsConn)
//	mon.Start(ctx)
//	// ... use VPN tunnel ...
//	select {
//	case err := <-mon.Done():
//	    if se, ok := err.(*saml.SessionExpiredError); ok {
//	        // re-authenticate
//	    }
//	}
type SessionMonitor struct {
	r    io.Reader
	done chan error
}

// NewSessionMonitor creates a SessionMonitor that reads from r.
// r is typically the TLS connection to the VPN server, read after PUSH_REPLY.
func NewSessionMonitor(r io.Reader) *SessionMonitor {
	return &SessionMonitor{
		r:    r,
		done: make(chan error, 1),
	}
}

// Start begins monitoring in a background goroutine.
// The goroutine stops when ctx is cancelled or when a message is received.
// Errors (including *SessionExpiredError) are delivered via Done().
func (m *SessionMonitor) Start(ctx context.Context) {
	go m.run(ctx)
}

// Done returns a channel that receives exactly one value when monitoring ends.
// A *SessionExpiredError indicates the server sent AUTH_FAILED mid-session.
// io.EOF or context errors indicate normal connection close / cancellation.
func (m *SessionMonitor) Done() <-chan error {
	return m.done
}

func (m *SessionMonitor) run(ctx context.Context) {
	// Read control messages in a loop until ctx is cancelled or the connection
	// closes. openvpn3-core cliproto.hpp dispatches an unlimited stream of
	// mid-session control messages (AUTH_FAILED, keepalive, etc.); reading only
	// one message means later AUTH_FAILED events are silently dropped.
	//
	// Reference: openvpn3-core client/cliproto.hpp control-channel dispatch loop
	// — processes each incoming message in turn via client_proto_base::recv().
	type result struct {
		cm  *ControlMessage
		err error
	}

	for {
		ch := make(chan result, 1)
		go func() {
			cm, err := ReadControlMsg(m.r, 0)
			ch <- result{cm, err}
		}()

		select {
		case <-ctx.Done():
			m.done <- ctx.Err()
			return
		case res := <-ch:
			if res.err != nil {
				if errors.Is(res.err, io.EOF) {
					m.done <- io.EOF
				} else {
					m.done <- fmt.Errorf("saml: session monitor read: %w", res.err)
				}
				return
			}
			switch res.cm.Kind {
			case MsgKindAuthFailed, MsgKindAuthFailedCRV1:
				m.done <- &SessionExpiredError{Msg: res.cm.Raw}
				return
			default:
				// Unknown mid-session message (e.g. server-pushed PUSH_REPLY update,
				// INFO_PRE, restart notice) — log and continue reading.
				// Do not close the tunnel for messages we don't recognise.
				_ = strings.TrimRight(res.cm.Raw, "\x00")
				// continue loop
			}
		}
	}
}
