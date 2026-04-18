// Package ctls implements TLS-over-control-channel for OpenVPN3.
//
// OpenVPN embeds TLS inside its own reliable control channel rather than
// running TLS directly over TCP. This package bridges the gap by exposing
// a net.Conn view of the control-channel byte stream so that crypto/tls can
// run over it unchanged.
//
// Architecture:
//
//	Application
//	    │
//	    ▼
//	ctls.Conn  (crypto/tls.Conn wrapping a ControlTransport)
//	    │
//	    ▼
//	ControlTransport  (net.Conn; goroutine pairs raw TLS bytes with OpenVPN framing)
//	    │
//	    ▼
//	Reliable control channel  (framing + reliable.SendQueue/RecvWindow)
//
// Reference: openvpn3-core ssl/sslctx.hpp, ssl/proto.hpp
package ctls

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ControlTransport is a net.Conn whose Read/Write methods exchange raw TLS
// bytes with the caller while the underlying transport carries those bytes
// inside OpenVPN control-channel packets.
//
// Use NewControlTransport to create one, then pass it to tls.Client or
// tls.Server.  The caller is responsible for running the packet I/O loop
// (see ReadPacket / WritePacket) on the underlying OpenVPN connection.
type ControlTransport struct {
	// inbound delivers reassembled TLS payload bytes to Read callers.
	inbound chan []byte
	// outbound receives bytes from Write callers for framing/sending.
	outbound chan []byte
	// closedCh is closed when Close is called.
	closedCh chan struct{}

	mu         sync.Mutex
	closed     bool
	closeOnce  sync.Once
	localAddr  net.Addr
	remoteAddr net.Addr

	// readBuf holds a partial read from the current inbound chunk.
	readBuf []byte

	readDeadline  time.Time
	writeDeadline time.Time
}

// NewControlTransport creates a ControlTransport with buffered channels.
// bufSize controls how many chunks can be queued in each direction.
func NewControlTransport(local, remote net.Addr, bufSize int) *ControlTransport {
	if bufSize <= 0 {
		bufSize = 64
	}
	return &ControlTransport{
		inbound:    make(chan []byte, bufSize),
		outbound:   make(chan []byte, bufSize),
		closedCh:   make(chan struct{}),
		localAddr:  local,
		remoteAddr: remote,
	}
}

// InjectInbound delivers a reassembled TLS payload chunk to waiting Read calls.
// Called by the OpenVPN framing layer when a complete control packet arrives.
func (t *ControlTransport) InjectInbound(data []byte) error {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return fmt.Errorf("ctls: transport closed")
	}
	chunk := make([]byte, len(data))
	copy(chunk, data)
	t.inbound <- chunk
	return nil
}

// DrainOutbound returns the next chunk written by TLS to send over the wire.
// Returns (nil, io.EOF) when the transport is closed.
func (t *ControlTransport) DrainOutbound() ([]byte, error) {
	chunk, ok := <-t.outbound
	if !ok {
		return nil, io.EOF
	}
	return chunk, nil
}

// OutboundChan returns the raw outbound channel for use in select statements.
func (t *ControlTransport) OutboundChan() <-chan []byte {
	return t.outbound
}

// ClosedChan returns a channel that is closed when Close is called.
// The returned channel is safe to use in select statements.
func (t *ControlTransport) ClosedChan() <-chan struct{} {
	return t.closedCh
}

// Read implements net.Conn. It blocks until TLS bytes arrive via InjectInbound.
func (t *ControlTransport) Read(b []byte) (int, error) {
	for {
		// Serve from leftover buffer first.
		if len(t.readBuf) > 0 {
			n := copy(b, t.readBuf)
			t.readBuf = t.readBuf[n:]
			return n, nil
		}

		// Wait for next chunk with optional deadline.
		var deadline <-chan time.Time
		t.mu.Lock()
		rd := t.readDeadline
		t.mu.Unlock()
		if !rd.IsZero() {
			d := time.Until(rd)
			if d <= 0 {
				return 0, &timeoutError{}
			}
			deadline = time.After(d)
		}

		select {
		case chunk, ok := <-t.inbound:
			if !ok {
				return 0, io.EOF
			}
			n := copy(b, chunk)
			if n < len(chunk) {
				t.readBuf = chunk[n:]
			}
			return n, nil
		case <-deadline:
			return 0, &timeoutError{}
		}
	}
}

// Write implements net.Conn. It queues TLS bytes for pickup by DrainOutbound.
func (t *ControlTransport) Write(b []byte) (int, error) {
	t.mu.Lock()
	closed := t.closed
	wd := t.writeDeadline
	t.mu.Unlock()
	if closed {
		return 0, fmt.Errorf("ctls: transport closed")
	}

	chunk := make([]byte, len(b))
	copy(chunk, b)

	if !wd.IsZero() {
		d := time.Until(wd)
		if d <= 0 {
			return 0, &timeoutError{}
		}
		select {
		case t.outbound <- chunk:
			return len(b), nil
		case <-time.After(d):
			return 0, &timeoutError{}
		}
	}

	t.outbound <- chunk
	return len(b), nil
}

// Close implements net.Conn.
func (t *ControlTransport) Close() error {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		t.mu.Unlock()
		close(t.inbound)
		close(t.outbound)
		close(t.closedCh)
	})
	return nil
}

// LocalAddr implements net.Conn.
func (t *ControlTransport) LocalAddr() net.Addr { return t.localAddr }

// RemoteAddr implements net.Conn.
func (t *ControlTransport) RemoteAddr() net.Addr { return t.remoteAddr }

// SetDeadline implements net.Conn.
func (t *ControlTransport) SetDeadline(tm time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.readDeadline = tm
	t.writeDeadline = tm
	return nil
}

// SetReadDeadline implements net.Conn.
func (t *ControlTransport) SetReadDeadline(tm time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.readDeadline = tm
	return nil
}

// SetWriteDeadline implements net.Conn.
func (t *ControlTransport) SetWriteDeadline(tm time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.writeDeadline = tm
	return nil
}

// Conn is a TLS connection running over a ControlTransport.
// It wraps crypto/tls.Conn and exposes the underlying transport for packet I/O.
type Conn struct {
	*tls.Conn
	transport *ControlTransport
}

// Transport returns the underlying ControlTransport, or nil when the inner
// net.Conn is not a *ControlTransport (e.g. in tests using net.Pipe).
func (c *Conn) Transport() *ControlTransport { return c.transport }

// Dial performs a TLS client handshake over inner (any net.Conn, typically a
// *ControlTransport). cfg must supply the server CA for verification.
func Dial(inner net.Conn, cfg *tls.Config) (*Conn, error) {
	var ct *ControlTransport
	if t, ok := inner.(*ControlTransport); ok {
		ct = t
	}
	tc := tls.Client(inner, cfg)
	if err := tc.Handshake(); err != nil {
		return nil, fmt.Errorf("ctls: client handshake: %w", err)
	}
	return &Conn{Conn: tc, transport: ct}, nil
}

// Accept performs a TLS server handshake over inner (any net.Conn, typically a
// *ControlTransport). cfg must supply the server certificate.
func Accept(inner net.Conn, cfg *tls.Config) (*Conn, error) {
	var ct *ControlTransport
	if t, ok := inner.(*ControlTransport); ok {
		ct = t
	}
	tc := tls.Server(inner, cfg)
	if err := tc.Handshake(); err != nil {
		return nil, fmt.Errorf("ctls: server handshake: %w", err)
	}
	return &Conn{Conn: tc, transport: ct}, nil
}

// TLSState returns the TLS ConnectionState after the handshake completes.
// Callers use this to extract the negotiated cipher suite, peer certificates,
// and (via reflection or a custom crypto/tls build) the TLS master secret for
// OpenVPN key derivation via prf.ExpandKeys.
func (c *Conn) TLSState() tls.ConnectionState {
	return c.Conn.ConnectionState()
}

// NewPipeConnPair returns two ControlTransports wired together via net.Pipe.
// Data written to one is readable from the other, with proper EOF/close
// propagation. Use this for unit tests.
func NewPipeConnPair() (*netPipeTransport, *netPipeTransport) {
	c1, c2 := net.Pipe()
	return &netPipeTransport{c1}, &netPipeTransport{c2}
}

// netPipeTransport wraps net.Pipe's net.Conn with the same interface contract
// as ControlTransport (both implement net.Conn). For tests only.
type netPipeTransport struct {
	net.Conn
}

// timeoutError is a net.Error indicating a deadline exceeded.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "ctls: deadline exceeded" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

