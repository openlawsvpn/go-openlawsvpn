// Package testenv manages the mock openvpn3-core server for integration tests.
//
// Two execution modes are supported:
//
//   - Docker mode (default): pulls and runs the mock server container.
//   - Binary mode: runs the pre-built mock-server binary directly.
//     Set Config.Binary to the path of the binary, or set the
//     MOCK_SERVER_BIN environment variable.
//
// Usage:
//
//	func TestMain(m *testing.M) {
//	    srv, err := testenv.Start(testenv.Config{})
//	    if err != nil { log.Fatal(err) }
//	    defer srv.Stop()
//	    os.Exit(m.Run())
//	}
//
// All integration tests must be tagged //go:build integration so that
// `go test ./...` (without -tags=integration) skips them and requires no
// Docker daemon or binary.
package testenv

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Image is the Docker image name for the mock server.
const Image = "ghcr.io/openlawsvpn/ovpn3-mock-server:latest"

// MockServerEvent is one structured log line emitted by the mock server.
type MockServerEvent struct {
	TS     int64  `json:"ts"`
	Event  string `json:"event"`
	Detail string `json:"detail"`
}

// AuthPacketInfo holds the fields logged by the mock server in an
// "auth_packet_recv" event.  These are the plaintext values of the
// key-method-2 auth packet the client sent over TLS.
type AuthPacketInfo struct {
	TotalBytes     int    `json:"total_bytes"`
	Options        string `json:"options"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	PasswordLen    int    `json:"password_len"`
	PasswordPrefix string `json:"password_prefix"`
	PeerInfo       string `json:"peer_info"`
}

// Config controls how the mock server is started.
type Config struct {
	// CRV1Mode, when true, starts the server in AUTH_FAILED,CRV1 mode.
	CRV1Mode bool

	// Image overrides the default Docker image name (Docker mode only).
	Image string

	// Binary is the path to the mock-server binary. When set, the server is
	// started as a subprocess instead of via Docker. The MOCK_SERVER_BIN
	// environment variable is used as a fallback when Binary is empty.
	Binary string

	// CertDir is the directory containing ca.crt, server.crt, server.key.
	// Used only in binary mode. Default: resolved from the binary's location.
	CertDir string

	// TCPPort is the host-side TCP port. 0 means pick a free port.
	TCPPort int

	// UDPPort is the host-side UDP port (Docker mode only). 0 means pick one.
	UDPPort int
}

// Server represents a running mock server.
type Server struct {
	containerID string          // set in Docker mode
	proc        *exec.Cmd       // set in binary mode
	logPipe     io.ReadCloser   // set in binary mode
	TCPAddr     string          // "127.0.0.1:<port>"
	UDPAddr     string          // "127.0.0.1:<port>"
	Events      []MockServerEvent
}

// Start launches the mock server and waits until it is ready.
func Start(cfg Config) (*Server, error) {
	bin := cfg.Binary
	if bin == "" {
		bin = os.Getenv("MOCK_SERVER_BIN")
	}
	if bin != "" {
		return startBinary(bin, cfg)
	}
	return startDocker(cfg)
}

// startDocker pulls (if needed) and runs the mock server in Docker.
func startDocker(cfg Config) (*Server, error) {
	img := cfg.Image
	if img == "" {
		img = Image
	}

	tcpPort, err := freePort()
	if err != nil {
		return nil, fmt.Errorf("testenv: find free TCP port: %w", err)
	}
	if cfg.TCPPort != 0 {
		tcpPort = cfg.TCPPort
	}
	udpPort, err := freePort()
	if err != nil {
		return nil, fmt.Errorf("testenv: find free UDP port: %w", err)
	}
	if cfg.UDPPort != 0 {
		udpPort = cfg.UDPPort
	}

	args := []string{
		"run", "--rm", "-d",
		"-p", fmt.Sprintf("127.0.0.1:%d:443/tcp", tcpPort),
		"-p", fmt.Sprintf("127.0.0.1:%d:1194/udp", udpPort),
	}
	if cfg.CRV1Mode {
		args = append(args, "-e", "MOCK_CRV1=1")
	}
	args = append(args, img)

	out, err := exec.Command("docker", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("testenv: docker run: %w", err)
	}

	containerID := strings.TrimSpace(string(out))
	srv := &Server{
		containerID: containerID,
		TCPAddr:     fmt.Sprintf("127.0.0.1:%d", tcpPort),
		UDPAddr:     fmt.Sprintf("127.0.0.1:%d", udpPort),
	}

	if err := srv.waitReady(10 * time.Second); err != nil {
		srv.Stop() //nolint:errcheck
		return nil, fmt.Errorf("testenv: server did not become ready: %w", err)
	}
	return srv, nil
}

// startBinary runs the mock-server binary as a subprocess.
func startBinary(binPath string, cfg Config) (*Server, error) {
	tcpPort, err := freePort()
	if err != nil {
		return nil, fmt.Errorf("testenv: find free TCP port: %w", err)
	}
	if cfg.TCPPort != 0 {
		tcpPort = cfg.TCPPort
	}

	env := os.Environ()
	env = append(env, fmt.Sprintf("MOCK_TCP_PORT=%d", tcpPort))
	if cfg.CRV1Mode {
		env = append(env, "MOCK_CRV1=1")
	}
	if cfg.CertDir != "" {
		env = append(env, "CERT_DIR="+cfg.CertDir)
	}

	cmd := exec.Command(binPath)
	cmd.Env = env

	// Capture stdout (JSON event log).
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("testenv: stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("testenv: start binary: %w", err)
	}

	srv := &Server{
		proc:    cmd,
		logPipe: pipe,
		TCPAddr: fmt.Sprintf("127.0.0.1:%d", tcpPort),
		UDPAddr: "",
	}

	// Stream events in background so the pipe doesn't block.
	// waitReadyBinary consumes from this channel until "ready"; afterwards
	// the background goroutine continues draining into srv.Events.
	eventsCh := make(chan MockServerEvent, 256)
	go func() {
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			var e MockServerEvent
			if err := json.Unmarshal(scanner.Bytes(), &e); err == nil {
				eventsCh <- e
			}
		}
		close(eventsCh)
	}()

	// waitReadyBinary reads from eventsCh and populates srv.Events.
	// After it returns, start a goroutine to drain remaining events.
	if err := srv.waitReadyBinary(10*time.Second, eventsCh); err != nil {
		srv.Stop() //nolint:errcheck
		return nil, fmt.Errorf("testenv: server did not become ready: %w", err)
	}
	go func() {
		for e := range eventsCh {
			srv.Events = append(srv.Events, e)
		}
	}()
	return srv, nil
}

// Stop terminates the mock server.
func (s *Server) Stop() error {
	if s.proc != nil {
		_ = s.proc.Process.Kill()
		return s.proc.Wait()
	}
	if s.containerID != "" {
		out, err := exec.Command("docker", "stop", s.containerID).CombinedOutput()
		if err != nil {
			return fmt.Errorf("testenv: docker stop: %w (output: %s)", err, out)
		}
	}
	return nil
}

// Logs returns the raw stdout of the container as a string (Docker mode only).
func (s *Server) Logs() (string, error) {
	if s.containerID == "" {
		return "", nil
	}
	out, err := exec.Command("docker", "logs", s.containerID).Output()
	if err != nil {
		return "", fmt.Errorf("testenv: docker logs: %w", err)
	}
	return string(out), nil
}

// waitReady polls container logs until a "ready" event appears (Docker mode).
func (s *Server) waitReady(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for ready event")
		case <-time.After(200 * time.Millisecond):
		}

		raw, err := exec.Command("docker", "logs", s.containerID).Output()
		if err != nil {
			continue
		}
		events := parseEvents(raw)
		s.Events = events
		for _, e := range events {
			if e.Event == "ready" {
				return nil
			}
		}
	}
}

// waitReadyBinary waits for the binary process to emit a "ready" event.
// eventsCh is the streaming channel from the binary's stdout goroutine.
func (s *Server) waitReadyBinary(timeout time.Duration, eventsCh <-chan MockServerEvent) error {
	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			return fmt.Errorf("timeout waiting for ready event")
		case e, ok := <-eventsCh:
			if !ok {
				return fmt.Errorf("server stdout closed before ready event")
			}
			s.Events = append(s.Events, e)
			if e.Event == "ready" {
				return nil
			}
		}
	}
}

// parseEvents decodes newline-delimited JSON from mock server stdout.
func parseEvents(raw []byte) []MockServerEvent {
	var events []MockServerEvent
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		var e MockServerEvent
		if err := dec.Decode(&e); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}
		events = append(events, e)
	}
	return events
}

// AuthEvents returns all "auth_packet_recv" events logged by the server,
// parsed into AuthPacketInfo structs for easy assertion in tests.
func (s *Server) AuthEvents() []AuthPacketInfo {
	var out []AuthPacketInfo
	for _, e := range s.Events {
		if e.Event != "auth_packet_recv" {
			continue
		}
		var info AuthPacketInfo
		if err := json.Unmarshal([]byte(e.Detail), &info); err == nil {
			out = append(out, info)
		}
	}
	return out
}

// freePort returns a free TCP port on localhost.
func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port, nil
}
