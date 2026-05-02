// Command openlawsvpn-cli is a minimal CLI for the go-openvpn3 VPN client.
//
// It implements the AWS Client VPN SAML/CRV1 authentication flow and
// brings up a Linux TUN interface with the routes and DNS pushed by the server.
// Non-SAML profiles (cert-auth, user-pass) are also supported via auto-detection.
//
// Usage:
//
//	openlawsvpn-cli -config <path.ovpn> [-saml-token <base64token>]
//	openlawsvpn-cli -relay <token> [-relay-endpoint <wss://...>] [-agent-id <uuid>] [-hostname <name>]
//	openlawsvpn-cli -relay <token> -config <path.ovpn> [...]   # -config optional in relay mode
//
// Flags:
//
//	-config          Path to the .ovpn profile file.
//	                 Required for direct (non-relay) mode.
//	                 Optional in relay mode — the app always sends the profile inside
//	                 the phase2 payload; -config is only used as a fallback if the
//	                 payload carries no ovpn_config.
//	-saml-token      Base64-encoded SAMLResponse.  When omitted, the CLI starts
//	                 an ACS server on 127.0.0.1:35001 and waits for the browser
//	                 callback, or reads the token from standard input if stdin
//	                 is not a TTY.
//	-relay           Organisation token for relay mode.  When set, the CLI connects
//	                 to the relay WebSocket and waits for the mobile/desktop app to
//	                 deliver credentials; Phase 1 and SAML run on the app, not here.
//	-relay-endpoint  Relay WebSocket URL (default: wss://ws.relay.openlawsvpn.com).
//	-agent-id        Stable UUID for this agent (default: random, changes on restart).
//	-hostname        Human-readable label shown in the app (default: os.Hostname).
//	-daemon          Fork to background after the tunnel is up; foreground process
//	                 exits 0 once the VPN is established, 1 on failure.
//	-pidfile         Write the daemon PID to this file (only used with -daemon).
//	-logfile         Redirect daemon stdout+stderr to this file (only with -daemon;
//	                 default: /dev/null).
//
// # Daemon mode
//
// With -daemon the CLI daemonizes after the tunnel is established:
//
//   - The foreground process blocks until the VPN is up, then prints the daemon PID
//     and exits 0.  The shell prompt / CI step returns immediately.
//   - The background process keeps the tunnel alive, handling reconnects and rekeying.
//   - Use -pidfile to record the PID for later cleanup (sudo kill $(cat pidfile)).
//   - Use -logfile to capture background diagnostics.
//
// Example:
//
//	sudo openlawsvpn-cli -relay $TOKEN -daemon \
//	  -pidfile /tmp/openlawsvpn.pid \
//	  -logfile /tmp/openlawsvpn.log
//	# returns once the tunnel is up; VPN runs in background
//
// Build as a fully static binary:
//
//	CGO_ENABLED=0 go build -o openlawsvpn-cli ./cmd/cli
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	vpn "github.com/openlawsvpn/go-openlawsvpn"
	"github.com/openlawsvpn/go-openlawsvpn/auth/saml"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/relay"
)

func main() {
	configPath    := flag.String("config", "", "path to .ovpn profile file (required)")
	samlToken     := flag.String("saml-token", "", "pre-supplied base64 SAMLResponse (skips ACS server)")
	relayToken    := flag.String("relay", "", "organisation token — enables relay mode")
	relayEndpoint := flag.String("relay-endpoint", "wss://ws.relay.openlawsvpn.com", "relay WebSocket URL")
	relayAgentID  := flag.String("agent-id", "", "stable UUID for this agent (default: random)")
	relayHostname := flag.String("hostname", "", "human-readable agent label (default: os.Hostname)")
	daemonMode    := flag.Bool("daemon", false, "fork to background once the tunnel is up")
	pidFile       := flag.String("pidfile", "", "write daemon PID to this file (requires -daemon)")
	logFile       := flag.String("logfile", "", "redirect daemon output to this file (requires -daemon)")
	browserCmd    := flag.String("browser", "", "browser command to open SAML URL (e.g. firefox, chromium); default: xdg-open")
	flag.Parse()

	// Daemon re-exec: when OPENLAWSVPN_READY_FD is set, we are the background
	// child. All flags are inherited via os.Args. We notify the parent through
	// the pipe FD once the tunnel is up, then continue running indefinitely.
	readyFD := 0
	if v := os.Getenv("OPENLAWSVPN_READY_FD"); v != "" {
		fd, err := strconv.Atoi(v)
		if err != nil || fd <= 2 {
			fmt.Fprintln(os.Stderr, "openlawsvpn-cli: invalid OPENLAWSVPN_READY_FD")
			os.Exit(1)
		}
		readyFD = fd
	}

	if *daemonMode && readyFD == 0 {
		// Foreground parent: create a pipe, re-exec self as background child
		// passing the write-end FD, then block until the child signals ready.
		spawnDaemon(*pidFile, *logFile)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Relay mode: -config is optional. The app delivers ovpn_config inside the
	// phase2 payload, so no local profile is needed. If -config is provided it
	// is used as a fallback when the payload carries no config.
	if *relayToken != "" {
		hostname := *relayHostname
		if hostname == "" {
			if h, err := os.Hostname(); err == nil {
				hostname = h
			} else {
				hostname = "unknown"
			}
		}
		var fallbackProfile *profile.Profile
		if *configPath != "" {
			fp, err := profile.ParsePath(*configPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "openlawsvpn-cli: parse config: %v\n", err)
				os.Exit(1)
			}
			fallbackProfile = fp
		}
		runRelayMode(ctx, fallbackProfile, relay.Config{
			Token:    *relayToken,
			Hostname: hostname,
			AgentID:  *relayAgentID,
			Endpoint: *relayEndpoint,
		}, readyFD)
		return
	}

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "openlawsvpn-cli: -config flag is required")
		flag.Usage()
		os.Exit(1)
	}

	p, err := profile.ParsePath(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openlawsvpn-cli: parse config: %v\n", err)
		os.Exit(1)
	}

	client := vpn.New(p)

	remoteDesc := p.Remote
	if p.RandomHostname {
		remoteDesc = "<random>." + p.Remote
	}
	fmt.Fprintf(os.Stderr, "openlawsvpn-cli: connecting to %s:%d (%s)...\n",
		remoteDesc, p.Port, protoName(p.Proto))

	// Wire up the SAML token callback for AWS SSO profiles.
	preSuppliedToken := *samlToken

	client.SAMLTokenFn = func(ctx context.Context, challenge vpn.SAMLChallenge) (string, error) {
		fmt.Printf("openlawsvpn-cli: SAML authentication required\n")
		fmt.Printf("openlawsvpn-cli: Open this URL in your browser:\n\n  %s\n\n", challenge.URL)
		openBrowser(challenge.URL, *browserCmd)

		if preSuppliedToken != "" {
			tok := preSuppliedToken
			preSuppliedToken = "" // consume it — re-auth will go through the ACS flow
			fmt.Fprintf(os.Stderr, "openlawsvpn-cli: SAML token received (%d chars)\n", len(tok))
			return tok, nil
		}

		tok, err := waitForSAMLToken(ctx, challenge, *browserCmd)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(os.Stderr, "openlawsvpn-cli: SAML token received (%d chars)\n", len(tok))
		return tok, nil
	}

	if err := client.Connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "openlawsvpn-cli: connect failed: %v\n", err)
		if isPermissionError(err) {
			fmt.Fprintln(os.Stderr, "openlawsvpn-cli: hint: TUN device requires root — re-run with sudo")
		}
		os.Exit(1)
	}

	local := outboundIP()
	fmt.Fprintf(os.Stderr, "openlawsvpn-cli: tunnel up — local=%s tun=%s\n",
		local, client.LocalIP())
	notifyReady(readyFD, local)

	// Wait for signal or server-initiated disconnect (e.g. keepalive timeout).
	// If the disconnect was caused by a dead link, attempt to reconnect.
	for {
		select {
		case <-ctx.Done():
			// User pressed Ctrl-C or sent SIGTERM — clean exit.
			fmt.Fprintln(os.Stderr, "\nopenlawsvpn-cli: disconnecting...")
			stop()
			if err := client.Disconnect(); err != nil {
				fmt.Fprintf(os.Stderr, "openlawsvpn-cli: disconnect error: %v\n", err)
			}
			if err := client.WaitForDisconnect(); err != nil {
				fmt.Fprintf(os.Stderr, "openlawsvpn-cli: wait error: %v\n", err)
			}
			fmt.Fprintln(os.Stderr, "openlawsvpn-cli: disconnected")
			return
		case <-client.Done():
			reason := client.WaitForDisconnect()
			if reason == nil || ctx.Err() != nil {
				// Clean disconnect or signal — exit.
				fmt.Fprintln(os.Stderr, "openlawsvpn-cli: disconnected")
				return
			}
			// Unclean disconnect (dead link, keepalive timeout, etc.) — reconnect.
			fmt.Fprintf(os.Stderr, "openlawsvpn-cli: tunnel down (%v), reconnecting...\n", reason)
			if err := client.Reconnect(ctx); err != nil {
				if ctx.Err() != nil {
					fmt.Fprintln(os.Stderr, "openlawsvpn-cli: disconnected")
					return
				}
				if errors.Is(err, vpn.ErrReauthRequired) {
					// SAML session expired — run the full browser flow again.
					fmt.Fprintln(os.Stderr, "openlawsvpn-cli: SAML session expired, re-authenticating...")
					if err := client.Connect(ctx); err != nil {
						fmt.Fprintf(os.Stderr, "openlawsvpn-cli: re-auth connect failed: %v\n", err)
						os.Exit(1)
					}
				} else {
					fmt.Fprintf(os.Stderr, "openlawsvpn-cli: reconnect failed: %v\n", err)
					os.Exit(1)
				}
			}
			fmt.Fprintf(os.Stderr, "openlawsvpn-cli: tunnel up — local=%s tun=%s\n",
				outboundIP(), client.LocalIP())
		}
	}
}

// waitForSAMLToken starts the ACS server to catch the browser callback.
// While waiting, pressing Enter reprints the URL and reopens the browser
// (useful when the link was opened in the wrong browser). A non-empty line
// is treated as a pasted SAMLResponse token (fallback for SSH/headless use).
func waitForSAMLToken(ctx context.Context, challenge vpn.SAMLChallenge, browserCmd string) (string, error) {
	acs, err := saml.NewACSServer()
	if err != nil {
		// ACS port unavailable — fall back to stdin.
		fmt.Fprintln(os.Stderr, "openlawsvpn-cli: ACS server unavailable; paste SAMLResponse and press Enter:")
		return readTokenFromStdin()
	}

	fmt.Fprintf(os.Stderr, "openlawsvpn-cli: waiting for SAML callback on 127.0.0.1:%d\n", saml.ACSPort)
	fmt.Fprintln(os.Stderr, "       Press Enter to reopen the URL in your browser, or paste SAMLResponse to skip the browser")

	tokenCh := make(chan string, 1)
	errCh := make(chan error, 1)

	go func() {
		tok, err := acs.Wait(ctx)
		if err != nil {
			errCh <- err
			return
		}
		tokenCh <- tok
	}()

	// Stdin loop: empty Enter = reopen URL, non-empty = pasted token.
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				fmt.Fprintf(os.Stderr, "\nopenlawsvpn-cli: reopening URL...\n  %s\n\n", challenge.URL)
				openBrowser(challenge.URL, browserCmd)
				continue
			}
			select {
			case tokenCh <- line:
			default:
			}
			return
		}
	}()

	select {
	case tok := <-tokenCh:
		return tok, nil
	case err := <-errCh:
		return "", err
	case <-ctx.Done():
		return "", fmt.Errorf("openlawsvpn-cli: SAML wait cancelled: %w", ctx.Err())
	}
}

// readTokenFromStdin reads one line from stdin as the SAML token.
func readTokenFromStdin() (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		tok := scanner.Text()
		if tok == "" {
			return "", fmt.Errorf("openlawsvpn-cli: empty SAMLResponse from stdin")
		}
		return tok, nil
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("openlawsvpn-cli: read stdin: %w", err)
	}
	return "", fmt.Errorf("openlawsvpn-cli: EOF on stdin before SAMLResponse")
}

// openBrowser opens url in the specified browser (or xdg-open if empty).
// Failure is silently ignored — the user can always open the URL manually.
func openBrowser(url, browserCmd string) {
	bin := "xdg-open"
	if browserCmd != "" {
		bin = browserCmd
	}
	cmd := exec.Command(bin, url)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err == nil {
		go cmd.Wait() //nolint:errcheck
	}
}

// isPermissionError reports whether err looks like a permission/privilege failure.
func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "permission denied") ||
		strings.Contains(s, "operation not permitted") ||
		strings.Contains(s, "CAP_NET_ADMIN")
}

// runRelayMode connects to the relay server and waits for the mobile/desktop app to deliver
// Phase 2 credentials. Phase 1 and the SAML browser flow run on the app — not here.
// runRelayMode starts the relay agent. fallback may be nil — the app always sends
// ovpn_config in the phase2 payload, so a local profile is not required.
func runRelayMode(ctx context.Context, fallback *profile.Profile, cfg relay.Config, readyFD int) {
	cfg.Log = func(msg string) { fmt.Fprintln(os.Stderr, msg) }

	// agentPtr is set just after relay.New returns so the OnPhase2 closure can
	// call SendStatus without a circular dependency.
	var agentPtr *relay.Agent

	// activeClient is set inside OnPhase2 so OnDisconnect can call Disconnect()
	// on the running VPN client.
	var activeClientMu sync.Mutex
	var activeClient *vpn.Client

	cfg.OnDisconnect = func() {
		activeClientMu.Lock()
		c := activeClient
		activeClientMu.Unlock()
		if c != nil {
			fmt.Fprintln(os.Stderr, "openlawsvpn-cli: relay: server requested disconnect")
			c.Disconnect() //nolint:errcheck
		}
	}

	cfg.OnPhase2 = func(phaseCtx context.Context, payload relay.Phase2Payload) error {
		fmt.Fprintf(os.Stderr, "openlawsvpn-cli: relay: received phase2 for session %s\n", payload.SessionID)

		// Payload config takes precedence; fall back to local profile if absent.
		var connProfile *profile.Profile
		if payload.OvpnConfig != "" {
			cp, err := profile.ParseString(payload.OvpnConfig)
			if err != nil {
				return fmt.Errorf("relay: parse ovpn_config from payload: %w", err)
			}
			connProfile = cp
		} else if fallback != nil {
			connProfile = fallback
		} else {
			return fmt.Errorf("relay: no ovpn_config in payload and no -config flag provided")
		}

		client := vpn.New(connProfile)
		activeClientMu.Lock()
		activeClient = client
		activeClientMu.Unlock()
		defer func() {
			activeClientMu.Lock()
			activeClient = nil
			activeClientMu.Unlock()
		}()

		// Pre-load the Phase 1 state that the app already obtained so connectPhase2
		// skips Phase 1 entirely and connects directly to the sticky backend IP.
		client.SetRelayPhase2(payload.RemoteIP, payload.StateID)

		if err := client.ConnectPhase2(phaseCtx, payload.SAMLResponse); err != nil {
			return fmt.Errorf("relay: phase2 connect: %w", err)
		}
		localIP := outboundIP()
		fmt.Fprintf(os.Stderr, "openlawsvpn-cli: relay: tunnel up — local=%s tun=%s vpn-endpoint=%s\n",
			localIP, client.LocalIP(), payload.RemoteIP)

		notifyReady(readyFD, localIP)

		// Notify the relay (and therefore the app) that the tunnel is up.
		if agentPtr != nil {
			agentPtr.SendStatus(ctx, payload.SessionID, "connected", localIP)
		}

		// Wait for disconnect or context cancel.
		<-client.Done()
		return client.WaitForDisconnect()
	}

	agent, err := relay.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openlawsvpn-cli: relay: %v\n", err)
		os.Exit(1)
	}
	agentPtr = agent

	fmt.Fprintf(os.Stderr, "openlawsvpn-cli: relay mode — agent_id=%s, waiting for app to connect...\n", agent.AgentID())

	if err := agent.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "openlawsvpn-cli: relay: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "openlawsvpn-cli: relay: disconnected")
}

// outboundIP returns the machine's preferred outbound IP by opening a UDP
// socket toward a public address (no packets are sent). Falls back to "" on
// error so the relay still gets a status update without an IP.
func outboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// spawnDaemon re-execs the current binary in the background, waits for the
// child to signal "tunnel up" via a pipe, then exits the foreground process.
//
// Strategy: re-exec (not fork) so the Go runtime starts fresh in the child
// without inheriting goroutines, mutexes, or half-open file descriptors.
// The write-end of a pipe is passed to the child via an extra FD (> 2) and
// the OPENLAWSVPN_READY_FD env var. Once the child calls notifyReady(), it
// writes "ok\n" and closes the FD; the parent unblocks and exits 0.
func spawnDaemon(pidFile, logFile string) {
	r, w, err := os.Pipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "openlawsvpn-cli: daemon pipe: %v\n", err)
		os.Exit(1)
	}

	// Choose the log destination for the child.
	var childOut *os.File
	if logFile != "" {
		childOut, err = os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "openlawsvpn-cli: open logfile: %v\n", err)
			os.Exit(1)
		}
	} else {
		childOut, err = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "openlawsvpn-cli: open /dev/null: %v\n", err)
			os.Exit(1)
		}
	}

	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "openlawsvpn-cli: resolve executable: %v\n", err)
		os.Exit(1)
	}

	// Pass write-end as FD 3 in the child.
	child := exec.Command(self, os.Args[1:]...)
	child.Stdout = childOut
	child.Stderr = childOut
	child.Stdin = nil
	child.ExtraFiles = []*os.File{w} // becomes FD 3 in child (ExtraFiles[0] → fd 3)
	child.Env = append(os.Environ(), "OPENLAWSVPN_READY_FD=3")
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // detach from terminal

	if err := child.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "openlawsvpn-cli: spawn daemon: %v\n", err)
		os.Exit(1)
	}
	// Close write-end in parent so a child crash causes the pipe to close.
	w.Close()
	childOut.Close()

	if pidFile != "" {
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(child.Process.Pid)+"\n"), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "openlawsvpn-cli: write pidfile: %v\n", err)
		}
	}

	// Block until the child writes "ok\n" or closes the pipe (error/crash).
	buf := make([]byte, 64)
	n, _ := r.Read(buf)
	r.Close()

	if n == 0 || !strings.HasPrefix(string(buf[:n]), "ok") {
		fmt.Fprintln(os.Stderr, "openlawsvpn-cli: daemon failed to establish tunnel")
		child.Process.Kill() //nolint:errcheck
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "openlawsvpn-cli: daemon started (pid %d)\n", child.Process.Pid)
	// Detach — let the child continue.
	os.Exit(0)
}

// notifyReady signals the parent foreground process (if any) that the tunnel is
// up. readyFD is 0 when not in daemon mode, in which case this is a no-op.
func notifyReady(readyFD int, localIP string) {
	if readyFD == 0 {
		return
	}
	f := os.NewFile(uintptr(readyFD), "ready-pipe")
	fmt.Fprintf(f, "ok local=%s\n", localIP)
	f.Close()
}

// protoName returns a human-readable protocol string.
func protoName(proto profile.Proto) string {
	switch proto {
	case profile.ProtoTCP:
		return "tcp"
	case profile.ProtoUDP:
		return "udp"
	default:
		return "unknown"
	}
}
