// Command openlawsvpn-cli is a minimal CLI for the go-openlawsvpn VPN client.
//
// It implements the AWS Client VPN SAML/CRV1 authentication flow and
// brings up a Linux TUN interface with the routes and DNS pushed by the server.
// Non-SAML profiles (cert-auth, user-pass) are also supported via auto-detection.
//
// Usage:
//
//	openlawsvpn-cli -config <path.ovpn> [-saml-token-file <mode-0600-file>]
//	openlawsvpn-cli -relay <token> [-relay-endpoint <wss://...>] [-agent-id <uuid>]
//
// Flags:
//
//	-config          Path to the .ovpn profile file.
//	                 Required for direct (non-relay) mode.
//	                 Optional in relay mode — the app always sends the profile inside
//	                 the phase2 payload; -config is only used as a fallback if the
//	                 payload carries no ovpn_config.
//	-saml-token-file Read a base64-encoded SAMLResponse from a mode-0600 file.
//	-saml-token-fd   Read it from an open descriptor (0 means standard input).
//	-relay            Relay organisation identifier/token. The public demo value
//	                  is "default"; use a token file for private bearer tokens.
//	-relay-token-file / -relay-token-fd
//	                  Optionally read a private relay token outside argv.
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
//	sudo openlawsvpn-cli -relay default -daemon \
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
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	vpn "github.com/openlawsvpn/go-openlawsvpn"
	"github.com/openlawsvpn/go-openlawsvpn/auth/saml"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/relay"
)

func main() {
	configPath := flag.String("config", "", "path to .ovpn profile file (required in direct mode)")
	samlToken := flag.String("saml-token", "", "deprecated: SAMLResponse on command line (unsafe; use -saml-token-file or -saml-token-fd)")
	samlTokenFile := flag.String("saml-token-file", "", "read a pre-supplied SAMLResponse from a mode-0600 file")
	samlTokenFD := flag.Int("saml-token-fd", -1, "read a pre-supplied SAMLResponse from an open file descriptor (0 for stdin)")
	relayToken := flag.String("relay", "", "relay organisation identifier/token (use 'default' for the public demo)")
	relayTokenFile := flag.String("relay-token-file", "", "read the relay organisation token from a mode-0600 file")
	relayTokenFD := flag.Int("relay-token-fd", -1, "read the relay organisation token from an open file descriptor (0 for stdin)")
	relayEndpoint := flag.String("relay-endpoint", "wss://ws.relay.openlawsvpn.com", "relay WebSocket URL")
	relayAgentID := flag.String("agent-id", "", "stable UUID for this agent (default: random)")
	relayHostname := flag.String("hostname", "", "human-readable agent label (default: os.Hostname)")
	daemonMode := flag.Bool("daemon", false, "fork to background once the tunnel is up")
	pidFile := flag.String("pidfile", "", "write daemon PID to this file (requires -daemon)")
	logFile := flag.String("logfile", "", "redirect daemon output to this file (requires -daemon)")
	browserCmd := flag.String("browser", "", "browser command to open SAML URL (e.g. firefox, chromium); default: xdg-open")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, `openlawsvpn-cli — AWS Client VPN with SAML/SSO authentication

USAGE
  openlawsvpn-cli -config <path.ovpn> [OPTIONS]          # direct mode
  openlawsvpn-cli -relay <token> [OPTIONS]               # relay/headless mode

MODES

  Direct mode   Connect interactively on this machine. A browser opens for
                SAML login; the token is captured automatically via the ACS
                server on 127.0.0.1:35001. Requires root or CAP_NET_ADMIN.

  Relay mode    Register as a headless agent waiting for credentials. The
                mobile/desktop app runs the SAML flow and delivers the
                completed credentials to this agent via the relay service.
                The tunnel is then established here. Useful for CI/CD runners
                and remote VMs that cannot open a browser.

OPTIONS

  -config <path>          Path to .ovpn profile file.
                          Required in direct mode. Optional in relay mode —
                          the app always sends the profile in the payload;
                          -config is only used as a fallback.

  -relay <token>          Organisation identifier/token; enables relay mode.
                          The public demo value is "default". Private tokens
                          act as bearer credentials; -relay-token-file is safer
                          for long-running or shared systems.

  -relay-token-file <path>
                          Alternative input for a private organisation token.
                          The file must be regular and have mode 0600 or stricter.

  -relay-token-fd <fd>    Read the organisation token from an already-open file
                          descriptor. Use 0 for standard input. Not supported
                          with -daemon; use -relay-token-file in daemon mode.

  -relay-endpoint <url>   Relay WebSocket URL.
                          Default: wss://ws.relay.openlawsvpn.com

  -agent-id <uuid>        Stable UUID identifying this agent across reconnects.
                          Default: random (changes on every restart).
                          Set a fixed value to keep the same label in the app.

  -hostname <name>        Human-readable label shown in the app agent list.
                          Default: system hostname (os.Hostname).

  -daemon                 Fork to background after the tunnel is up.
                          The foreground process blocks until the VPN is
                          established, prints "daemon started (pid N)", then
                          exits 0. The background process keeps the tunnel alive.
                          Use -pidfile to record the PID for later cleanup.

  -pidfile <path>         Write the daemon PID to this file. Only used with -daemon.
                          Example: -pidfile /tmp/openlawsvpn.pid

  -logfile <path>         Redirect daemon stdout+stderr to this file.
                          Only used with -daemon. Default: /dev/null.
                          Example: -logfile /tmp/openlawsvpn.log

  -saml-token-file <path> Read a pre-supplied SAMLResponse from a mode-0600 file.

  -saml-token-fd <fd>     Read a pre-supplied SAMLResponse from an already-open
                          descriptor. Use 0 for standard input. Not supported
                          with -daemon; use -saml-token-file in daemon mode.

  -saml-token <base64>    Deprecated and rejected with -daemon because command
                          arguments are visible in process listings.

  -browser <cmd>          Browser command to open the SAML URL.
                          Default: xdg-open. Example: -browser firefox

  -h, -help               Print this help message.

EXAMPLES

  # Interactive SAML login (direct mode)
  sudo openlawsvpn-cli -config ~/Downloads/client.ovpn

  # Public relay demo
  sudo openlawsvpn-cli -relay default -daemon \
    -pidfile /tmp/openlawsvpn.pid \
    -logfile /tmp/openlawsvpn.log

  # Relay agent — block until app approves, then stay in foreground
  sudo openlawsvpn-cli -relay-token-file /run/user/$UID/openlawsvpn-relay-token \
    -config ~/Downloads/client.ovpn

  # Relay agent — daemon mode for CI/CD (exits once tunnel is up)
  sudo openlawsvpn-cli \
    -relay-token-file /run/user/$UID/openlawsvpn-relay-token \
    -daemon \
    -pidfile /tmp/openlawsvpn.pid \
    -logfile /tmp/openlawsvpn.log

  # Disconnect daemon
  sudo kill $(cat /tmp/openlawsvpn.pid)

  # Fixed agent identity across restarts
  sudo openlawsvpn-cli -relay-token-file /run/user/$UID/openlawsvpn-relay-token \
    -agent-id acf3b812-… -hostname build-runner-01

RELAY ENDPOINTS
  WebSocket:  wss://ws.relay.openlawsvpn.com
  REST API:   https://api.relay.openlawsvpn.com/api/v1

`)
	}

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
		if err := validateDaemonSecretSources(*samlToken, *relayToken, *samlTokenFD, *relayTokenFD); err != nil {
			fmt.Fprintf(os.Stderr, "openlawsvpn-cli: %v\n", err)
			os.Exit(1)
		}
	}

	if *daemonMode && readyFD == 0 {
		// Foreground parent: create a pipe, re-exec self as background child
		// passing the write-end FD, then block until the child signals ready.
		spawnDaemon(*pidFile, *logFile)
		return
	}

	resolvedSAMLToken, err := resolveSecret("SAML token", *samlToken, *samlTokenFile, *samlTokenFD, saml.MaxSAMLResponseBytes, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openlawsvpn-cli: %v\n", err)
		os.Exit(1)
	}
	warnRelayLiteral := *relayToken != "" && *relayToken != "default"
	resolvedRelayToken, err := resolveSecret("relay token", *relayToken, *relayTokenFile, *relayTokenFD, 64*1024, warnRelayLiteral)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openlawsvpn-cli: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Relay mode: -config is optional. The app delivers ovpn_config inside the
	// phase2 payload, so no local profile is needed. If -config is provided it
	// is used as a fallback when the payload carries no config.
	if resolvedRelayToken != "" {
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
		runRelayMode(ctx, stop, fallbackProfile, relay.Config{
			Token:    resolvedRelayToken,
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
	preSuppliedToken := resolvedSAMLToken

	client.SAMLTokenFn = func(ctx context.Context, challenge vpn.SAMLChallenge) (string, error) {
		if preSuppliedToken != "" {
			tok := preSuppliedToken
			preSuppliedToken = "" // consume it — re-auth will go through the ACS flow
			fmt.Fprintf(os.Stderr, "openlawsvpn-cli: SAML token received (%d chars)\n", len(tok))
			return tok, nil
		}

		fmt.Printf("openlawsvpn-cli: SAML authentication required\n")
		fmt.Printf("openlawsvpn-cli: Open this URL in your browser:\n\n  %s\n\n", challenge.URL)
		openBrowser(challenge.URL, *browserCmd)

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
	stdinDone := make(chan struct{})
	defer close(stdinDone)

	go func() {
		tok, err := acs.Wait(ctx)
		if err != nil {
			errCh <- err
			return
		}
		tokenCh <- tok
	}()

	// Stdin loop: empty Enter = reopen URL, non-empty = pasted token. It is
	// stopped once ACS or context completion wins the race so later terminal
	// input cannot reopen an expired URL.
	go watchSAMLTokenInput(os.Stdin, stdinDone, func() {
		fmt.Fprintf(os.Stderr, "\nopenlawsvpn-cli: reopening URL...\n  %s\n\n", challenge.URL)
		openBrowser(challenge.URL, browserCmd)
	}, tokenCh)

	select {
	case tok := <-tokenCh:
		return tok, nil
	case err := <-errCh:
		return "", err
	case <-ctx.Done():
		return "", fmt.Errorf("openlawsvpn-cli: SAML wait cancelled: %w", ctx.Err())
	}
}

// watchSAMLTokenInput forwards a pasted SAML token or invokes onEmpty for an
// empty line. Closing done disables it without closing the process's stdin.
func watchSAMLTokenInput(r io.Reader, done <-chan struct{}, onEmpty func(), tokenCh chan<- string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		select {
		case <-done:
			return
		default:
		}

		line := scanner.Text()
		if line == "" {
			select {
			case <-done:
				return
			default:
				onEmpty()
			}
			continue
		}

		select {
		case tokenCh <- line:
		case <-done:
		}
		return
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

func validateDaemonSecretSources(samlLiteral, relayLiteral string, samlFD, relayFD int) error {
	// Relay literals are intentionally supported for backward compatibility and
	// for the public "default" organisation selector. Private relay users can
	// opt into -relay-token-file to keep their bearer token out of argv.
	_ = relayLiteral
	if samlLiteral != "" {
		return fmt.Errorf("daemon mode requires -saml-token-file; a SAML assertion must not remain in process arguments")
	}
	if samlFD >= 0 || relayFD >= 0 {
		return fmt.Errorf("daemon mode cannot preserve file-descriptor token inputs across re-exec; use a token-file option")
	}
	return nil
}

func resolveSecret(name, literal, path string, fd, maxBytes int, warnLiteral bool) (string, error) {
	sources := 0
	if literal != "" {
		sources++
	}
	if path != "" {
		sources++
	}
	if fd >= 0 {
		sources++
	}
	if sources > 1 {
		return "", fmt.Errorf("%s: choose exactly one command-line, file, or file-descriptor source", name)
	}
	if literal != "" {
		if warnLiteral {
			fmt.Fprintf(os.Stderr, "openlawsvpn-cli: warning: command-line %s is visible in process listings; use a token-file or file-descriptor option for private credentials\n", name)
		}
		return literal, nil
	}
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return "", fmt.Errorf("read %s file: %w", name, err)
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return "", fmt.Errorf("stat %s file: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("%s file must be a regular file", name)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("%s file permissions %04o expose it to group or other users; remove all group/other permissions", name, info.Mode().Perm())
		}
		return readBoundedSecret(name, f, maxBytes)
	}
	if fd >= 0 {
		f := os.NewFile(uintptr(fd), name)
		if f == nil {
			return "", fmt.Errorf("%s: invalid file descriptor %d", name, fd)
		}
		return readBoundedSecret(name, f, maxBytes)
	}
	return "", nil
}

func readBoundedSecret(name string, r io.Reader, maxBytes int) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(r, int64(maxBytes+1)))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", name, err)
	}
	if len(raw) > maxBytes {
		clear(raw)
		return "", fmt.Errorf("%s exceeds %d bytes", name, maxBytes)
	}
	secret := strings.TrimSpace(string(raw))
	clear(raw)
	if secret == "" {
		return "", fmt.Errorf("%s is empty", name)
	}
	return secret, nil
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
func runRelayMode(ctx context.Context, stop context.CancelFunc, fallback *profile.Profile, cfg relay.Config, readyFD int) {
	cfg.Log = func(msg string) { fmt.Fprintln(os.Stderr, msg) }

	// agentPtr is set just after relay.New returns so the OnPhase2 closure can
	// call SendStatus without a circular dependency.
	var agentPtr *relay.Agent

	// activeClient is set inside OnPhase2 so OnDisconnect can call Disconnect()
	// on the running VPN client.
	var activeClientMu sync.Mutex
	var activeClient *vpn.Client

	// serverDisconnect is set to true when disconnect originates from the relay
	// server, so OnPhase2 can suppress the spurious write error from the closed
	// UDP socket and the process can exit cleanly.
	var serverDisconnect atomic.Bool

	cfg.OnDisconnect = func() {
		activeClientMu.Lock()
		c := activeClient
		activeClientMu.Unlock()
		if c != nil {
			fmt.Fprintln(os.Stderr, "openlawsvpn-cli: relay: server requested disconnect")
			serverDisconnect.Store(true)
			c.Disconnect() //nolint:errcheck
		}
		// Cancel the agent Run loop so the process exits instead of reconnecting.
		stop()
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
		err := client.WaitForDisconnect()

		// Tell the relay the agent is now idle so the app sees "standby" immediately.
		if agentPtr != nil {
			agentPtr.SendStatus(ctx, payload.SessionID, "standby", "")
		}

		// Suppress the write error caused by our own Disconnect() closing the UDP
		// socket mid-write — this is a normal shutdown path, not a real failure.
		if serverDisconnect.Load() {
			return nil
		}
		return err
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
