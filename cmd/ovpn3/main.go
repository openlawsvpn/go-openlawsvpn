// Command ovpn3 is a minimal CLI for the go-openvpn3 VPN client.
//
// It implements the AWS Client VPN SAML/CRV1 authentication flow and
// brings up a Linux TUN interface with the routes and DNS pushed by the server.
// Non-SAML profiles (cert-auth, user-pass) are also supported via auto-detection.
//
// Usage:
//
//	ovpn3 -config <path.ovpn> [-saml-token <base64token>]
//	ovpn3 -relay <token> [-relay-endpoint <wss://...>] [-agent-id <uuid>] [-hostname <name>]
//	ovpn3 -relay <token> -config <path.ovpn> [...]   # -config optional in relay mode
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
//	-relay-endpoint  Relay WebSocket URL (default: wss://ws.relay.openlawsvpn.com/ws).
//	-agent-id        Stable UUID for this agent (default: random, changes on restart).
//	-hostname        Human-readable label shown in the app (default: os.Hostname).
//
// # CI / headless mode
//
// When the CI environment variable is set (any non-empty value — GitHub Actions,
// GitLab CI, Jenkins, and most CI systems set it automatically), the relay agent
// runs in foreground mode:
//
//   - The tunnel comes up and the process blocks, keeping the VPN alive for the
//     rest of the pipeline job.
//   - Once the tunnel is established, a machine-readable line is printed to stdout
//     so that the calling shell script or workflow step can detect readiness:
//
//	OVPN3_TUNNEL_UP local=<outbound-ip> vpn=<assigned-ip> endpoint=<server-ip>
//
//   - The process exits with code 0 when the context is cancelled (SIGINT/SIGTERM
//     or the job finishes and the step is killed).
//   - In relay mode with CI=true, the process does NOT exit after Phase 2 delivers
//     credentials — it stays connected and forwards the "tunnel up" line so the
//     next pipeline step can proceed.
//
// Example GitHub Actions step:
//
//	- name: Connect VPN
//	  run: sudo ovpn3 -relay ${{ secrets.RELAY_TOKEN }} &
//	  # Next step runs after tunnel is up (detected via log polling or sleep)
//
// Build as a fully static binary:
//
//	CGO_ENABLED=0 go build -o ovpn3 ./cmd/ovpn3
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
	"strings"
	"syscall"

	vpn "github.com/openlawsvpn/go-openlawsvpn"
	"github.com/openlawsvpn/go-openlawsvpn/auth/saml"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/relay"
)

func main() {
	configPath     := flag.String("config", "", "path to .ovpn profile file (required)")
	samlToken      := flag.String("saml-token", "", "pre-supplied base64 SAMLResponse (skips ACS server)")
	relayToken     := flag.String("relay", "", "organisation token — enables relay mode")
	relayEndpoint  := flag.String("relay-endpoint", "wss://ws.relay.openlawsvpn.com/ws", "relay WebSocket URL")
	relayAgentID   := flag.String("agent-id", "", "stable UUID for this agent (default: random)")
	relayHostname  := flag.String("hostname", "", "human-readable agent label (default: os.Hostname)")
	flag.Parse()

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
				fmt.Fprintf(os.Stderr, "ovpn3: parse config: %v\n", err)
				os.Exit(1)
			}
			fallbackProfile = fp
		}
		runRelayMode(ctx, fallbackProfile, relay.Config{
			Token:    *relayToken,
			Hostname: hostname,
			AgentID:  *relayAgentID,
			Endpoint: *relayEndpoint,
		})
		return
	}

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "ovpn3: -config flag is required")
		flag.Usage()
		os.Exit(1)
	}

	p, err := profile.ParsePath(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ovpn3: parse config: %v\n", err)
		os.Exit(1)
	}

	client := vpn.New(p)

	remoteDesc := p.Remote
	if p.RandomHostname {
		remoteDesc = "<random>." + p.Remote
	}
	fmt.Fprintf(os.Stderr, "ovpn3: connecting to %s:%d (%s)...\n",
		remoteDesc, p.Port, protoName(p.Proto))

	// Wire up the SAML token callback for AWS SSO profiles.
	preSuppliedToken := *samlToken

	client.SAMLTokenFn = func(ctx context.Context, challenge vpn.SAMLChallenge) (string, error) {
		fmt.Printf("ovpn3: SAML authentication required\n")
		fmt.Printf("ovpn3: Open this URL in your browser:\n\n  %s\n\n", challenge.URL)
		openBrowser(challenge.URL)

		if preSuppliedToken != "" {
			tok := preSuppliedToken
			preSuppliedToken = "" // consume it — re-auth will go through the ACS flow
			fmt.Fprintf(os.Stderr, "ovpn3: SAML token received (%d chars)\n", len(tok))
			return tok, nil
		}

		tok, err := waitForSAMLToken(ctx, challenge)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(os.Stderr, "ovpn3: SAML token received (%d chars)\n", len(tok))
		return tok, nil
	}

	if err := client.Connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "ovpn3: connect failed: %v\n", err)
		if isPermissionError(err) {
			fmt.Fprintln(os.Stderr, "ovpn3: hint: TUN device requires root — re-run with sudo")
		}
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "ovpn3: tunnel up — local=%s tun=%s\n",
		outboundIP(), client.LocalIP())

	// Wait for signal or server-initiated disconnect (e.g. keepalive timeout).
	// If the disconnect was caused by a dead link, attempt to reconnect.
	for {
		select {
		case <-ctx.Done():
			// User pressed Ctrl-C or sent SIGTERM — clean exit.
			fmt.Fprintln(os.Stderr, "\novpn3: disconnecting...")
			stop()
			if err := client.Disconnect(); err != nil {
				fmt.Fprintf(os.Stderr, "ovpn3: disconnect error: %v\n", err)
			}
			if err := client.WaitForDisconnect(); err != nil {
				fmt.Fprintf(os.Stderr, "ovpn3: wait error: %v\n", err)
			}
			fmt.Fprintln(os.Stderr, "ovpn3: disconnected")
			return
		case <-client.Done():
			reason := client.WaitForDisconnect()
			if reason == nil || ctx.Err() != nil {
				// Clean disconnect or signal — exit.
				fmt.Fprintln(os.Stderr, "ovpn3: disconnected")
				return
			}
			// Unclean disconnect (dead link, keepalive timeout, etc.) — reconnect.
			fmt.Fprintf(os.Stderr, "ovpn3: tunnel down (%v), reconnecting...\n", reason)
			if err := client.Reconnect(ctx); err != nil {
				if ctx.Err() != nil {
					fmt.Fprintln(os.Stderr, "ovpn3: disconnected")
					return
				}
				if errors.Is(err, vpn.ErrReauthRequired) {
					// SAML session expired — run the full browser flow again.
					fmt.Fprintln(os.Stderr, "ovpn3: SAML session expired, re-authenticating...")
					if err := client.Connect(ctx); err != nil {
						fmt.Fprintf(os.Stderr, "ovpn3: re-auth connect failed: %v\n", err)
						os.Exit(1)
					}
				} else {
					fmt.Fprintf(os.Stderr, "ovpn3: reconnect failed: %v\n", err)
					os.Exit(1)
				}
			}
			fmt.Fprintf(os.Stderr, "ovpn3: tunnel up — local=%s tun=%s\n",
				outboundIP(), client.LocalIP())
		}
	}
}

// waitForSAMLToken starts the ACS server to catch the browser callback, then
// falls back to reading the token from stdin if the user prefers to paste it.
func waitForSAMLToken(ctx context.Context, challenge vpn.SAMLChallenge) (string, error) {
	acs, err := saml.NewACSServer()
	if err != nil {
		// ACS port unavailable — fall back to stdin.
		fmt.Fprintln(os.Stderr, "ovpn3: ACS server unavailable; paste SAMLResponse and press Enter:")
		return readTokenFromStdin()
	}

	fmt.Fprintf(os.Stderr, "ovpn3: waiting for SAML callback on 127.0.0.1:%d\n", saml.ACSPort)
	fmt.Fprintln(os.Stderr, "       (or paste SAMLResponse on stdin if the browser cannot reach localhost)")

	_ = challenge // URL already printed by caller

	// Run ACS and stdin reader concurrently; first one wins.
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

	// Also accept token from stdin (useful in SSH/headless environments).
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				select {
				case tokenCh <- line:
				default:
				}
			}
		}
	}()

	select {
	case tok := <-tokenCh:
		return tok, nil
	case err := <-errCh:
		return "", err
	case <-ctx.Done():
		return "", fmt.Errorf("ovpn3: SAML wait cancelled: %w", ctx.Err())
	}
}

// readTokenFromStdin reads one line from stdin as the SAML token.
func readTokenFromStdin() (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		tok := scanner.Text()
		if tok == "" {
			return "", fmt.Errorf("ovpn3: empty SAMLResponse from stdin")
		}
		return tok, nil
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("ovpn3: read stdin: %w", err)
	}
	return "", fmt.Errorf("ovpn3: EOF on stdin before SAMLResponse")
}

// openBrowser attempts to open url in the system browser using xdg-open.
// Failure is silently ignored — the user can always open the URL manually.
func openBrowser(url string) {
	cmd := exec.Command("xdg-open", url)
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
func runRelayMode(ctx context.Context, fallback *profile.Profile, cfg relay.Config) {
	cfg.Log = func(msg string) { fmt.Fprintln(os.Stderr, msg) }

	// agentPtr is set just after relay.New returns so the OnPhase2 closure can
	// call SendStatus without a circular dependency.
	var agentPtr *relay.Agent

	cfg.OnPhase2 = func(ctx context.Context, payload relay.Phase2Payload) error {
		fmt.Fprintf(os.Stderr, "ovpn3: relay: received phase2 for session %s\n", payload.SessionID)

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
		// Pre-load the Phase 1 state that the app already obtained so connectPhase2
		// skips Phase 1 entirely and connects directly to the sticky backend IP.
		client.SetRelayPhase2(payload.RemoteIP, payload.StateID)

		if err := client.ConnectPhase2(ctx, payload.SAMLResponse); err != nil {
			return fmt.Errorf("relay: phase2 connect: %w", err)
		}
		localIP := outboundIP()
		fmt.Fprintf(os.Stderr, "ovpn3: relay: tunnel up — local=%s tun=%s vpn-endpoint=%s\n",
			localIP, client.LocalIP(), payload.RemoteIP)

		// In CI mode print a machine-readable ready line. Written to both
		// stdout (for script piping) and stderr (so 2>/log or &>/log both work).
		if isCI() {
			line := fmt.Sprintf("OVPN3_TUNNEL_UP local=%s vpn=%s endpoint=%s",
				localIP, client.LocalIP(), payload.RemoteIP)
			fmt.Println(line)
			fmt.Fprintln(os.Stderr, line)
		}

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
		fmt.Fprintf(os.Stderr, "ovpn3: relay: %v\n", err)
		os.Exit(1)
	}
	agentPtr = agent

	fmt.Fprintf(os.Stderr, "ovpn3: relay mode — agent_id=%s, waiting for app to connect...\n", agent.AgentID())

	if err := agent.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "ovpn3: relay: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "ovpn3: relay: disconnected")
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

// isCI reports whether the process is running inside a CI environment.
// GitHub Actions, GitLab CI, CircleCI, Jenkins and most other systems set CI.
func isCI() bool {
	v := os.Getenv("CI")
	return v != "" && v != "0" && v != "false"
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
