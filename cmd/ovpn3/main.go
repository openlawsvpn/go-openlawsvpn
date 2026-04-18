// Command ovpn3 is a minimal CLI for the go-openvpn3 VPN client.
//
// It implements the AWS Client VPN SAML/CRV1 authentication flow and
// brings up a Linux TUN interface with the routes and DNS pushed by the server.
// Non-SAML profiles (cert-auth, user-pass) are also supported via auto-detection.
//
// Usage:
//
//	ovpn3 -config <path.ovpn> [-saml-token <base64token>]
//
// Flags:
//
//	-config     Path to the .ovpn profile file (required).
//	-saml-token Base64-encoded SAMLResponse.  When omitted, the CLI starts
//	            an ACS server on 127.0.0.1:35001 and waits for the browser
//	            callback, or reads the token from standard input if stdin
//	            is not a TTY.
//
// The command prints the SAML URL to stdout, waits for authentication, then
// prints "tunnel up" once the tunnel is established.  Send SIGINT or SIGTERM
// to disconnect gracefully.
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
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	vpn "github.com/openlawsvpn/go-openvpn3"
	"github.com/openlawsvpn/go-openvpn3/auth/saml"
	"github.com/openlawsvpn/go-openvpn3/profile"
)

func main() {
	configPath := flag.String("config", "", "path to .ovpn profile file (required)")
	samlToken := flag.String("saml-token", "", "pre-supplied base64 SAMLResponse (skips ACS server)")
	flag.Parse()

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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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

	fmt.Println("ovpn3: tunnel up")

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
			if err := client.Wait(); err != nil {
				fmt.Fprintf(os.Stderr, "ovpn3: wait error: %v\n", err)
			}
			fmt.Fprintln(os.Stderr, "ovpn3: disconnected")
			return
		case <-client.Done():
			reason := client.Wait()
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
			fmt.Println("ovpn3: tunnel up")
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
