// Package profile parses OpenVPN .ovpn configuration files.
//
// It handles the directives that go-openlawsvpn needs: remote, port, proto,
// inline PEM blocks (<ca>, <cert>, <key>), cipher, auth, rekey timing, and
// common extra options such as comp-lzo / compress.
package profile

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

// Proto is the transport protocol for the VPN tunnel.
type Proto int

const (
	// ProtoTCP uses TCP with the 2-byte length-prefix framing.
	ProtoTCP Proto = iota
	// ProtoUDP uses raw UDP packets.
	ProtoUDP
)

// Profile holds the parsed contents of an .ovpn file.
type Profile struct {
	// Remote is the VPN server hostname or IP.
	Remote string
	// Port is the server port (default 1194).
	Port int
	// Proto is the transport protocol.
	Proto Proto

	// CA is the PEM-encoded certificate authority bundle.
	CA []byte
	// Cert is the PEM-encoded client certificate.
	Cert []byte
	// Key is the PEM-encoded client private key.
	Key []byte

	// Cipher is the negotiated data-channel cipher name, e.g. "AES-256-GCM".
	Cipher string
	// Auth is the HMAC digest, e.g. "SHA256" (unused for GCM).
	Auth string

	// RenegSec is the data-channel key renegotiation interval in seconds.
	// An explicit "reneg-sec 0" disables client-initiated renegotiation, as it
	// does in OpenVPN3. Profiles without the directive use the OpenVPN default
	// of 3600 seconds.
	RenegSec int
	// RenegBytes is the data-channel key renegotiation byte threshold.
	// 0 means no byte-limit renegotiation.
	RenegBytes int64
	// BecomePrimarySec is the optional delay before a negotiated rekey becomes
	// the primary send key. 0 uses the OpenVPN default derived from reneg-sec.
	BecomePrimarySec int

	// TunMTU is the MTU for the TUN interface, from the 'tun-mtu' directive.
	// 0 means use the default (1500).
	TunMTU int

	// MSSFix is the maximum segment size clamp value, from the 'mssfix' directive.
	// A zero value with MSSFixSet true explicitly disables MSS clamping.
	MSSFix int
	// MSSFixSet reports whether the profile explicitly set a numeric mssfix
	// value. It distinguishes "mssfix 0" from an omitted directive, for which
	// OpenVPN applies its default MSS clamp.
	MSSFixSet bool

	// RandomHostname indicates the 'remote-random-hostname' directive was present.
	// When true, the client must prepend a random subdomain to Remote before dialing.
	// AWS Client VPN requires this — the bare endpoint hostname has no DNS record.
	RandomHostname bool

	// VerifyX509Name is the expected CN or SAN from the 'verify-x509-name' directive.
	// When non-empty, it overrides the TLS ServerName used for certificate verification.
	// AWS Client VPN profiles typically set this to the actual certificate CN (e.g. "mtlab.ai").
	VerifyX509Name string

	// ForceSAMLFlow is set when the profile contains 'auth-federate' or
	// 'x-openlawsvpn-flow saml'. It forces FlowAWSSSO regardless of the remote
	// hostname, allowing non-AWS servers (e.g. the demo mockserver) to use the
	// CRV1/SAML two-phase flow.
	ForceSAMLFlow bool

	// DNSServers, DNSSearchDomains, and DNSRouteDomains are static DNS options
	// from the profile. They are combined with options pushed by the server.
	DNSServers       []net.IP
	DNSSearchDomains []string
	DNSRouteDomains  []string
}

// AuthFlow describes which authentication mechanism the profile uses.
type AuthFlow int

const (
	// FlowAWSSSO is the AWS Client VPN SAML/CRV1 two-phase flow.
	// Detected when the remote hostname matches cvpn-endpoint-*.amazonaws.com.
	FlowAWSSSO AuthFlow = iota
	// FlowCertAuth is standard mutual-TLS client certificate authentication.
	// Detected when the profile embeds both <cert> and <key> blocks.
	FlowCertAuth
	// FlowUserPass is username/password authentication (auth-user-pass).
	// Used as the fallback when no other pattern matches.
	FlowUserPass
)

// DetectFlow inspects the profile and returns the appropriate AuthFlow.
func (p *Profile) DetectFlow() AuthFlow {
	if p.ForceSAMLFlow {
		return FlowAWSSSO
	}
	if strings.HasPrefix(p.Remote, "cvpn-endpoint-") && strings.HasSuffix(p.Remote, ".amazonaws.com") {
		return FlowAWSSSO
	}
	if len(p.Cert) > 0 && len(p.Key) > 0 {
		return FlowCertAuth
	}
	return FlowUserPass
}

// ParseFile parses an .ovpn profile from the provided reader.
func ParseFile(r io.Reader) (*Profile, error) {
	p := &Profile{
		Port:   1194,
		Proto:  ProtoUDP,
		Cipher: "AES-256-GCM",
		Auth:   "SHA256",
		// openvpn3-core ssl/proto.hpp starts with this default, then lets an
		// explicit reneg-sec directive (including zero) override it.
		RenegSec: 3600,
	}

	scanner := bufio.NewScanner(r)
	var inlineTag string
	var inlineBuf bytes.Buffer

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip blank lines and comments.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Closing inline block tag.
		if inlineTag != "" {
			if line == "</"+inlineTag+">" {
				switch inlineTag {
				case "ca":
					p.CA = append([]byte{}, inlineBuf.Bytes()...)
				case "cert":
					p.Cert = append([]byte{}, inlineBuf.Bytes()...)
				case "key":
					p.Key = append([]byte{}, inlineBuf.Bytes()...)
				}
				inlineTag = ""
				inlineBuf.Reset()
			} else {
				inlineBuf.WriteString(line)
				inlineBuf.WriteByte('\n')
			}
			continue
		}

		// Opening inline block tag.
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") {
			tag := line[1 : len(line)-1]
			switch tag {
			case "ca", "cert", "key":
				inlineTag = tag
				inlineBuf.Reset()
				continue
			}
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		directive := strings.ToLower(fields[0])

		switch directive {
		case "remote":
			if len(fields) < 2 {
				return nil, fmt.Errorf("profile: remote: missing hostname")
			}
			p.Remote = fields[1]
			if len(fields) >= 3 {
				port, err := strconv.Atoi(fields[2])
				if err != nil || port < 1 || port > 65535 {
					return nil, fmt.Errorf("profile: remote: invalid port %q", fields[2])
				}
				p.Port = port
			}
		case "port":
			if len(fields) < 2 {
				return nil, fmt.Errorf("profile: port: missing value")
			}
			port, err := strconv.Atoi(fields[1])
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("profile: port: invalid %q", fields[1])
			}
			p.Port = port
		case "proto":
			if len(fields) < 2 {
				return nil, fmt.Errorf("profile: proto: missing value")
			}
			switch strings.ToLower(fields[1]) {
			case "tcp", "tcp-client":
				p.Proto = ProtoTCP
			case "udp":
				p.Proto = ProtoUDP
			default:
				return nil, fmt.Errorf("profile: proto: unknown %q", fields[1])
			}
		case "cipher":
			if len(fields) < 2 {
				return nil, fmt.Errorf("profile: cipher: missing value")
			}
			p.Cipher = strings.ToUpper(fields[1])
		case "auth":
			if len(fields) < 2 {
				return nil, fmt.Errorf("profile: auth: missing value")
			}
			p.Auth = strings.ToUpper(fields[1])
		case "reneg-sec":
			if len(fields) < 2 {
				return nil, fmt.Errorf("profile: reneg-sec: missing value")
			}
			n, err := strconv.Atoi(fields[1])
			if err != nil || n < 0 {
				return nil, fmt.Errorf("profile: reneg-sec: invalid %q", fields[1])
			}
			p.RenegSec = n
		case "reneg-bytes":
			if len(fields) < 2 {
				return nil, fmt.Errorf("profile: reneg-bytes: missing value")
			}
			n, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("profile: reneg-bytes: invalid %q", fields[1])
			}
			p.RenegBytes = n
		case "become-primary":
			if len(fields) < 2 {
				return nil, fmt.Errorf("profile: become-primary: missing value")
			}
			n, err := strconv.Atoi(fields[1])
			if err != nil || n < 0 {
				return nil, fmt.Errorf("profile: become-primary: invalid %q", fields[1])
			}
			p.BecomePrimarySec = n
		case "tun-mtu":
			if len(fields) < 2 {
				return nil, fmt.Errorf("profile: tun-mtu: missing value")
			}
			n, err := strconv.Atoi(fields[1])
			if err != nil || n < 68 || n > 65535 {
				return nil, fmt.Errorf("profile: tun-mtu: invalid %q", fields[1])
			}
			p.TunMTU = n
		case "mssfix":
			// OpenVPN accepts a bare "mssfix" and applies its default. Keep
			// MSSFixSet false in that case, exactly as when the directive is
			// omitted. A numeric zero is an explicit opt-out.
			if len(fields) >= 2 {
				n, err := strconv.Atoi(fields[1])
				if err != nil || n < 0 {
					return nil, fmt.Errorf("profile: mssfix: invalid %q", fields[1])
				}
				p.MSSFix = n
				p.MSSFixSet = true
			}
		case "remote-random-hostname":
			p.RandomHostname = true
		case "auth-federate":
			// AWS Client VPN profiles use this OpenVPN directive to request
			// federated (SAML) authentication. Treat it as the standard spelling
			// of the existing explicit SAML-flow override.
			p.ForceSAMLFlow = true
		case "x-openlawsvpn-flow":
			if len(fields) >= 2 && strings.ToLower(fields[1]) == "saml" {
				p.ForceSAMLFlow = true
			}
		case "verify-x509-name":
			if len(fields) >= 2 {
				p.VerifyX509Name = fields[1]
			}
		case "dhcp-option":
			if len(fields) < 3 {
				continue
			}
			switch strings.ToUpper(fields[1]) {
			case "DNS":
				ip := net.ParseIP(fields[2])
				if ip == nil {
					return nil, fmt.Errorf("profile: dhcp-option DNS: invalid IP %q", fields[2])
				}
				p.DNSServers = append(p.DNSServers, ip)
			case "DOMAIN":
				p.DNSSearchDomains = append(p.DNSSearchDomains, fields[2])
			case "DOMAIN-ROUTE":
				p.DNSRouteDomains = append(p.DNSRouteDomains, fields[2])
			}
		case "ca":
			// Inline file reference: ca /path/to/ca.crt — not supported here.
			// Users must use <ca>...</ca> inline blocks.
		case "cert":
			// Same — use <cert>...</cert>.
		case "key":
			// Same — use <key>...</key>.
		}
		// Unrecognised directives are silently ignored (forward-compat).
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("profile: read: %w", err)
	}

	if p.Remote == "" {
		return nil, fmt.Errorf("profile: missing 'remote' directive")
	}
	return p, nil
}

// ParseString is a convenience wrapper around ParseFile for in-memory profiles.
func ParseString(s string) (*Profile, error) {
	return ParseFile(strings.NewReader(s))
}

// ParsePath opens path and parses it as an .ovpn profile file.
func ParsePath(path string) (*Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("profile: open %s: %w", path, err)
	}
	defer f.Close()
	return ParseFile(f)
}
