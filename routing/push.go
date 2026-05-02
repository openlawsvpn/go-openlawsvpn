// Package routing parses OpenVPN PUSH_REPLY routing options and applies
// them to the Linux kernel via netlink.
//
// Options parsed from PUSH_REPLY:
//
//   - topology <subnet|net30>            — determines how ifconfig is interpreted
//   - ifconfig <local> <peer|mask>       — TUN interface IPv4 address
//   - ifconfig-ipv6 <addr/prefix> <gw>  — TUN interface IPv6 address
//   - route-gateway <gw>                — default gateway for IPv4 route directives
//   - route <net> <mask> [gateway]       — explicit IPv4 network routes
//   - route-ipv6 <net/prefix> [gateway] — explicit IPv6 network routes
//   - redirect-gateway [def1] [...]      — default-route replacement (IPv4)
//   - redirect-gateway ipv6 [...]        — default-route replacement (IPv6)
//
// Parsing is pure Go and requires no special privileges.
// Applying routes requires CAP_NET_ADMIN (root on most systems).
//
// Reference: openvpn3-core tun/client/tunprop.hpp
package routing

import (
	"fmt"
	"net"
	"strings"

	"github.com/openlawsvpn/go-openlawsvpn/internal/compress"
)

// Topology is the OpenVPN P2P topology mode pushed by the server.
type Topology int

const (
	// TopologyNet30 is the traditional /30 point-to-point topology.
	// ifconfig local peer — peer is the P2P gateway address.
	TopologyNet30 Topology = iota
	// TopologySubnet is the modern subnet topology.
	// ifconfig local mask — mask is the subnet mask; route-gateway carries the gateway.
	TopologySubnet
)

// Ifconfig holds the TUN interface address pushed by the server.
type Ifconfig struct {
	// Local is the IP address assigned to the client's TUN interface.
	Local net.IP
	// Mask is the subnet mask for subnet topology; for net30 it is /30.
	Mask net.IPMask
	// Gateway is the next-hop gateway (route-gateway for subnet; peer addr for net30).
	Gateway net.IP
}

// Ifconfig6 holds the TUN interface IPv6 address pushed by the server.
// Corresponds to the "ifconfig-ipv6 <addr/prefix> <gw>" directive.
//
// Reference: openvpn3-core tun/client/tunprop.hpp tun_prop_ifconfig_ipv6().
type Ifconfig6 struct {
	// Local is the IPv6 address assigned to the client's TUN interface.
	Local net.IP
	// Prefix is the prefix length (e.g. 64 for a /64 network).
	Prefix int
	// Gateway is the IPv6 next-hop (may be nil when not pushed).
	Gateway net.IP
}

// Route represents a single network route pushed by the server.
type Route struct {
	// Network is the destination network address.
	Network net.IP
	// Mask is the destination network mask.
	Mask net.IPMask
	// Gateway is the next-hop address.
	// If nil, Ifconfig.Gateway is used.
	Gateway net.IP
}

// Route6 represents a single IPv6 network route pushed by the server.
// Corresponds to a "route-ipv6 <net/prefix> [gateway]" directive.
//
// Reference: openvpn3-core tun/client/tunprop.hpp tun_prop_route_ipv6().
type Route6 struct {
	// Network is the destination IPv6 network address.
	Network net.IP
	// Prefix is the prefix length (0–128).
	Prefix int
	// Gateway is the IPv6 next-hop (may be nil; use Ifconfig6.Gateway).
	Gateway net.IP
}

// KeyDerivation selects the data-channel key derivation method.
//
// Reference: openvpn3-core ssl/proto.hpp parse_pushed_protocol_flags() line ~836:
//
//	"tls-ekm"  → TLS RFC 5705 ExportKeyingMaterial (openvpn3-core 3.x default)
//	(absent)   → legacy OpenVPN PRF (HMAC-SHA256 over TLS master secret + randoms)
type KeyDerivation int

const (
	// KeyDerivationTLSEKM uses RFC 5705 ExportKeyingMaterial.
	// This is the default for servers that push "protocol-flags tls-ekm" or
	// "key-derivation tls-ekm". AWS Client VPN and openvpn3-core 3.x use this.
	KeyDerivationTLSEKM KeyDerivation = iota
	// KeyDerivationOpenVPNPRF uses the legacy OpenVPN HMAC-SHA256 PRF over the
	// TLS 1.2 master secret and client/server randoms.
	// Used by stock OpenVPN 2.x servers that do not push "protocol-flags tls-ekm".
	KeyDerivationOpenVPNPRF
)

// PushOptions holds all routing-relevant options extracted from a PUSH_REPLY.
type PushOptions struct {
	// Topology is the tunnel topology mode.
	Topology Topology

	// Ifconfig holds the TUN interface IPv4 addressing, if present.
	Ifconfig *Ifconfig

	// Ifconfig6 holds the TUN interface IPv6 addressing, if present.
	// Populated by "ifconfig-ipv6 <addr/prefix> <gw>".
	//
	// Reference: openvpn3-core tun/client/tunprop.hpp tun_prop_ifconfig_ipv6().
	Ifconfig6 *Ifconfig6

	// Routes is the list of explicit IPv4 routes from "route" directives.
	Routes []Route

	// Routes6 is the list of explicit IPv6 routes from "route-ipv6" directives.
	//
	// Reference: openvpn3-core tun/client/tunprop.hpp tun_prop_route_ipv6().
	Routes6 []Route6

	// RedirectGateway is true when the server pushed "redirect-gateway" (IPv4).
	// This means all IPv4 traffic (0.0.0.0/0) should be routed through the tunnel.
	RedirectGateway bool

	// RedirectGateway6 is true when the server pushed "redirect-gateway ipv6".
	// This means all IPv6 traffic (::/0) should be routed through the tunnel.
	RedirectGateway6 bool

	// Cipher is the data-channel cipher negotiated with the server (e.g. "AES-256-GCM").
	// Empty means the server did not push a cipher directive; the client falls back
	// to AES-256-GCM (the only cipher advertised in IV_CIPHERS).
	//
	// Reference: openvpn3-core ssl/proto.hpp parse_pushed_data_channel_options()
	// line ~753: parses "cipher <name>" and validates it against IV_NCP.
	Cipher string

	// Compression is the compression mode negotiated with the server.
	// Most servers (including AWS Client VPN) push no compression directive,
	// so this defaults to compress.ModeNone.
	//
	// Reference: openvpn3-core ssl/proto.hpp parse_pushed_compression() line ~875:
	//   parses "compress lz4[-v2]" and "comp-lzo" from the PUSH_REPLY option list.
	Compression compress.Mode

	// PingInterval is the keepalive send interval in seconds (from "ping N").
	// 0 means keepalive is disabled.
	//
	// Reference: openvpn3-core ssl/proto.hpp ProtoConfig::load_common(),
	// load_duration_parm(keepalive_ping, "ping", ...) line ~1254.
	PingInterval int

	// PingRestart is the keepalive receive timeout in seconds (from "ping-restart N").
	// If no data arrives within this window the tunnel should be considered dead.
	// 0 means no restart on idle.
	//
	// Reference: openvpn3-core ssl/proto.hpp ProtoConfig::load_common(),
	// load_duration_parm(keepalive_timeout, "ping-restart", ...) line ~1255.
	PingRestart int

	// Mssfix is the MSS clamp value in bytes pushed by the server (from "mssfix N").
	// 0 means not pushed; client should use profile value or default (1492 for TCP, 1450 for UDP).
	//
	// Reference: openvpn3-core ssl/proto.hpp parse_pushed_mssfix() line ~925.
	Mssfix int

	// InactiveTimeout is the maximum idle time in seconds before disconnecting (from "inactive N [bytes]").
	// 0 means no inactive timeout.
	//
	// Reference: openvpn3-core client/cliproto.hpp process_inactive().
	InactiveTimeout int

	// InactiveBytes is the minimum bytes that must flow within InactiveTimeout seconds.
	// If 0, any byte resets the timer.
	//
	// Reference: openvpn3-core client/cliproto.hpp process_inactive() second arg.
	InactiveBytes int

	// KeyDerivation is the method used to derive data-channel keys.
	// Defaults to KeyDerivationTLSEKM (RFC 5705), set to KeyDerivationOpenVPNPRF
	// when the server does not push "protocol-flags tls-ekm" or "key-derivation tls-ekm".
	//
	// Reference: openvpn3-core ssl/proto.hpp parse_pushed_protocol_flags() line ~836.
	KeyDerivation KeyDerivation
}

// ParsePushReply extracts routing options from a PUSH_REPLY control message.
//
// The message is a comma-separated list of key-value directives, for example:
//
//	PUSH_REPLY,topology subnet,ifconfig 172.16.77.4 255.255.255.224,
//	  route-gateway 172.16.77.1,route 10.130.0.0 255.255.0.0,
//	  dhcp-option DNS 10.130.0.2,cipher AES-256-GCM
//
// ParsePushReply silently skips directives it does not recognise (forward
// compatibility). It returns an error only when a recognised directive is
// syntactically malformed.
func ParsePushReply(msg string) (*PushOptions, error) {
	// Strip the leading "PUSH_REPLY," prefix and any trailing null byte.
	msg = strings.TrimPrefix(msg, "PUSH_REPLY,")
	msg = strings.TrimRight(msg, "\x00")

	// Default to legacy PRF; switched to EKM when "protocol-flags tls-ekm" or
	// "key-derivation tls-ekm" is parsed below.
	// Reference: openvpn3-core ssl/proto.hpp parse_pushed_protocol_flags() line ~836:
	// servers that support EKM push "protocol-flags ... tls-ekm"; stock OpenVPN 2.x
	// does not, so the absence of the flag means legacy PRF.
	opts := &PushOptions{KeyDerivation: KeyDerivationOpenVPNPRF}

	// routeGateway holds the explicit route-gateway value; applied to Ifconfig
	// after all directives are parsed.
	var routeGateway net.IP

	for _, field := range strings.Split(msg, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		parts := strings.Fields(field)
		if len(parts) == 0 {
			continue
		}

		switch strings.ToLower(parts[0]) {
		case "topology":
			if len(parts) < 2 {
				return nil, fmt.Errorf("routing: topology: expected argument")
			}
			switch strings.ToLower(parts[1]) {
			case "subnet":
				opts.Topology = TopologySubnet
			case "net30":
				opts.Topology = TopologyNet30
			default:
				return nil, fmt.Errorf("routing: topology: unknown value %q (want subnet or net30)", parts[1])
			}

		case "route-gateway":
			if len(parts) < 2 {
				return nil, fmt.Errorf("routing: route-gateway: expected argument")
			}
			gw := net.ParseIP(parts[1])
			if gw == nil {
				return nil, fmt.Errorf("routing: route-gateway: invalid IP %q", parts[1])
			}
			routeGateway = gw.To4()

		case "ifconfig":
			if len(parts) < 3 {
				return nil, fmt.Errorf("routing: ifconfig: expected 2 args, got %d", len(parts)-1)
			}
			local := net.ParseIP(parts[1])
			if local == nil {
				return nil, fmt.Errorf("routing: ifconfig: invalid local IP %q", parts[1])
			}
			// parts[2] is either the subnet mask (topology subnet) or the P2P peer (net30).
			// We store it as Mask; for net30 the P2P peer also becomes the gateway.
			second := net.ParseIP(parts[2])
			if second == nil {
				return nil, fmt.Errorf("routing: ifconfig: invalid second arg %q", parts[2])
			}
			if opts.Topology == TopologySubnet {
				mask4 := second.To4()
				if mask4 == nil {
					return nil, fmt.Errorf("routing: ifconfig: subnet mask must be IPv4, got %q", parts[2])
				}
				opts.Ifconfig = &Ifconfig{
					Local: local.To4(),
					Mask:  net.IPMask(mask4),
				}
			} else {
				// Net30: second arg is the P2P peer; mask is /30.
				opts.Ifconfig = &Ifconfig{
					Local:   local.To4(),
					Mask:    net.CIDRMask(30, 32),
					Gateway: second.To4(),
				}
			}

		case "route":
			// route <network> <mask> [gateway]
			if len(parts) < 3 {
				return nil, fmt.Errorf("routing: route: expected network and mask, got %d arg(s)", len(parts)-1)
			}
			netIP := net.ParseIP(parts[1])
			if netIP == nil {
				return nil, fmt.Errorf("routing: route: invalid network %q", parts[1])
			}
			maskIP := net.ParseIP(parts[2])
			if maskIP == nil {
				return nil, fmt.Errorf("routing: route: invalid mask %q", parts[2])
			}
			mask4 := maskIP.To4()
			if mask4 == nil {
				return nil, fmt.Errorf("routing: route: mask must be IPv4, got %q", parts[2])
			}
			r := Route{
				Network: netIP.To4(),
				Mask:    net.IPMask(mask4),
			}
			if len(parts) >= 4 {
				gw := net.ParseIP(parts[3])
				if gw == nil {
					return nil, fmt.Errorf("routing: route: invalid gateway %q", parts[3])
				}
				r.Gateway = gw.To4()
			}
			opts.Routes = append(opts.Routes, r)

		case "cipher":
			// Reference: openvpn3-core ssl/proto.hpp
			// parse_pushed_data_channel_options() line ~753: server pushes the
			// negotiated cipher after NCP. Client validates it is in IV_CIPHERS.
			if len(parts) >= 2 {
				opts.Cipher = parts[1]
			}

		case "compress":
			// Reference: openvpn3-core ssl/proto.hpp parse_pushed_compression()
			// line ~875: opts "compress lz4" and "compress lz4-v2" map to ModeLZ4.
			if len(parts) >= 2 {
				switch strings.ToLower(parts[1]) {
				case "lz4", "lz4-v2":
					opts.Compression = compress.ModeLZ4
				case "stub-v2":
					opts.Compression = compress.ModeLZ4 // same framing as lz4
				}
			}

		case "comp-lzo":
			// Reference: openvpn3-core ssl/proto.hpp parse_pushed_compression()
			// line ~908: "comp-lzo no" maps to LZO_STUB (ModeLZO in Go).
			// Any comp-lzo value triggers ModeLZO (we don't compress, just flag it).
			opts.Compression = compress.ModeLZO

		case "ifconfig-ipv6":
			// ifconfig-ipv6 <addr/prefix> <gateway>
			// Reference: openvpn3-core tun/client/tunprop.hpp tun_prop_ifconfig_ipv6().
			if len(parts) < 2 {
				return nil, fmt.Errorf("routing: ifconfig-ipv6: expected addr/prefix")
			}
			ip6, prefix6, err := net.ParseCIDR(parts[1])
			if err != nil {
				return nil, fmt.Errorf("routing: ifconfig-ipv6: invalid addr/prefix %q: %w", parts[1], err)
			}
			_ = prefix6
			ones, _ := prefix6.Mask.Size()
			ifc6 := &Ifconfig6{Local: ip6, Prefix: ones}
			if len(parts) >= 3 {
				gw6 := net.ParseIP(parts[2])
				if gw6 == nil {
					return nil, fmt.Errorf("routing: ifconfig-ipv6: invalid gateway %q", parts[2])
				}
				ifc6.Gateway = gw6
			}
			opts.Ifconfig6 = ifc6

		case "route-ipv6":
			// route-ipv6 <net/prefix> [gateway]
			// Reference: openvpn3-core tun/client/tunprop.hpp tun_prop_route_ipv6().
			if len(parts) < 2 {
				return nil, fmt.Errorf("routing: route-ipv6: expected net/prefix")
			}
			_, net6, err := net.ParseCIDR(parts[1])
			if err != nil {
				return nil, fmt.Errorf("routing: route-ipv6: invalid net/prefix %q: %w", parts[1], err)
			}
			ones6, _ := net6.Mask.Size()
			r6 := Route6{Network: net6.IP, Prefix: ones6}
			if len(parts) >= 3 {
				gw6 := net.ParseIP(parts[2])
				if gw6 == nil {
					return nil, fmt.Errorf("routing: route-ipv6: invalid gateway %q", parts[2])
				}
				r6.Gateway = gw6
			}
			opts.Routes6 = append(opts.Routes6, r6)

		case "redirect-gateway":
			// redirect-gateway may be followed by flags (def1, bypass-dhcp, ipv6, etc.)
			for _, flag := range parts[1:] {
				if strings.EqualFold(flag, "ipv6") {
					opts.RedirectGateway6 = true
				}
			}
			// Any redirect-gateway directive (with or without ipv6 flag) enables IPv4 redirect,
			// unless it's ipv6-only (no def1/default4 flag check needed — set both to be safe).
			opts.RedirectGateway = true

		case "ping":
			// keepalive send interval — openvpn3-core ssl/proto.hpp
			// ProtoConfig::load_common() line ~1254:
			//   load_duration_parm(keepalive_ping, "ping", opt, 1, false, false)
			if len(parts) >= 2 {
				var v int
				if _, err := fmt.Sscanf(parts[1], "%d", &v); err == nil && v > 0 {
					opts.PingInterval = v
				}
			}

		case "ping-restart":
			// dead-link timeout — openvpn3-core ssl/proto.hpp
			// ProtoConfig::load_common() line ~1255:
			//   load_duration_parm(keepalive_timeout, "ping-restart", opt, 1, false, false)
			if len(parts) >= 2 {
				var v int
				if _, err := fmt.Sscanf(parts[1], "%d", &v); err == nil && v > 0 {
					opts.PingRestart = v
				}
			}

		case "mssfix":
			// Reference: openvpn3-core ssl/proto.hpp parse_pushed_mssfix() line ~925.
			if len(parts) >= 2 {
				var v int
				if _, err := fmt.Sscanf(parts[1], "%d", &v); err == nil && v >= 68 && v <= 65535 {
					opts.Mssfix = v
				}
			}

		case "protocol-flags":
			// Reference: openvpn3-core ssl/proto.hpp parse_pushed_protocol_flags()
			// line ~836: flag list may include "tls-ekm", "cc-exit", "dyn-tls-crypt".
			// Only "tls-ekm" affects key derivation.
			for _, flag := range parts[1:] {
				if strings.EqualFold(flag, "tls-ekm") {
					opts.KeyDerivation = KeyDerivationTLSEKM
				}
			}

		case "key-derivation":
			// Reference: openvpn3-core ssl/proto.hpp line ~863:
			// "key-derivation tls-ekm" is an alternative form of the same flag.
			if len(parts) >= 2 && strings.EqualFold(parts[1], "tls-ekm") {
				opts.KeyDerivation = KeyDerivationTLSEKM
			}

		case "inactive":
			// Reference: openvpn3-core client/cliproto.hpp process_inactive():
			// "inactive <timeout_secs> [bytes]"
			if len(parts) >= 2 {
				var v int
				if _, err := fmt.Sscanf(parts[1], "%d", &v); err == nil && v > 0 {
					opts.InactiveTimeout = v
				}
				if len(parts) >= 3 {
					var b int
					if _, err := fmt.Sscanf(parts[2], "%d", &b); err == nil && b >= 0 {
						opts.InactiveBytes = b
					}
				}
			}
		}
		// All other directives (dhcp-option, cipher, peer-id, etc.) are ignored.
	}

	// Apply the explicit route-gateway to subnet-topology Ifconfig.
	if opts.Ifconfig != nil && opts.Topology == TopologySubnet && routeGateway != nil {
		opts.Ifconfig.Gateway = routeGateway
	}

	return opts, nil
}
