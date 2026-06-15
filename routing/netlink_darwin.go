//go:build darwin && !ios

// Route management for the macOS CLI (Path A — native utun).
//
// macOS does not expose Linux rtnetlink(7); routes are added via the BSD
// route(8) binary using exec.Command. This is the same approach used by
// WireGuard-tools, OpenVPN3-cli, and Homebrew-distributed VPN clients on macOS.
//
// On the GUI path (NEPacketTunnelProvider / Path B) the OS applies routes via
// setTunnelNetworkSettings; these functions are never called.
package routing

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// ApplyRoutes adds the routes described by opts to the macOS routing table via
// the route(8) command. ifIndex is unused on macOS (the interface name is
// looked up from the index). Requires root / sudo.
func ApplyRoutes(opts *PushOptions, ifIndex int) error {
	if opts == nil {
		return nil
	}

	ifName, err := ifNameByIndex(ifIndex)
	if err != nil {
		return fmt.Errorf("routing: interface index %d: %w", ifIndex, err)
	}

	var defaultGW net.IP
	if opts.Ifconfig != nil {
		defaultGW = opts.Ifconfig.Gateway
	}

	// On macOS, utun is always IFF_POINTOPOINT. SIOCSIFDSTADDR sets the peer
	// address but the kernel does not reliably install a /32 host route via
	// separate ioctls (unlike the combined `ifconfig utun9 <local> <peer>`
	// command). Add the host route explicitly so that subsequent pushed routes
	// that use the gateway as next-hop resolve via utun instead of via the
	// default route (en0).
	if opts.Ifconfig != nil && defaultGW != nil {
		if err := routeAdd(defaultGW, net.CIDRMask(32, 32), nil, ifName); err != nil {
			// "entry exists" is fine — SIOCSIFDSTADDR may have already created it.
			if !isRouteExists(err) {
				return fmt.Errorf("routing: host route to gateway %s: %w", defaultGW, err)
			}
		}
	}

	// Explicit routes from PUSH_REPLY.
	for _, r := range opts.Routes {
		gw := r.Gateway
		if gw == nil {
			gw = defaultGW
		}
		if err := routeAdd(r.Network, r.Mask, gw, ifName); err != nil {
			return fmt.Errorf("routing: add route %s: %w", r.Network, err)
		}
	}

	// Default route (redirect-gateway).
	if opts.RedirectGateway {
		if err := routeAdd(net.IPv4(0, 0, 0, 0), net.CIDRMask(0, 32), defaultGW, ifName); err != nil {
			return fmt.Errorf("routing: default route: %w", err)
		}
	}

	return nil
}

// DeleteRoutes removes routes added by ApplyRoutes. Errors are collected and
// returned as a single combined error so cleanup continues past failures.
func DeleteRoutes(opts *PushOptions, ifIndex int) error {
	if opts == nil {
		return nil
	}

	ifName, err := ifNameByIndex(ifIndex)
	if err != nil {
		return fmt.Errorf("routing: interface index %d: %w", ifIndex, err)
	}

	var defaultGW net.IP
	if opts.Ifconfig != nil {
		defaultGW = opts.Ifconfig.Gateway
	}

	var errs []error
	save := func(e error) {
		if e != nil {
			errs = append(errs, e)
		}
	}

	// Remove the gateway host route added by ApplyRoutes.
	if opts.Ifconfig != nil && defaultGW != nil {
		save(routeDel(defaultGW, net.CIDRMask(32, 32), nil, ifName))
	}
	for _, r := range opts.Routes {
		gw := r.Gateway
		if gw == nil {
			gw = defaultGW
		}
		save(routeDel(r.Network, r.Mask, gw, ifName))
	}
	if opts.RedirectGateway {
		save(routeDel(net.IPv4(0, 0, 0, 0), net.CIDRMask(0, 32), defaultGW, ifName))
	}

	if len(errs) > 0 {
		return fmt.Errorf("routing: delete routes: %v", errs)
	}
	return nil
}

// AddIPv6Addr is a no-op on macOS — IPv6 address is set by Configure() via
// SIOCSIFADDR_IN6 (not implemented yet; macOS CLI is IPv4-only for now).
func AddIPv6Addr(_ int, _ net.IP, _ int) error { return nil }

// InterfaceIndex returns the OS interface index for ifName.
func InterfaceIndex(ifName string) (int, error) {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return 0, err
	}
	return iface.Index, nil
}

// ifNameByIndex returns the interface name for the given index.
func ifNameByIndex(ifIndex int) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Index == ifIndex {
			return iface.Name, nil
		}
	}
	return "", fmt.Errorf("no interface with index %d", ifIndex)
}

// routeAdd adds an IPv4 route: route add [-net|-host] <dst/mask> [-interface <if>|-gateway <gw>]
func routeAdd(dst net.IP, mask net.IPMask, gw net.IP, ifName string) error {
	return routeCmd("add", dst, mask, gw, ifName)
}

// routeDel deletes an IPv4 route.
func routeDel(dst net.IP, mask net.IPMask, gw net.IP, ifName string) error {
	return routeCmd("delete", dst, mask, gw, ifName)
}

// isRouteExists returns true when route(8) reports "entry already exists".
func isRouteExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "entry already exists")
}

func routeCmd(verb string, dst net.IP, mask net.IPMask, gw net.IP, ifName string) error {
	ones, bits := mask.Size()

	var args []string
	args = append(args, "-n", verb)

	if ones == 32 && bits == 32 {
		// Host route.
		args = append(args, "-host", dst.String())
	} else {
		// Network route: pass as CIDR — route(8) on macOS accepts x.x.x.x/prefix.
		args = append(args, "-net", fmt.Sprintf("%s/%d", dst.String(), ones))
	}

	if gw != nil {
		args = append(args, gw.String())
	} else {
		args = append(args, "-interface", ifName)
	}

	out, err := exec.Command("/sbin/route", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("/sbin/route %v: %w — %s", args, err, string(out))
	}
	return nil
}
