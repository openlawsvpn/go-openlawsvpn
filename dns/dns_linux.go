//go:build linux

// Linux DNS configuration: systemd-resolved via D-Bus, with /etc/resolv.conf fallback.
package dns

import (
	"fmt"
	"net"
	"os"

	"github.com/godbus/dbus/v5"
)

// resolvedObject is the D-Bus object path for the systemd-resolved Manager.
const resolvedDest = "org.freedesktop.resolve1"
const resolvedPath = dbus.ObjectPath("/org/freedesktop/resolve1")
const resolvedIface = "org.freedesktop.resolve1.Manager"

func ifIndex(ifName string) (int32, error) {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return 0, fmt.Errorf("dns: interface %q: %w", ifName, err)
	}
	return int32(iface.Index), nil
}

// ApplyResolved configures DNS via systemd-resolved over D-Bus (no polkit).
//
// It calls org.freedesktop.resolve1.Manager.SetLinkDNS, SetLinkDomains and
// SetLinkDefaultRoute, scoping the pushed servers to the TUN interface ifName
// and routing ALL DNS queries to them (matching the AWS Client VPN client,
// which installs the pushed servers as the machine's global resolvers).
func ApplyResolved(cfg *Config, ifName string) error {
	if cfg == nil || len(cfg.Servers) == 0 {
		return nil
	}

	idx, err := ifIndex(ifName)
	if err != nil {
		return err
	}

	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("dns: system bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object(resolvedDest, resolvedPath)

	type addrEntry struct {
		Family  int32
		Address []byte
	}
	var addrs []addrEntry
	for _, srv := range cfg.Servers {
		ip4 := srv.To4()
		if ip4 != nil {
			addrs = append(addrs, addrEntry{Family: 2, Address: []byte(ip4)})
		} else {
			addrs = append(addrs, addrEntry{Family: 10, Address: []byte(srv.To16())})
		}
	}
	if err := obj.Call(resolvedIface+".SetLinkDNS", 0, idx, addrs).Err; err != nil {
		return fmt.Errorf("dns: SetLinkDNS: %w", err)
	}

	// Route ALL DNS queries to the VPN-pushed servers.
	//
	// systemd-resolved (the default resolver on Fedora) will not consult a
	// link's DNS servers unless a domain is associated with the link or the link
	// is the default DNS route. AWS Client VPN pushes DNS servers but never a
	// domain, so without this the pushed resolver sits unused and internal names
	// (private hosted zones, VPC interface endpoints) fail to resolve. The "~."
	// route-only wildcard makes tun0 the default DNS route, so every query goes
	// to the pushed servers — the same effect as the AWS client, which installs
	// them as the machine's global resolv.conf nameservers.
	//
	// The bool is resolved's route_only flag: true = routing domain (~domain),
	// used only to pick which link answers a query, never appended as a search
	// suffix. "." must be route-only; any pushed search domains are added as real
	// search domains (route_only=false) so single-label lookups still work.
	type domainEntry struct {
		Domain    string
		RouteOnly bool
	}
	domains := []domainEntry{{Domain: ".", RouteOnly: true}}
	for _, d := range cfg.SearchDomains {
		domains = append(domains, domainEntry{Domain: d, RouteOnly: false})
	}
	if err := obj.Call(resolvedIface+".SetLinkDomains", 0, idx, domains).Err; err != nil {
		return fmt.Errorf("dns: SetLinkDomains: %w", err)
	}

	// Explicitly flag tun0 as the default DNS route. The "~." domain above
	// already achieves this on every systemd version we support; this is
	// belt-and-suspenders and is treated as non-fatal if unsupported.
	if err := obj.Call(resolvedIface+".SetLinkDefaultRoute", 0, idx, true).Err; err != nil {
		fmt.Fprintf(os.Stderr, "dns: SetLinkDefaultRoute (non-fatal): %v\n", err)
	}

	return nil
}

// RevertResolved removes per-interface DNS settings set by ApplyResolved.
func RevertResolved(ifName string) error {
	idx, err := ifIndex(ifName)
	if err != nil {
		return err
	}

	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("dns: system bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object(resolvedDest, resolvedPath)
	if err := obj.Call(resolvedIface+".RevertLink", 0, idx).Err; err != nil {
		return fmt.Errorf("dns: RevertLink: %w", err)
	}
	return nil
}

// Apply applies cfg using the best available backend:
//  1. Try ApplyResolved (direct D-Bus to systemd-resolved, no polkit).
//  2. Fall back to ApplyResolvConf (overwrites /etc/resolv.conf).
func Apply(cfg *Config, ifName, backupPath string) (Backend, error) {
	if cfg == nil || len(cfg.Servers) == 0 {
		return BackendNone, nil
	}
	if err := ApplyResolved(cfg, ifName); err == nil {
		return BackendResolved, nil
	} else {
		fmt.Fprintf(os.Stderr, "dns: resolved D-Bus failed (%v), falling back to /etc/resolv.conf\n", err)
	}
	if backupPath != "" {
		if err := BackupResolvConf(backupPath); err != nil {
			return BackendNone, err
		}
	}
	return BackendResolvConf, ApplyResolvConf(cfg)
}

// Revert removes the DNS configuration applied by Apply.
func Revert(backend Backend, ifName, backupPath string) error {
	switch backend {
	case BackendResolved:
		return RevertResolved(ifName)
	case BackendResolvConf:
		return RestoreResolvConf(backupPath)
	default:
		return nil
	}
}
