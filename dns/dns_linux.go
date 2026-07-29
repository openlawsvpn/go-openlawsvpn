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

// resolvedDomainEntry is the (string domain, bool route_only) tuple expected
// by org.freedesktop.resolve1.Manager.SetLinkDomains.
type resolvedDomainEntry struct {
	Domain    string
	RouteOnly bool
}

func resolvedLinkDomains(cfg *Config) []resolvedDomainEntry {
	var domains []resolvedDomainEntry
	if len(cfg.RouteDomains) == 0 {
		// A route-only root domain, represented as {".", true} on the D-Bus
		// API, matches every multi-label DNS name. This prevents
		// systemd-resolved from treating all default DNS links (for example the
		// Wi-Fi resolver) as equal candidates.
		domains = append(domains, resolvedDomainEntry{Domain: ".", RouteOnly: true})
	} else {
		// Explicit DOMAIN-ROUTE values select split DNS. A route-only domain is
		// used for routing but is never appended to single-label lookups.
		for _, d := range cfg.RouteDomains {
			domains = append(domains, resolvedDomainEntry{Domain: d, RouteOnly: true})
		}
	}
	for _, d := range cfg.SearchDomains {
		domains = append(domains, resolvedDomainEntry{Domain: d, RouteOnly: false})
	}
	return domains
}

func ifIndex(ifName string) (int32, error) {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return 0, fmt.Errorf("dns: interface %q: %w", ifName, err)
	}
	return int32(iface.Index), nil
}

// ApplyResolved configures DNS via systemd-resolved over D-Bus (no polkit).
//
// It calls org.freedesktop.resolve1.Manager.SetLinkDNS and SetLinkDomains,
// scoping the servers to the TUN interface ifName. Without explicit
// DOMAIN-ROUTE values, a route-only root domain (~.) makes the VPN resolver
// preferred for all multi-label queries. Explicit routes select split DNS.
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

	domains := resolvedLinkDomains(cfg)
	if err := obj.Call(resolvedIface+".SetLinkDomains", 0, idx, domains).Err; err != nil {
		// SetLinkDNS has already changed resolved state. Undo it before letting
		// Apply fall back to resolv.conf, so the two backends cannot conflict.
		_ = obj.Call(resolvedIface+".RevertLink", 0, idx).Err
		return fmt.Errorf("dns: SetLinkDomains: %w", err)
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
