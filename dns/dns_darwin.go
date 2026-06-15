//go:build darwin && !ios

// macOS DNS configuration for the CLI (Path A — native utun).
//
// DNS is injected into SCDynamicStore via `scutil --set` scoped to the
// VPN's own service key (State:/Network/Service/<ifName>/DNS). This is
// the same mechanism used by the OpenVPN3 macOS client and WireGuard-macOS:
// mDNSResponder picks up the entry immediately without polluting the Wi-Fi
// or Ethernet service, and the entry disappears automatically when the
// interface goes down.
//
// Fallback: /etc/resolv.conf overwrite (rarely needed; scutil works on all
// modern macOS versions with SIP disabled or running as root).
//
// On Path B (GUI / NEPacketTunnelProvider) the OS applies DNS via
// setTunnelNetworkSettings; these functions are never called.
package dns

import (
	"fmt"
	"os/exec"
	"strings"
)

// Apply injects VPN DNS via SCDynamicStore (scutil) scoped to ifName.
// Falls back to /etc/resolv.conf if scutil fails.
func Apply(cfg *Config, ifName, backupPath string) (Backend, error) {
	if cfg == nil || len(cfg.Servers) == 0 {
		return BackendNone, nil
	}

	if err := applyScutil(cfg, ifName); err == nil {
		return BackendResolved, nil
	}

	// Fallback: overwrite /etc/resolv.conf.
	if backupPath != "" {
		if err := BackupResolvConf(backupPath); err != nil {
			return BackendNone, err
		}
	}
	return BackendResolvConf, ApplyResolvConf(cfg)
}

// Revert removes DNS settings applied by Apply.
func Revert(backend Backend, ifName, backupPath string) error {
	switch backend {
	case BackendResolved:
		return revertScutil(ifName)
	case BackendResolvConf:
		return RestoreResolvConf(backupPath)
	default:
		return nil
	}
}

// scutil script that injects a DNS entry into SCDynamicStore for the given
// interface. mDNSResponder picks this up immediately; the entry is scoped to
// the VPN service key and does not affect Wi-Fi or Ethernet.
//
// Equivalent to what the OpenVPN3 macOS client writes via the
// openssl_app_proxy helper's dns_setup() call (openvpn3/client/ovpncli.cpp).
func applyScutil(cfg *Config, ifName string) error {
	var script strings.Builder
	script.WriteString("d.init\n")
	script.WriteString("d.add ServerAddresses *")
	for _, srv := range cfg.Servers {
		script.WriteString(" ")
		script.WriteString(srv.String())
	}
	script.WriteString("\n")
	if len(cfg.SearchDomains) > 0 {
		script.WriteString("d.add SearchDomains *")
		for _, dom := range cfg.SearchDomains {
			script.WriteString(" ")
			script.WriteString(dom)
		}
		script.WriteString("\n")
	}
	// SupplementalMatchDomains with empty string makes this a split-DNS
	// entry; mDNSResponder will use this resolver only for VPN-pushed domains
	// (or for all domains if no match domains are specified and the tunnel
	// is the default route).
	script.WriteString("d.add SupplementalMatchDomains *\n")
	script.WriteString(fmt.Sprintf("set State:/Network/Service/%s/DNS\n", ifName))

	cmd := exec.Command("/usr/sbin/scutil")
	cmd.Stdin = strings.NewReader(script.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scutil DNS inject: %w — %s", err, string(out))
	}
	return nil
}

// revertScutil removes the SCDynamicStore DNS entry for ifName.
func revertScutil(ifName string) error {
	script := fmt.Sprintf("remove State:/Network/Service/%s/DNS\n", ifName)
	cmd := exec.Command("/usr/sbin/scutil")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scutil DNS remove: %w — %s", err, string(out))
	}
	return nil
}
