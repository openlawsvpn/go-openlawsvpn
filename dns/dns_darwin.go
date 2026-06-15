//go:build darwin && !ios

// macOS DNS configuration for the CLI (Path A — native utun).
//
// Two backends, tried in order:
//  1. networksetup -setdnsservers <service> <servers…>  — scopes DNS to the
//     active network service; survives sleep/wake without polluting global state.
//  2. /etc/resolv.conf overwrite (same fallback as Linux).
//
// On Path B (GUI / NEPacketTunnelProvider) the OS applies DNS via
// setTunnelNetworkSettings; these functions are never called.
package dns

import (
	"fmt"
	"os/exec"
	"strings"
)

// Apply applies cfg using the best available backend for macOS:
//  1. networksetup -setdnsservers on the primary IPv4 service (Wi-Fi or Ethernet).
//  2. /etc/resolv.conf overwrite as a fallback.
//
// Returns the Backend used so Revert can call the matching cleanup.
func Apply(cfg *Config, ifName, backupPath string) (Backend, error) {
	if cfg == nil || len(cfg.Servers) == 0 {
		return BackendNone, nil
	}

	if svc, err := primaryService(); err == nil {
		if err := applyNetworkSetup(svc, cfg); err == nil {
			return BackendResolved, nil
		}
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
		svc, err := primaryService()
		if err != nil {
			return err
		}
		return revertNetworkSetup(svc)
	case BackendResolvConf:
		return RestoreResolvConf(backupPath)
	default:
		return nil
	}
}

// applyNetworkSetup calls: networksetup -setdnsservers <service> <ip> [<ip>…]
func applyNetworkSetup(service string, cfg *Config) error {
	args := []string{"-setdnsservers", service}
	for _, srv := range cfg.Servers {
		args = append(args, srv.String())
	}
	out, err := exec.Command("/usr/sbin/networksetup", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("networksetup -setdnsservers: %w — %s", err, string(out))
	}
	return nil
}

// revertNetworkSetup clears custom DNS: networksetup -setdnsservers <service> empty
func revertNetworkSetup(service string) error {
	out, err := exec.Command("/usr/sbin/networksetup", "-setdnsservers", service, "empty").CombinedOutput()
	if err != nil {
		return fmt.Errorf("networksetup -setdnsservers empty: %w — %s", err, string(out))
	}
	return nil
}

// primaryService returns the name of the primary IPv4 network service
// (e.g. "Wi-Fi" or "Ethernet") by parsing: networksetup -listnetworkserviceorder
func primaryService() (string, error) {
	out, err := exec.Command("/usr/sbin/networksetup", "-listnetworkserviceorder").Output()
	if err != nil {
		return "", fmt.Errorf("networksetup -listnetworkserviceorder: %w", err)
	}
	// Output looks like:
	//   (1) Wi-Fi
	//   (Hardware Port: Wi-Fi, Device: en0)
	//   (2) Ethernet
	//   ...
	// Pick the first non-disabled service name.
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if len(line) > 3 && line[0] == '(' && line[1] >= '1' && line[1] <= '9' {
			// Strip leading "(N) "
			if idx := strings.Index(line, ") "); idx >= 0 {
				return strings.TrimSpace(line[idx+2:]), nil
			}
		}
	}
	return "", fmt.Errorf("could not determine primary network service")
}
