//go:build darwin && !ios

package vpn

import (
	"fmt"
	"net"
	"os"

	"github.com/openlawsvpn/go-openlawsvpn/dns"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
	"github.com/openlawsvpn/go-openlawsvpn/tun"
)

// openNativeTUN opens a native utun interface via SYSPROTO_CONTROL, configures
// it, applies routes, and sets up DNS. Called from ConnectPhase2 when no
// TUNSetup callback is set (CLI / Homebrew path). Requires root / sudo.
func (c *Client) openNativeTUN(pushOpts *routing.PushOptions, dnsOpts *dns.Config, mtu int) (*tun.Device, error) {
	dev, err := tun.Open()
	if err != nil {
		return nil, fmt.Errorf("vpn: open utun device: %w (run as root or with sudo)", err)
	}

	cfg := tun.Config{MTU: mtu}
	if pushOpts.Ifconfig != nil {
		cfg.LocalIP = pushOpts.Ifconfig.Local
		if pushOpts.Topology == routing.TopologySubnet {
			cfg.Mask = pushOpts.Ifconfig.Mask
		} else {
			cfg.PeerIP = pushOpts.Ifconfig.Gateway
		}
	}
	if cfgErr := dev.Configure(cfg); cfgErr != nil {
		dev.Close()
		return nil, fmt.Errorf("vpn: configure utun device: %w", cfgErr)
	}

	iface, ifErr := net.InterfaceByName(dev.Name())
	if ifErr == nil {
		if pushOpts.Ifconfig6 != nil {
			if v6Err := routing.AddIPv6Addr(iface.Index, pushOpts.Ifconfig6.Local, pushOpts.Ifconfig6.Prefix); v6Err != nil {
				fmt.Fprintf(os.Stderr, "vpn: configure IPv6 address: %v\n", v6Err)
			}
		}
		if routeErr := routing.ApplyRoutes(pushOpts, iface.Index); routeErr != nil {
			fmt.Fprintf(os.Stderr, "vpn: apply routes: %v\n", routeErr)
		}
	}

	dnsBackend, dnsErr := dns.Apply(dnsOpts, dev.Name(), c.dnsBackup)
	c.dnsBackend = dnsBackend
	if dnsErr != nil {
		fmt.Fprintf(os.Stderr, "vpn: apply DNS: %v\n", dnsErr)
	}
	return dev, nil
}
