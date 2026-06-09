//go:build !android && !ios && !darwin

package vpn

import (
	"fmt"
	"net"
	"os"

	"github.com/openlawsvpn/go-openlawsvpn/dns"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
	"github.com/openlawsvpn/go-openlawsvpn/tun"
)

// openNativeTUN opens /dev/net/tun, configures the interface, applies routes
// and DNS. Called from ConnectPhase2 on Linux when no TUNSetup callback is set.
func (c *Client) openNativeTUN(pushOpts *routing.PushOptions, dnsOpts *dns.Config, mtu int) (*tun.Device, error) {
	dev, err := tun.Open("")
	if err != nil {
		return nil, fmt.Errorf("vpn: open TUN device: %w (run as root or grant CAP_NET_ADMIN)", err)
	}
	cfg := tun.Config{
		LocalIP: pushOpts.Ifconfig.Local,
		MTU:     mtu,
	}
	if pushOpts.Topology == routing.TopologySubnet {
		cfg.Mask = pushOpts.Ifconfig.Mask
	} else {
		cfg.PeerIP = pushOpts.Ifconfig.Gateway
	}
	if cfgErr := dev.Configure(cfg); cfgErr != nil {
		dev.Close()
		return nil, fmt.Errorf("vpn: configure TUN device: %w", cfgErr)
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
	c.dnsBackup = ""
	dnsBackend, dnsErr := dns.Apply(dnsOpts, dev.Name(), c.dnsBackup)
	c.dnsBackend = dnsBackend
	if dnsErr != nil {
		fmt.Fprintf(os.Stderr, "vpn: apply DNS: %v\n", dnsErr)
	}
	return dev, nil
}
