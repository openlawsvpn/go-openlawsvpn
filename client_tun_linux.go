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
		// When redirect-gateway is active, add a /32 bypass route for the VPN
		// server BEFORE the default route is installed.  Without this, the new
		// 0.0.0.0/0 via tun overrides the physical-interface route to the server,
		// causing the VPN's own TCP connection to loop through the tunnel and die.
		if pushOpts.RedirectGateway {
			if sip := net.ParseIP(c.phase1IP); sip != nil {
				if gw, gwErr := routing.LookupGateway(sip); gwErr == nil {
					if gw == nil {
						fmt.Fprintf(os.Stderr, "vpn: redirect-gateway: server %s is direct-link, no bypass needed\n", sip)
					} else if berr := routing.AddBypassRoute(sip, gw); berr == nil {
						fmt.Fprintf(os.Stderr, "vpn: redirect-gateway bypass route: %s via %s\n", sip, gw)
						c.serverBypassIP = sip
						c.serverBypassGW = gw
					} else {
						fmt.Fprintf(os.Stderr, "vpn: add bypass route: %v\n", berr)
					}
				} else {
					fmt.Fprintf(os.Stderr, "vpn: lookup gateway for bypass: %v\n", gwErr)
				}
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
