//go:build darwin && !ios

package vpn

import (
	"fmt"
	"net"

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
		// macOS utun is always IFF_POINTOPOINT regardless of server topology.
		// SIOCSIFNETMASK does not create a connected subnet route on a P2P
		// interface, so the pushed gateway (e.g. 172.16.76.129) has no route
		// via utun and /sbin/route resolves it via the default (en0). Setting
		// SIOCSIFDSTADDR instead makes the kernel install a /32 host route to
		// the gateway via utun, allowing all subsequent pushed routes to
		// resolve correctly. Same approach used by WireGuard-go on macOS.
		cfg.PeerIP = pushOpts.Ifconfig.Gateway
	}
	if cfgErr := dev.Configure(cfg); cfgErr != nil {
		dev.Close()
		return nil, fmt.Errorf("vpn: configure utun device: %w", cfgErr)
	}

	iface, ifErr := net.InterfaceByName(dev.Name())
	if ifErr == nil {
		if pushOpts.Ifconfig6 != nil {
			if v6Err := routing.AddIPv6Addr(iface.Index, pushOpts.Ifconfig6.Local, pushOpts.Ifconfig6.Prefix); v6Err != nil {
				c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: configure IPv6 address: %v", v6Err)})
			}
		}
		c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: applying %d routes via %s", len(pushOpts.Routes), dev.Name())})
		if routeErr := routing.ApplyRoutes(pushOpts, iface.Index); routeErr != nil {
			c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: apply routes: %v", routeErr)})
		} else {
			c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: routes applied via %s", dev.Name())})
		}
	} else {
		c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: interface lookup failed: %v", ifErr)})
	}

	dnsBackend, dnsErr := dns.Apply(dnsOpts, dev.Name(), c.dnsBackup)
	c.dnsBackend = dnsBackend
	if dnsErr != nil {
		c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: apply DNS: %v", dnsErr)})
	} else {
		c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: DNS applied (backend=%d)", dnsBackend)})
	}
	return dev, nil
}
