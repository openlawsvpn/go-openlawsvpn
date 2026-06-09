//go:build ios

package vpn

import (
	"fmt"

	"github.com/openlawsvpn/go-openlawsvpn/dns"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
	"github.com/openlawsvpn/go-openlawsvpn/tun"
)

// openNativeTUN is not used on iOS — NEPacketTunnelProvider provides the TUN fd.
// If called without TUNSetup wired (e.g. in tests), returns an error.
func (c *Client) openNativeTUN(pushOpts *routing.PushOptions, _ *dns.Config, _ int) (*tun.Device, error) {
	return nil, fmt.Errorf("vpn: openNativeTUN called on iOS without TUNSetup wired")
}
