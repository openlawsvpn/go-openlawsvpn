//go:build android

package vpn

import (
	"fmt"

	"github.com/openlawsvpn/go-openlawsvpn/dns"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
	"github.com/openlawsvpn/go-openlawsvpn/tun"
)

// openNativeTUN is not used on Android — VpnService provides the TUN fd.
// If called without TUNSetup wired (e.g. in tests), returns an error.
func (c *Client) openNativeTUN(pushOpts *routing.PushOptions, _ *dns.Config, _ int) (*tun.Device, error) {
	return nil, fmt.Errorf("vpn: openNativeTUN called on Android without TUNSetup wired")
}
