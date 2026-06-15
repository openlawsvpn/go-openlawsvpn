//go:build ios

// iOS DNS stubs — DNS is configured via NEPacketTunnelNetworkSettings;
// the Go layer never calls Apply or Revert directly.
package dns

// Apply is a no-op on iOS — DNS is configured via setTunnelNetworkSettings.
func Apply(_ *Config, _, _ string) (Backend, error) { return BackendNone, nil }

// Revert is a no-op on iOS.
func Revert(_ Backend, _, _ string) error { return nil }
