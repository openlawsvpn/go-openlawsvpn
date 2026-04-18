package routing_test

import (
	"strings"
	"testing"

	"github.com/openlawsvpn/go-openvpn3/routing"
)

// FuzzParsePushReply feeds random strings to ParsePushReply to verify it
// never panics. PUSH_REPLY is received from the server and is the largest
// surface of untrusted structured data in the protocol.
func FuzzParsePushReply(f *testing.F) {
	// Seed: realistic AWS Client VPN PUSH_REPLY.
	f.Add("PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5,route 10.0.0.0 255.255.0.0,dhcp-option DNS 10.0.0.2,ping 1,ping-restart 20,cipher AES-256-GCM,key-derivation tls-ekm,peer-id 7")
	// Seed: minimal.
	f.Add("PUSH_REPLY,ifconfig 10.0.0.1 10.0.0.2")
	// Seed: redirect-gateway.
	f.Add("PUSH_REPLY,redirect-gateway def1,ifconfig 172.16.0.2 172.16.0.1")
	// Seed: subnet topology.
	f.Add("PUSH_REPLY,topology subnet,ifconfig 10.8.0.2 255.255.255.0")
	// Seed: compression options.
	f.Add("PUSH_REPLY,ifconfig 10.0.0.1 10.0.0.2,compress lz4-v2")
	// Seed: inactive timeout.
	f.Add("PUSH_REPLY,ifconfig 10.0.0.1 10.0.0.2,inactive 300 10000")
	// Seed: empty.
	f.Add("")
	// Seed: not a PUSH_REPLY.
	f.Add("AUTH_FAILED")
	// Seed: very long option values.
	f.Add("PUSH_REPLY,ifconfig " + strings.Repeat("1", 100) + " " + strings.Repeat("2", 100))
	// Seed: many unknown options.
	f.Add("PUSH_REPLY," + strings.Repeat("unknown-option val,", 100) + "ifconfig 10.0.0.1 10.0.0.2")

	f.Fuzz(func(t *testing.T, msg string) {
		_, _ = routing.ParsePushReply(msg)
	})
}
