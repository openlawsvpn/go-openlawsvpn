package vpn

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/dns"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
)

func TestResourceDriftEventsAreDeduplicated(t *testing.T) {
	p, err := profile.ParseString("remote vpn.example.com 443\nproto tcp-client\n")
	if err != nil {
		t.Fatal(err)
	}
	c := New(p)
	want := routing.RouteIdentity{Destination: "10.0.0.0/8", Gateway: "10.8.0.1", Interface: 7}
	admin := routing.RouteIdentity{Destination: want.Destination, Gateway: "192.0.2.1", Interface: 2}
	c.routeOwnership = routing.NewOwnership([]routing.RouteIdentity{want}, func(string) (*routing.RouteIdentity, error) { return &admin, nil }, nil, nil)

	dir := t.TempDir()
	dnsPath := filepath.Join(dir, "resolv.conf")
	os.WriteFile(dnsPath, []byte("nameserver 9.9.9.9\n"), 0644) //nolint:errcheck
	c.dnsOwnership = dns.NewFileOwnership(dnsPath, "", []byte("nameserver 10.0.0.2\n"))

	var routeEvents, dnsEvents int
	c.EventFn = func(event Event) {
		switch event.Type {
		case EventRouteDrift:
			routeEvents++
		case EventDNSDrift:
			dnsEvents++
		}
	}
	reported := make(map[string]bool)
	c.checkResourceDrift(reported)
	c.checkResourceDrift(reported)
	if routeEvents != 1 || dnsEvents != 1 {
		t.Fatalf("drift events route=%d dns=%d, want one each", routeEvents, dnsEvents)
	}
	if !net.ParseIP("192.0.2.1").Equal(net.ParseIP(admin.Gateway)) {
		t.Fatal("test administrator route was unexpectedly changed")
	}
}

func TestResourceDriftReportsSuccessfulRouteRestoration(t *testing.T) {
	p, err := profile.ParseString("remote vpn.example.com 443\nproto tcp-client\n")
	if err != nil {
		t.Fatal(err)
	}
	c := New(p)
	want := routing.RouteIdentity{Destination: "10.130.0.0/16", Gateway: "172.16.76.1", Interface: 5}
	present := false
	c.routeOwnership = routing.NewOwnership(
		[]routing.RouteIdentity{want},
		func(string) (*routing.RouteIdentity, error) {
			if !present {
				return nil, nil
			}
			got := want
			return &got, nil
		},
		func(routing.RouteIdentity) error {
			present = true
			return nil
		},
		nil,
	)

	var got Event
	c.EventFn = func(event Event) {
		if event.Type == EventRouteDrift {
			got = event
		}
	}
	c.checkResourceDrift(make(map[string]bool))
	if !present {
		t.Fatal("missing route was not restored")
	}
	if got.Resource != want.Destination || got.Message != "restored" {
		t.Fatalf("event = %#v, want restored %s", got, want.Destination)
	}
}
