//go:build linux

package dns

import (
	"net"
	"testing"
)

func TestResolvedLinkDomainsIncludesRouteOnlyRoot(t *testing.T) {
	cfg := &Config{
		Servers:       []net.IP{net.ParseIP("10.130.0.2")},
		SearchDomains: []string{"internal.example"},
	}

	domains := resolvedLinkDomains(cfg)

	want := []resolvedDomainEntry{
		{Domain: ".", RouteOnly: true},
		{Domain: "internal.example", RouteOnly: false},
	}
	if len(domains) != len(want) {
		t.Fatalf("domain count = %d, want %d", len(domains), len(want))
	}
	for i := range want {
		if domains[i] != want[i] {
			t.Errorf("domain[%d] = %#v, want %#v", i, domains[i], want[i])
		}
	}
}

func TestResolvedLinkDomainsUsesExplicitRoutesForSplitDNS(t *testing.T) {
	cfg := &Config{
		Servers:      []net.IP{net.ParseIP("10.130.0.2")},
		RouteDomains: []string{"internal.company.com", "us-east-2.eks.amazonaws.com"},
	}

	domains := resolvedLinkDomains(cfg)
	want := []resolvedDomainEntry{
		{Domain: "internal.company.com", RouteOnly: true},
		{Domain: "us-east-2.eks.amazonaws.com", RouteOnly: true},
	}
	if len(domains) != len(want) {
		t.Fatalf("domain count = %d, want %d", len(domains), len(want))
	}
	for i := range want {
		if domains[i] != want[i] {
			t.Errorf("domain[%d] = %#v, want %#v", i, domains[i], want[i])
		}
	}
}

func TestResolvedStateIncludesAddressesAndDomainKinds(t *testing.T) {
	cfg := &Config{
		Servers:       []net.IP{net.ParseIP("10.130.0.2"), net.ParseIP("2001:db8::53")},
		SearchDomains: []string{"search.example"},
		RouteDomains:  []string{"route.example"},
	}
	addrs, domains := resolvedState(cfg)
	if string(addrs) != "10.130.0.2\x002001:db8::53\x00" {
		t.Fatalf("addresses = %q", addrs)
	}
	if string(domains) != "route.example\x01\x00search.example\x00\x00" {
		t.Fatalf("domains = %q", domains)
	}
}
