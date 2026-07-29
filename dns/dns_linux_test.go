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
