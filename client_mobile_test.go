package vpn

import (
	"encoding/json"
	"net"
	"reflect"
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/dns"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
)

func TestBuildIfconfigJSONIncludesDNSDomains(t *testing.T) {
	gotJSON := buildIfconfigJSON(&routing.PushOptions{}, &dns.Config{
		Servers:       []net.IP{net.ParseIP("10.130.0.2")},
		SearchDomains: []string{"corp.example"},
		RouteDomains:  []string{"internal.company.com", "us-east-2.eks.amazonaws.com"},
	}, 1500)

	var got struct {
		DNS           []string `json:"dns"`
		SearchDomains []string `json:"search_domains"`
		RouteDomains  []string `json:"route_domains"`
	}
	if err := json.Unmarshal([]byte(gotJSON), &got); err != nil {
		t.Fatalf("unmarshal tunnel config: %v", err)
	}

	if want := []string{"10.130.0.2"}; !reflect.DeepEqual(got.DNS, want) {
		t.Errorf("dns = %v, want %v", got.DNS, want)
	}
	if want := []string{"corp.example"}; !reflect.DeepEqual(got.SearchDomains, want) {
		t.Errorf("search_domains = %v, want %v", got.SearchDomains, want)
	}
	if want := []string{"internal.company.com", "us-east-2.eks.amazonaws.com"}; !reflect.DeepEqual(got.RouteDomains, want) {
		t.Errorf("route_domains = %v, want %v", got.RouteDomains, want)
	}
}

func TestBuildIfconfigJSONIncludesIPv6(t *testing.T) {
	gotJSON := buildIfconfigJSON(&routing.PushOptions{
		Ifconfig6: &routing.Ifconfig6{
			Local:   net.ParseIP("2001:db8::2"),
			Prefix:  64,
			Gateway: net.ParseIP("2001:db8::1"),
		},
		RedirectGateway6: true,
	}, nil, 1420)

	var got struct {
		Local            string `json:"local6"`
		Prefix           int    `json:"prefix6"`
		Gateway          string `json:"gateway6"`
		RedirectGateway6 bool   `json:"redirect_gateway6"`
	}
	if err := json.Unmarshal([]byte(gotJSON), &got); err != nil {
		t.Fatalf("unmarshal tunnel config: %v", err)
	}
	if got.Local != "2001:db8::2" || got.Prefix != 64 || got.Gateway != "2001:db8::1" || !got.RedirectGateway6 {
		t.Fatalf("IPv6 config = %+v", got)
	}
}
