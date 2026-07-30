package vpn

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

func TestLogRemoteCertificateAtVerb4(t *testing.T) {
	c := New(&profile.Profile{Verb: 4})
	var message string
	c.EventFn = func(e Event) { message = e.Message }
	c.logRemoteCertificate(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{
			Subject:      pkix.Name{CommonName: "vpn.example.com"},
			Issuer:       pkix.Name{Country: []string{"US"}, Organization: []string{"Example"}, CommonName: "Example CA"},
			SerialNumber: big.NewInt(42),
			NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
			DNSNames:     []string{"vpn.example.com"},
		}},
		VerifiedChains: [][]*x509.Certificate{{}},
	}, "vpn.example.com")

	for _, want := range []string{
		"verified", "subject=CN=vpn.example.com", "issuer=C=US, O=Example, CN=Example CA", "serial=2A",
		"notBefore=Jan  1 00:00:00 2026 GMT", "DNS:vpn.example.com", "sha256 Fingerprint=",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("certificate log %q does not contain %q", message, want)
		}
	}
}

func TestCertificateSerialNumberPreservesDERLeadingZero(t *testing.T) {
	// Certificate ::= SEQUENCE { TBSCertificate, signatureAlgorithm, signature }
	// TBSCertificate starts with version [0] then the serial-number INTEGER.
	raw := []byte{
		0x30, 0x0f, // Certificate sequence
		0x30, 0x08, // TBSCertificate sequence
		0xa0, 0x03, 0x02, 0x01, 0x02, // version v3
		0x02, 0x01, 0x06, // serial number 06
		0x30, 0x00, // signature algorithm
		0x03, 0x01, 0x00, // signature value
	}
	if got := certificateSerialNumber(&x509.Certificate{Raw: raw, SerialNumber: big.NewInt(6)}); got != "06" {
		t.Errorf("certificateSerialNumber() = %q, want 06", got)
	}
}
