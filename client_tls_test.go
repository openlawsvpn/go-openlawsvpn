package vpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

func TestBuildTLSConfigRejectsLegacyCommonNameByDefault(t *testing.T) {
	caPEM, serverCert := legacyTestServerCertificate(t, "vpn.example.test", nil)
	cfg, err := buildTLSConfig(&profile.Profile{Remote: "vpn.example.test", CA: caPEM}, nil)
	if err != nil {
		t.Fatalf("buildTLSConfig() error: %v", err)
	}
	if err := testTLSHandshake(cfg, serverCert); err == nil {
		t.Fatal("TLS handshake unexpectedly accepted a Common Name-only certificate")
	}
}

func TestBuildTLSConfigAllowsExactLegacyCommonName(t *testing.T) {
	caPEM, serverCert := legacyTestServerCertificate(t, "vpn.example.test", nil)
	cfg, err := buildTLSConfig(&profile.Profile{
		Remote:        "vpn.example.test",
		CA:            caPEM,
		AllowLegacyCN: true,
	}, nil)
	if err != nil {
		t.Fatalf("buildTLSConfig() error: %v", err)
	}
	if err := testTLSHandshake(cfg, serverCert); err != nil {
		t.Fatalf("TLS handshake with exact legacy Common Name: %v", err)
	}
}

func TestBuildTLSConfigLegacyCommonNameRejectsMismatch(t *testing.T) {
	caPEM, serverCert := legacyTestServerCertificate(t, "other.example.test", nil)
	cfg, err := buildTLSConfig(&profile.Profile{
		Remote:        "vpn.example.test",
		CA:            caPEM,
		AllowLegacyCN: true,
	}, nil)
	if err != nil {
		t.Fatalf("buildTLSConfig() error: %v", err)
	}
	err = testTLSHandshake(cfg, serverCert)
	if err == nil || !strings.Contains(err.Error(), "legacy Common Name mismatch") {
		t.Fatalf("TLS handshake error = %v, want legacy Common Name mismatch", err)
	}
}

func TestBuildTLSConfigLegacyCommonNameRejectsSANCertificate(t *testing.T) {
	caPEM, serverCert := legacyTestServerCertificate(t, "vpn.example.test", []string{"other.example.test"})
	cfg, err := buildTLSConfig(&profile.Profile{
		Remote:        "vpn.example.test",
		CA:            caPEM,
		AllowLegacyCN: true,
	}, nil)
	if err != nil {
		t.Fatalf("buildTLSConfig() error: %v", err)
	}
	err = testTLSHandshake(cfg, serverCert)
	if err == nil || !strings.Contains(err.Error(), "contains a Subject Alternative Name") {
		t.Fatalf("TLS handshake error = %v, want SAN rejection", err)
	}
}

func TestBuildTLSConfigWithoutProfileCAUsesSystemVerification(t *testing.T) {
	cfg, err := buildTLSConfig(&profile.Profile{Remote: "vpn.example.test"}, nil)
	if err != nil {
		t.Fatalf("buildTLSConfig() error: %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("profile without <ca> must not disable TLS verification")
	}
}

func legacyTestServerCertificate(t *testing.T, commonName string, dnsNames []string) ([]byte, tls.Certificate) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), serverCert
}

func testTLSHandshake(clientConfig *tls.Config, serverCert tls.Certificate) error {
	clientConn, serverConn := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	clientConn.SetDeadline(deadline)
	serverConn.SetDeadline(deadline)
	serverResult := make(chan error, 1)
	go func() {
		server := tls.Server(serverConn, &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
		})
		serverResult <- server.Handshake()
		serverConn.Close()
	}()

	tlsConfig := clientConfig.Clone()
	tlsConfig.MaxVersion = tls.VersionTLS12
	client := tls.Client(clientConn, tlsConfig)
	err := client.Handshake()
	clientConn.Close()
	if serverErr := <-serverResult; err == nil {
		err = serverErr
	}
	return err
}
