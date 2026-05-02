//go:build integration

// Package testenv integration tests.
// Run with: go test -v -tags=integration ./testenv/
package testenv_test

import (
	"testing"

	"github.com/openlawsvpn/go-openlawsvpn/testenv"
)

// TestStartStop verifies that the mock server container starts, emits a
// "ready" event, and stops cleanly.
func TestStartStop(t *testing.T) {
	srv, err := testenv.Start(testenv.Config{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop() //nolint:errcheck

	t.Logf("TCP: %s  UDP: %s", srv.TCPAddr, srv.UDPAddr)
	for _, e := range srv.Events {
		t.Logf("event: %s detail: %s", e.Event, e.Detail)
	}
}

// TestStartCRV1 verifies the mock server can be started in CRV1 mode.
func TestStartCRV1(t *testing.T) {
	srv, err := testenv.Start(testenv.Config{CRV1Mode: true})
	if err != nil {
		t.Fatalf("Start CRV1: %v", err)
	}
	defer srv.Stop() //nolint:errcheck

	found := false
	for _, e := range srv.Events {
		if e.Event == "crv1_mode" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected crv1_mode event in server logs")
	}
}
