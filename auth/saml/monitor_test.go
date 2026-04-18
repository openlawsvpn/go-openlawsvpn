package saml_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openvpn3/auth/saml"
)

func TestSessionMonitorAuthFailed(t *testing.T) {
	// Simulate server sending AUTH_FAILED on an active session.
	r := strings.NewReader("AUTH_FAILED\x00")
	mon := saml.NewSessionMonitor(r)
	mon.Start(context.Background())

	select {
	case err := <-mon.Done():
		var se *saml.SessionExpiredError
		if !errors.As(err, &se) {
			t.Fatalf("expected *SessionExpiredError, got %T: %v", err, err)
		}
		if se.Msg != "AUTH_FAILED" {
			t.Errorf("Msg = %q", se.Msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for SessionExpired")
	}
}

func TestSessionMonitorAuthFailedCRV1(t *testing.T) {
	// Simulate server sending a CRV1 re-challenge mid-session.
	r := strings.NewReader("AUTH_FAILED,CRV1:R:state::https://idp.example.com\x00")
	mon := saml.NewSessionMonitor(r)
	mon.Start(context.Background())

	select {
	case err := <-mon.Done():
		var se *saml.SessionExpiredError
		if !errors.As(err, &se) {
			t.Fatalf("expected *SessionExpiredError, got %T: %v", err, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSessionMonitorEOF(t *testing.T) {
	// Simulate server closing the connection.
	r := strings.NewReader("") // immediate EOF
	mon := saml.NewSessionMonitor(r)
	mon.Start(context.Background())

	select {
	case err := <-mon.Done():
		if err != io.EOF {
			t.Fatalf("expected io.EOF, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSessionMonitorContextCancel(t *testing.T) {
	// Block forever — cancelled by context.
	pr, _ := io.Pipe()
	defer pr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	mon := saml.NewSessionMonitor(pr)
	mon.Start(ctx)
	cancel()

	select {
	case err := <-mon.Done():
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout after context cancel")
	}
}
