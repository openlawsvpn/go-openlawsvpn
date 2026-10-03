package vpn

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/openlawsvpn/go-openlawsvpn/internal/datachannel"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
	"github.com/openlawsvpn/go-openlawsvpn/routing"
)

func TestPeerInfoAdvertisesImplementedFIPSCiphers(t *testing.T) {
	for _, cipher := range []string{"AES-128-GCM", "AES-192-GCM", "AES-256-GCM"} {
		if !strings.Contains(peerInfo, cipher) {
			t.Errorf("peerInfo does not advertise %s", cipher)
		}
	}
	if strings.Contains(peerInfo, "CHACHA20") {
		t.Fatal("peerInfo advertises unsupported and non-FIPS ChaCha20")
	}
}

func TestNewDataChannelNegotiatedAESGCM(t *testing.T) {
	keyMaterial := bytes.Repeat([]byte{0x5A}, 256)
	for _, cipher := range []string{"AES-128-GCM", "AES-192-GCM", "AES-256-GCM", ""} {
		t.Run(cipher, func(t *testing.T) {
			if _, err := newDataChannel(cipher, 7, 0, keyMaterial); err != nil {
				t.Fatalf("newDataChannel(%q): %v", cipher, err)
			}
		})
	}
	if _, err := newDataChannel("CHACHA20-POLY1305", 7, 0, keyMaterial); err == nil {
		t.Fatal("expected unsupported cipher error")
	}
	if _, err := newDataChannel("AES-256-GCM", 7, 0, keyMaterial[:255]); err == nil {
		t.Fatal("expected short key-material error")
	}
}

func TestApplyStaticProfileIPv6(t *testing.T) {
	static := &profile.IPv6Config{
		Local:   net.ParseIP("2001:db8::2"),
		Prefix:  64,
		Gateway: net.ParseIP("2001:db8::1"),
	}
	push := &routing.PushOptions{}
	applyStaticProfileOptions(push, &profile.Profile{Ifconfig6: static})
	if push.Ifconfig6 == nil || push.Ifconfig6.Local.String() != "2001:db8::2" || push.Ifconfig6.Prefix != 64 {
		t.Fatalf("static IPv6 was not applied: %+v", push.Ifconfig6)
	}

	pushed := &routing.Ifconfig6{Local: net.ParseIP("2001:db8:1::2"), Prefix: 96}
	push.Ifconfig6 = pushed
	applyStaticProfileOptions(push, &profile.Profile{Ifconfig6: static})
	if push.Ifconfig6 != pushed {
		t.Fatal("static IPv6 replaced a server-pushed value")
	}
}

func TestEffectiveKeepalivePrecedence(t *testing.T) {
	tests := []struct {
		name     string
		profile  *profile.Profile
		push     *routing.PushOptions
		interval int
		timeout  int
		exit     bool
	}{
		{name: "defaults", profile: &profile.Profile{}, push: &routing.PushOptions{}, interval: 10, timeout: 60},
		{name: "static restart", profile: &profile.Profile{PingInterval: 7, PingRestart: 30}, push: &routing.PushOptions{}, interval: 7, timeout: 30},
		{name: "static exit", profile: &profile.Profile{PingInterval: 8, PingExit: 40}, push: &routing.PushOptions{}, interval: 8, timeout: 40, exit: true},
		{name: "pushed restart overrides exit", profile: &profile.Profile{PingInterval: 8, PingExit: 40}, push: &routing.PushOptions{PingRestart: 20}, interval: 8, timeout: 20},
		{name: "pushed exit overrides restart", profile: &profile.Profile{PingRestart: 40}, push: &routing.PushOptions{PingInterval: 5, PingExit: 25}, interval: 5, timeout: 25, exit: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interval, timeout, exit := effectiveKeepalive(tt.profile, tt.push)
			if interval != tt.interval || timeout != tt.timeout || exit != tt.exit {
				t.Fatalf("effectiveKeepalive = (%d, %d, %t), want (%d, %d, %t)", interval, timeout, exit, tt.interval, tt.timeout, tt.exit)
			}
		})
	}
}

func TestPingExitErrorIsTerminal(t *testing.T) {
	if err := keepaliveTimeoutError(30, true); !errors.Is(err, ErrPingExit) {
		t.Fatalf("ping-exit error does not wrap ErrPingExit: %v", err)
	}
	if err := keepaliveTimeoutError(30, false); errors.Is(err, ErrPingExit) {
		t.Fatalf("ping-restart error unexpectedly wraps ErrPingExit: %v", err)
	}
}

func TestSendControlMessage(t *testing.T) {
	var buf bytes.Buffer
	c := &Client{state: stateTunnelUp, tlsRW: &buf}
	if err := c.SendControlMessage("AWS_CC_MSG,1,1,0,payload"); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "AWS_CC_MSG,1,1,0,payload\x00"; got != want {
		t.Fatalf("wire message = %q, want %q", got, want)
	}
}

func TestSendControlMessageRequiresTunnel(t *testing.T) {
	c := &Client{state: stateNew}
	if err := c.SendControlMessage("message"); err == nil {
		t.Fatal("expected inactive-tunnel error")
	}
}

func TestRekeyPromotionMovesControlChannel(t *testing.T) {
	keyMaterial := bytes.Repeat([]byte{0xA5}, 256)
	primary, err := newDataChannel("AES-256-GCM", 7, 0, keyMaterial)
	if err != nil {
		t.Fatal(err)
	}
	secondary, err := newDataChannel("AES-256-GCM", 7, 1, keyMaterial)
	if err != nil {
		t.Fatal(err)
	}
	manager := datachannel.NewManager(primary, nil)
	manager.Prepare(secondary)

	oldControl := &bytes.Buffer{}
	newControl := new(tls.Conn)
	c := &Client{state: stateTunnelUp, manager: manager, tlsRW: oldControl}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.scheduleRekeyPromotion(ctx, manager, 1, 0, newControl)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		got := c.tlsRW
		c.mu.Unlock()
		if got == newControl {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("promoted rekey did not take ownership of the control channel")
}
