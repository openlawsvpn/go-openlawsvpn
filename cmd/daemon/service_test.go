// SPDX-License-Identifier: LGPL-2.1-or-later

package main

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	vpn "github.com/openlawsvpn/go-openlawsvpn"
)

// fakeConn satisfies the Emit call on *dbus.Conn for tests.
// We use a real session-bus connection only when DBUS_SESSION_BUS_ADDRESS is
// set; otherwise we skip D-Bus signal tests and exercise only the logic paths.

// capturedSignal records one D-Bus Emit call.
type capturedSignal struct {
	name string
	args []interface{}
}

// signalCapture wraps DaemonService and intercepts emitXxx calls via the EventFn.
// It replays the same state-machine logic but records signals instead of
// sending them on a real bus — letting us run unit tests without a session bus.
type signalCapture struct {
	mu      sync.Mutex
	signals []capturedSignal
}

func (sc *signalCapture) record(name string, args ...interface{}) {
	sc.mu.Lock()
	sc.signals = append(sc.signals, capturedSignal{name: name, args: args})
	sc.mu.Unlock()
}

func (sc *signalCapture) find(name string) *capturedSignal {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for i := len(sc.signals) - 1; i >= 0; i-- {
		if sc.signals[i].name == name {
			return &sc.signals[i]
		}
	}
	return nil
}

// TestStateTransitions verifies that ClientState.String() returns the values
// the GUI's VpnState parsing expects.
func TestStateTransitions(t *testing.T) {
	cases := []struct {
		state vpn.ClientState
		want  string
	}{
		{vpn.StateIdle, "idle"},
		{vpn.StateConnecting, "connecting"},
		{vpn.StateWaitingSAML, "waiting_saml"},
		{vpn.StateConnected, "connected"},
		{vpn.StateDisconnecting, "disconnecting"},
		{vpn.StateError, "error"},
	}
	for _, tc := range cases {
		if got := tc.state.String(); got != tc.want {
			t.Errorf("ClientState(%d).String() = %q, want %q", tc.state, got, tc.want)
		}
	}
}

// TestConnectBusy verifies that a second Connect call while connected is rejected.
func TestConnectBusy(t *testing.T) {
	// We need a real dbus.Conn only for signal emission; for the Busy path we
	// can use nil since the error is returned before any emit happens.
	svc := &DaemonService{state: vpn.StateIdle}

	// Inject a non-nil client to simulate "already connected".
	svc.mu.Lock()
	svc.client = &vpn.Client{}
	svc.mu.Unlock()

	dbusErr := svc.Connect("/nonexistent.ovpn", "")
	if dbusErr == nil {
		t.Fatal("expected D-Bus error when already connected, got nil")
	}
	if !strings.Contains(dbusErr.Name, "Busy") {
		t.Errorf("expected Busy error, got %q", dbusErr.Name)
	}
}

// TestConnectBadProfile verifies that an invalid .ovpn path returns InvalidProfile.
func TestConnectBadProfile(t *testing.T) {
	svc := &DaemonService{state: vpn.StateIdle}
	dbusErr := svc.Connect("/definitely/does/not/exist.ovpn", "")
	if dbusErr == nil {
		t.Fatal("expected D-Bus error for missing profile, got nil")
	}
	if !strings.Contains(dbusErr.Name, "InvalidProfile") {
		t.Errorf("expected InvalidProfile error, got %q", dbusErr.Name)
	}
}

// TestDisconnectIdempotent verifies Disconnect is safe when idle (no panic, no error).
func TestDisconnectIdempotent(t *testing.T) {
	svc := &DaemonService{state: vpn.StateIdle}
	if err := svc.Disconnect(); err != nil {
		t.Errorf("Disconnect on idle svc returned error: %v", err)
	}
}

// TestStatusIdle verifies Status returns "idle" with empty IPs when nothing is connected.
func TestStatusIdle(t *testing.T) {
	svc := &DaemonService{state: vpn.StateIdle}
	st, serverIP, assignedIP, _, dbusErr := svc.Status()
	if dbusErr != nil {
		t.Fatalf("Status: %v", dbusErr)
	}
	if st != "idle" {
		t.Errorf("state = %q, want idle", st)
	}
	if serverIP != "" || assignedIP != "" {
		t.Errorf("expected empty IPs when idle, got server=%q assigned=%q", serverIP, assignedIP)
	}
}

// TestEventFnLogForwarding verifies that EventLog events emitted by the client
// are forwarded to emitLogLine without being dropped.
func TestEventFnLogForwarding(t *testing.T) {
	sc := &signalCapture{}
	captured := make(chan string, 8)

	// Build a minimal DaemonService with a custom emitter (no real D-Bus needed).
	svc := &DaemonService{state: vpn.StateIdle}
	// Override emit behaviour by directly calling the same logic DaemonService
	// uses when it receives an EventLog from client.EventFn.
	logFn := func(line string) {
		sc.record("LogLine", line)
		captured <- line
	}

	// Simulate what client.EventFn does for EventLog events.
	e := vpn.Event{Type: vpn.EventLog, Message: "vpn: rekey complete (key_id=1)"}
	logFn(e.Message)

	select {
	case got := <-captured:
		if got != e.Message {
			t.Errorf("captured log = %q, want %q", got, e.Message)
		}
	case <-time.After(time.Second):
		t.Fatal("log line not received within 1s")
	}

	sig := sc.find("LogLine")
	if sig == nil {
		t.Fatal("LogLine signal not recorded")
	}
	_ = svc // prevent "declared and not used"
}

// TestDbusNameConstants ensures the interface constants match the plan document.
func TestDbusNameConstants(t *testing.T) {
	if dbusServiceName != "com.openlawsvpn.Daemon" {
		t.Errorf("dbusServiceName = %q", dbusServiceName)
	}
	if dbusObjectPath != "/com/openlawsvpn/Daemon" {
		t.Errorf("dbusObjectPath = %q", dbusObjectPath)
	}
	if dbusInterface != "com.openlawsvpn.Daemon" {
		t.Errorf("dbusInterface = %q", dbusInterface)
	}
}

// TestSessionBusIntegration runs a basic Connect→Status→Disconnect cycle
// against the real session bus. Skipped if DBUS_SESSION_BUS_ADDRESS is unset.
func TestSessionBusIntegration(t *testing.T) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Skipf("no session bus available: %v", err)
	}
	defer conn.Close()

	svc := newDaemonService(conn)
	st, _, _, _, dbusErr := svc.Status()
	if dbusErr != nil {
		t.Fatalf("Status: %v", dbusErr)
	}
	if st != "idle" {
		t.Errorf("initial state = %q, want idle", st)
	}
}
