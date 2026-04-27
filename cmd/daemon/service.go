// SPDX-License-Identifier: LGPL-2.1-or-later

// Package main implements the openlawsvpn D-Bus daemon.
//
// It exposes the com.openlawsvpn.Daemon interface on the session bus so that
// the GTK GUI (or any other client) can control VPN connections without
// requiring root — privilege is held by this process via CAP_NET_ADMIN set in
// the systemd user unit.
package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	vpn "github.com/openlawsvpn/go-openvpn3"
	"github.com/openlawsvpn/go-openvpn3/auth/saml"
	"github.com/openlawsvpn/go-openvpn3/profile"
)

const (
	dbusServiceName = "com.openlawsvpn.Daemon"
	dbusObjectPath  = "/com/openlawsvpn/Daemon"
	dbusInterface   = "com.openlawsvpn.Daemon"
	statsInterval   = 5 * time.Second
)

// DaemonService implements the com.openlawsvpn.Daemon D-Bus interface.
// It wraps a go-openvpn3 Client and serialises all VPN operations.
type DaemonService struct {
	conn *dbus.Conn

	mu     sync.Mutex
	client *vpn.Client
	cancel context.CancelFunc
	state  vpn.ClientState
}

func newDaemonService(conn *dbus.Conn) *DaemonService {
	return &DaemonService{conn: conn, state: vpn.StateIdle}
}

// Connect starts a VPN connection for the given .ovpn profile path.
// Returns a D-Bus error if a connection is already active.
func (d *DaemonService) Connect(profilePath string) *dbus.Error {
	d.mu.Lock()
	if d.client != nil {
		d.mu.Unlock()
		return dbus.NewError(dbusInterface+".Busy", []interface{}{"connection already active"})
	}

	p, err := profile.ParsePath(profilePath)
	if err != nil {
		d.mu.Unlock()
		return dbus.NewError(dbusInterface+".InvalidProfile", []interface{}{err.Error()})
	}

	client := vpn.New(p)
	ctx, cancel := context.WithCancel(context.Background())
	d.client = client
	d.cancel = cancel
	d.mu.Unlock()

	// Wire event hook before calling Connect.
	client.EventFn = func(e vpn.Event) {
		switch e.Type {
		case vpn.EventStateChanged:
			d.mu.Lock()
			d.state = e.State
			d.mu.Unlock()
			d.emitStateChanged(e.State, e.ServerIP, e.Message)
		case vpn.EventLog:
			d.emitLogLine(e.Message)
		}
	}

	// SAML: daemon runs the ACS server and emits SAMLRequired so the GUI opens
	// the browser. This keeps port :35001 in the privileged daemon process.
	client.SAMLTokenFn = func(ctx context.Context, challenge vpn.SAMLChallenge) (string, error) {
		acs, err := saml.NewACSServer()
		if err != nil {
			return "", fmt.Errorf("daemon: start ACS server: %w", err)
		}
		d.emitSAMLRequired(challenge.URL)
		return acs.Wait(ctx)
	}

	go func() {
		defer func() {
			d.mu.Lock()
			d.client = nil
			d.cancel = nil
			d.mu.Unlock()
		}()

		if err := client.Connect(ctx); err != nil {
			if ctx.Err() == nil {
				d.emitLogLine(fmt.Sprintf("daemon: connect error: %v", err))
			}
			return
		}

		// Emit periodic stats while tunnel is up.
		ticker := time.NewTicker(statsInterval)
		defer ticker.Stop()
		for {
			select {
			case <-client.Done():
				if err := client.WaitForDisconnect(); err != nil && ctx.Err() == nil {
					d.emitLogLine(fmt.Sprintf("daemon: disconnected: %v", err))
				}
				return
			case <-ticker.C:
				s := client.Stats()
				d.emitStatsUpdate(s.BytesSent, s.BytesRecv, uint64(s.Uptime.Seconds()))
			case <-ctx.Done():
				client.Disconnect()  //nolint:errcheck
				client.WaitForDisconnect() //nolint:errcheck
				return
			}
		}
	}()

	return nil
}

// Disconnect gracefully tears down the active connection.
// No-op if idle.
func (d *DaemonService) Disconnect() *dbus.Error {
	d.mu.Lock()
	cancel := d.cancel
	d.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

// Status returns the current daemon state as (state, server_ip, assigned_ip).
func (d *DaemonService) Status() (string, string, string, *dbus.Error) {
	d.mu.Lock()
	st := d.state
	client := d.client
	d.mu.Unlock()

	serverIP := ""
	assignedIP := ""
	if client != nil {
		serverIP = client.Phase1IP()
		assignedIP = client.LocalIP()
	}
	return st.String(), serverIP, assignedIP, nil
}

// ---- signal helpers --------------------------------------------------------

func (d *DaemonService) emitStateChanged(state vpn.ClientState, serverIP, assignedIP string) {
	d.conn.Emit( //nolint:errcheck
		dbus.ObjectPath(dbusObjectPath),
		dbusInterface+".StateChanged",
		state.String(), serverIP, assignedIP,
	)
}

func (d *DaemonService) emitLogLine(line string) {
	d.conn.Emit( //nolint:errcheck
		dbus.ObjectPath(dbusObjectPath),
		dbusInterface+".LogLine",
		line,
	)
}

func (d *DaemonService) emitStatsUpdate(bytesSent, bytesRecv, uptimeSecs uint64) {
	d.conn.Emit( //nolint:errcheck
		dbus.ObjectPath(dbusObjectPath),
		dbusInterface+".StatsUpdate",
		bytesSent, bytesRecv, uptimeSecs,
	)
}

func (d *DaemonService) emitSAMLRequired(url string) {
	d.conn.Emit( //nolint:errcheck
		dbus.ObjectPath(dbusObjectPath),
		dbusInterface+".SAMLRequired",
		url,
	)
}
