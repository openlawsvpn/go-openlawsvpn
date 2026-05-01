// SPDX-License-Identifier: LGPL-2.1-or-later

// Package main implements the openlawsvpn D-Bus daemon.
//
// It exposes the com.openlawsvpn.Daemon interface on the system bus so that
// the GTK GUI (or any other client) can control VPN connections without
// requiring root — privilege is held by this process via CAP_NET_ADMIN set in
// the systemd system unit.
package main

import (
	"context"
	"fmt"
	"log"
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
	samlTimeout     = 5 * time.Minute
)

// DaemonService implements the com.openlawsvpn.Daemon D-Bus interface.
// It wraps a go-openvpn3 Client and serialises all VPN operations.
type DaemonService struct {
	conn *dbus.Conn

	mu          sync.Mutex
	client      *vpn.Client
	cancel      context.CancelFunc
	state       vpn.ClientState
	profilePath string
}

func newDaemonService(conn *dbus.Conn) *DaemonService {
	return &DaemonService{conn: conn, state: vpn.StateIdle}
}

// Connect starts a VPN connection. profilePath is used as an identifier returned
// by Status(); profileContent is the .ovpn file content read by the GUI (the
// daemon runs as a different user and cannot access the user's home directory).
func (d *DaemonService) Connect(profilePath, profileContent string) *dbus.Error {
	log.Printf("Connect: profile=%s", profilePath)
	d.mu.Lock()
	if d.client != nil {
		d.mu.Unlock()
		log.Printf("Connect: rejected — connection already active")
		return dbus.NewError(dbusInterface+".Busy", []interface{}{"connection already active"})
	}

	p, err := profile.ParseString(profileContent)
	if err != nil {
		d.mu.Unlock()
		log.Printf("Connect: invalid profile: %v", err)
		return dbus.NewError(dbusInterface+".InvalidProfile", []interface{}{err.Error()})
	}

	client := vpn.New(p)
	ctx, cancel := context.WithCancel(context.Background())
	d.client = client
	d.cancel = cancel
	d.profilePath = profilePath
	d.mu.Unlock()

	// Wire event hook before calling Connect.
	client.EventFn = func(e vpn.Event) {
		switch e.Type {
		case vpn.EventStateChanged:
			log.Printf("state: %s serverIP=%q msg=%q", e.State, e.ServerIP, e.Message)
			d.mu.Lock()
			d.state = e.State
			d.mu.Unlock()
			d.emitStateChanged(e.State, e.ServerIP, e.Message)
		case vpn.EventLog:
			log.Printf("vpn: %s", e.Message)
			d.emitLogLine(e.Message)
		}
	}

	// SAML: daemon runs the ACS server and emits SAMLRequired so the GUI opens
	// the browser. This keeps port :35001 in the privileged daemon process.
	client.SAMLTokenFn = func(ctx context.Context, challenge vpn.SAMLChallenge) (string, error) {
		log.Printf("saml: starting ACS server, SAML URL: %s", challenge.URL)
		acs, err := saml.NewACSServer()
		if err != nil {
			log.Printf("saml: ACS server error: %v", err)
			return "", fmt.Errorf("daemon: start ACS server: %w", err)
		}
		// Apply a timeout so SAML wait never blocks indefinitely if the browser
		// is never opened or the wrong browser is used (no SSO session).
		// The user can also cancel early by clicking "Cancel" in the GUI, which
		// calls Disconnect and cancels ctx.
		samlCtx, samlCancel := context.WithTimeout(ctx, samlTimeout)
		defer samlCancel()
		log.Printf("saml: ACS server ready, emitting SAMLRequired signal (timeout %s)", samlTimeout)
		d.emitSAMLRequired(challenge.URL)
		log.Printf("saml: waiting for browser callback on :35001")
		token, err := acs.Wait(samlCtx)
		if err != nil {
			log.Printf("saml: ACS wait error: %v", err)
			return "", err
		}
		log.Printf("saml: token received (len=%d)", len(token))
		return token, nil
	}

	go func() {
		log.Printf("connect goroutine: starting")
		defer func() {
			log.Printf("connect goroutine: exiting, clearing client")
			d.mu.Lock()
			d.client = nil
			d.cancel = nil
			d.profilePath = ""
			d.mu.Unlock()
		}()

		if err := client.Connect(ctx); err != nil {
			if ctx.Err() == nil {
				msg := err.Error()
				log.Printf("connect error: %v", err)
				d.emitLogLine(fmt.Sprintf("daemon: connect error: %v", err))
				d.emitStateChanged(vpn.StateError, "", msg)
			} else {
				log.Printf("connect cancelled: %v", ctx.Err())
			}
			return
		}
		log.Printf("connect: tunnel up, starting stats loop")

		// Emit periodic stats while tunnel is up.
		ticker := time.NewTicker(statsInterval)
		defer ticker.Stop()
		for {
			select {
			case <-client.Done():
				log.Printf("connect: client done signal")
				if err := client.WaitForDisconnect(); err != nil && ctx.Err() == nil {
					log.Printf("disconnect error: %v", err)
					d.emitLogLine(fmt.Sprintf("daemon: disconnected: %v", err))
				}
				return
			case <-ticker.C:
				s := client.Stats()
				d.emitStatsUpdate(s.BytesSent, s.BytesRecv, uint64(s.Uptime.Seconds()))
			case <-ctx.Done():
				log.Printf("connect: context cancelled, disconnecting")
				client.Disconnect()        //nolint:errcheck
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
		log.Printf("Disconnect: cancelling active connection")
		cancel()
	} else {
		log.Printf("Disconnect: no active connection")
	}
	return nil
}

// Status returns the current daemon state as (state, server_ip, assigned_ip, profile_path).
func (d *DaemonService) Status() (string, string, string, string, *dbus.Error) {
	d.mu.Lock()
	st := d.state
	client := d.client
	profilePath := d.profilePath
	d.mu.Unlock()

	serverIP := ""
	assignedIP := ""
	if client != nil {
		serverIP = client.Phase1IP()
		assignedIP = client.LocalIP()
	}
	return st.String(), serverIP, assignedIP, profilePath, nil
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
