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
	vpn "github.com/openlawsvpn/go-openlawsvpn"
	"github.com/openlawsvpn/go-openlawsvpn/auth/saml"
	"github.com/openlawsvpn/go-openlawsvpn/profile"
)

const (
	dbusServiceName = "com.openlawsvpn.Daemon"
	dbusObjectPath  = "/com/openlawsvpn/Daemon"
	dbusInterface   = "com.openlawsvpn.Daemon"
	statsInterval   = 5 * time.Second
	samlTimeout     = 5 * time.Minute
)

// Extra state strings for the relay flow (not part of vpn.ClientState).
const (
	stateRelayDelivering = "relay_delivering" // credentials sent to relay API
	stateRelayConnected  = "relay_connected"  // agent reported tunnel up
)

// DaemonService implements the com.openlawsvpn.Daemon D-Bus interface.
// It wraps a go-openlawsvpn Client and serialises all VPN operations.
type DaemonService struct {
	conn *dbus.Conn

	mu          sync.Mutex
	client      *vpn.Client
	cancel      context.CancelFunc
	state       vpn.ClientState
	profilePath string

	// Active relay session — set after /execute succeeds, cleared on release.
	relaySessionID  string
	relayBaseURL    string
	relayOrgToken   string
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
// In relay mode, also sends a release to the relay server so the remote agent disconnects.
func (d *DaemonService) Disconnect() *dbus.Error {
	d.mu.Lock()
	cancel := d.cancel
	sessionID := d.relaySessionID
	baseURL := d.relayBaseURL
	orgToken := d.relayOrgToken
	if sessionID != "" {
		d.relaySessionID = ""
		d.relayBaseURL = ""
		d.relayOrgToken = ""
	}
	d.mu.Unlock()

	if cancel != nil {
		log.Printf("Disconnect: cancelling active connection")
		cancel()
	} else {
		log.Printf("Disconnect: no active connection")
	}

	if sessionID != "" {
		log.Printf("Disconnect: releasing relay session %s", sessionID)
		if err := relayRelease(baseURL, orgToken, sessionID); err != nil {
			log.Printf("Disconnect: relay release: %v", err)
		}
		d.emitStateChangedStr(vpn.StateIdle.String(), "", "")
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

// ConnectRelay performs the full relay auth flow on behalf of the GUI:
//  1. POST /connect → session_id
//  2. Phase 1 against AWS VPN → CRV1 challenge (state_id, saml_url, remote_ip)
//  3. ACS server captures SAMLResponse (same :35001 ownership as local flow)
//  4. POST /session/:id/execute delivers credentials to the waiting agent
//
// The daemon emits StateChanged("relay_delivering"/"relay_connected") and the
// standard SAMLRequired signal so the GUI opens the browser as usual.
// orgToken and relayBaseURL scope the relay org; pass empty relayBaseURL to use
// the production default.
func (d *DaemonService) ConnectRelay(profilePath, profileContent, agentID, orgToken, relayBaseURL string) *dbus.Error {
	log.Printf("ConnectRelay: profile=%s agent=%s", profilePath, agentID)

	if relayBaseURL == "" {
		relayBaseURL = relayDefaultBase
	}

	d.mu.Lock()
	if d.client != nil {
		d.mu.Unlock()
		return dbus.NewError(dbusInterface+".Busy", []interface{}{"connection already active"})
	}

	p, err := profile.ParseString(profileContent)
	if err != nil {
		d.mu.Unlock()
		return dbus.NewError(dbusInterface+".InvalidProfile", []interface{}{err.Error()})
	}

	client := vpn.New(p)
	ctx, cancel := context.WithCancel(context.Background())
	d.client = client
	d.cancel = cancel
	d.profilePath = profilePath
	d.mu.Unlock()

	// suppressVpnSignals is set to true once we have the SAML token and cancel
	// the Phase 1 context. The resulting idle/disconnecting signals from the VPN
	// client must not reach the GUI — it should only see relay-specific states.
	var suppressVpnSignals bool
	var suppressMu sync.Mutex

	client.EventFn = func(e vpn.Event) {
		switch e.Type {
		case vpn.EventStateChanged:
			log.Printf("relay state: %s serverIP=%q msg=%q", e.State, e.ServerIP, e.Message)
			suppressMu.Lock()
			suppress := suppressVpnSignals
			suppressMu.Unlock()
			if suppress {
				log.Printf("relay: suppressing VPN state signal %q after context cancel", e.State)
				return
			}
			d.mu.Lock()
			d.state = e.State
			d.mu.Unlock()
			d.emitStateChanged(e.State, e.ServerIP, e.Message)
		case vpn.EventLog:
			log.Printf("relay vpn: %s", e.Message)
			d.emitLogLine(e.Message)
		}
	}

	// Capture state_id, saml_response, remote_ip from the SAML challenge.
	// These are needed for the /execute call after ACS captures the token.
	type samlCapture struct {
		stateID   string
		samlToken string
	}
	captured := make(chan samlCapture, 1)

	client.SAMLTokenFn = func(ctx context.Context, challenge vpn.SAMLChallenge) (string, error) {
		log.Printf("relay saml: starting ACS server, URL: %s", challenge.URL)
		acs, err := saml.NewACSServer()
		if err != nil {
			return "", fmt.Errorf("relay: ACS server: %w", err)
		}
		samlCtx, samlCancel := context.WithTimeout(ctx, samlTimeout)
		defer samlCancel()

		d.emitSAMLRequired(challenge.URL)
		log.Printf("relay saml: waiting for browser callback on :35001")

		token, err := acs.Wait(samlCtx)
		if err != nil {
			return "", err
		}
		log.Printf("relay saml: token received (len=%d)", len(token))

		// Send captured data to the goroutine below.
		captured <- samlCapture{
			stateID:   challenge.StateID,
			samlToken: token,
		}
		// Return the token so the Go client proceeds normally; we cancel context
		// immediately after so Phase 2 is aborted on this machine — the agent
		// does Phase 2, not us.
		return token, nil
	}

	go func() {
		log.Printf("relay goroutine: starting")
		defer func() {
			d.mu.Lock()
			d.client = nil
			d.cancel = nil
			d.profilePath = ""
			// Reset VPN client state so Status() returns "idle" after the relay
			// flow, not the stale pre-suppression state (e.g. "connecting" or
			// "waiting_saml"), which would freeze the Connect tab on GUI restart.
			d.state = vpn.StateIdle
			d.mu.Unlock()
		}()

		// Step 1: reserve the agent.
		sessionID, err := relayConnect(relayBaseURL, orgToken, agentID)
		if err != nil {
			log.Printf("relay: connect: %v", err)
			d.emitLogLine(fmt.Sprintf("relay: reserve agent: %v", err))
			d.emitStateChangedStr(vpn.StateError.String(), "", err.Error())
			cancel()
			return
		}
		log.Printf("relay: session_id=%s", sessionID)

		// Step 2: run Phase 1 through the Go client — it will call SAMLTokenFn,
		// which starts the ACS server, emits SAMLRequired, and captures the token.
		// We cancel the client context as soon as we have the SAML token so the
		// client does not proceed to create a TUN on this machine.
		phase1Done := make(chan error, 1)
		go func() {
			phase1Done <- client.Connect(ctx)
		}()

		var cap samlCapture
		select {
		case cap = <-captured:
			// Suppress idle/disconnecting signals fired when we cancel Phase 1.
			suppressMu.Lock()
			suppressVpnSignals = true
			suppressMu.Unlock()
			cancel()
			// Drain the phase1Done error (context cancelled — expected).
			<-phase1Done
		case err := <-phase1Done:
			// Connect returned before we got a token (auth failure, network error).
			if ctx.Err() == nil {
				msg := ""
				if err != nil {
					msg = err.Error()
				}
				log.Printf("relay: phase1 failed: %v", err)
				d.emitStateChangedStr(vpn.StateError.String(), "", msg)
			}
			return
		case <-ctx.Done():
			// User called Disconnect before SAML completed.
			<-phase1Done
			return
		}

		// Step 3: deliver credentials to the relay.
		d.emitStateChangedStr(stateRelayDelivering, "", "")
		log.Printf("relay: delivering credentials to session %s", sessionID)

		// Phase1IP() is the sticky remote VPN server IP captured during Phase 1.
		remoteIP := client.Phase1IP()
		if err := relayExecute(relayBaseURL, orgToken, sessionID, profileContent,
			cap.stateID, cap.samlToken, remoteIP); err != nil {
			log.Printf("relay: execute: %v", err)
			d.emitLogLine(fmt.Sprintf("relay: deliver credentials: %v", err))
			d.emitStateChangedStr(vpn.StateError.String(), "", err.Error())
			return
		}

		log.Printf("relay: credentials delivered, agent is executing Phase 2")
		// Store session so Disconnect() can release it later.
		d.mu.Lock()
		d.relaySessionID = sessionID
		d.relayBaseURL = relayBaseURL
		d.relayOrgToken = orgToken
		d.mu.Unlock()
		d.emitStateChangedStr(stateRelayConnected, agentID, "")
	}()

	return nil
}

// ---- signal helpers --------------------------------------------------------

func (d *DaemonService) emitStateChanged(state vpn.ClientState, serverIP, assignedIP string) {
	d.emitStateChangedStr(state.String(), serverIP, assignedIP)
}

// emitStateChangedStr emits StateChanged with a raw string state — used for
// relay-specific states that are not part of vpn.ClientState.
func (d *DaemonService) emitStateChangedStr(state, serverIP, assignedIP string) {
	d.conn.Emit( //nolint:errcheck
		dbus.ObjectPath(dbusObjectPath),
		dbusInterface+".StateChanged",
		state, serverIP, assignedIP,
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
