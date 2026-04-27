// SPDX-License-Identifier: LGPL-2.1-or-later

package vpn

import "time"

// EventType identifies the kind of event emitted by the Client.
type EventType int

const (
	// EventLog is an informational log line.
	EventLog EventType = iota
	// EventStateChanged signals a connection state transition.
	EventStateChanged
	// EventStatsUpdate carries a traffic statistics snapshot.
	EventStatsUpdate
)

// ClientState is the connection lifecycle state reported via events.
type ClientState int

const (
	// StateIdle means no active connection.
	StateIdle ClientState = iota
	// StateConnecting covers Phase 1 and Phase 2 establishment.
	StateConnecting
	// StateWaitingSAML means Phase 1 completed and the GUI must open the SAML URL.
	StateWaitingSAML
	// StateConnected means the TUN interface is up and data flows.
	StateConnected
	// StateDisconnecting means teardown is in progress.
	StateDisconnecting
	// StateError means connection failed; Message carries the reason.
	StateError
)

// String returns a lowercase D-Bus-friendly representation of the state.
func (s ClientState) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateConnecting:
		return "connecting"
	case StateWaitingSAML:
		return "waiting_saml"
	case StateConnected:
		return "connected"
	case StateDisconnecting:
		return "disconnecting"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// Event is emitted by the Client for every notable lifecycle transition or log line.
type Event struct {
	// Type identifies the event category.
	Type EventType

	// State is set when Type == EventStateChanged.
	State ClientState

	// Message carries a log line (EventLog), SAML URL (StateWaitingSAML),
	// error description (StateError), or assigned tunnel IP (StateConnected).
	Message string

	// ServerIP is the VPN server IP (set when State == StateConnected).
	ServerIP string

	// Stats is set when Type == EventStatsUpdate.
	Stats Stats

	// At is the wall-clock time of the event.
	At time.Time
}

// EventFn is a callback invoked for every Event emitted by the Client.
// It is called from internal goroutines; implementations must not block.
// Set Client.EventFn before calling Connect.
type EventFn func(Event)
