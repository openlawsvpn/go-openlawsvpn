package dns

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sync"
)

// DriftKind describes how VPN-owned DNS state differs from the host state.
type DriftKind int

const (
	// DriftMissing means the owned DNS state disappeared.
	DriftMissing DriftKind = iota + 1
	// DriftChanged means another actor replaced the owned DNS state.
	DriftChanged
)

// Ownership protects the lifecycle of a resolv.conf configuration created by
// one client. Platform resolver services retain their own per-link ownership.
type Ownership struct {
	mu       sync.Mutex
	path     string
	backup   string
	expected []byte
	closed   bool
	inspect  func() (DriftKind, bool, error)
	repair   func() error
	cleanup  func() error
}

// NewOwnership constructs ownership for a platform DNS backend.
func NewOwnership(inspect func() (DriftKind, bool, error), repair, cleanup func() error) *Ownership {
	return &Ownership{inspect: inspect, repair: repair, cleanup: cleanup}
}

// NewFileOwnership records the exact bytes written to path and the backup to
// restore when those bytes are still owned at cleanup time.
func NewFileOwnership(path, backup string, expected []byte) *Ownership {
	return &Ownership{path: path, backup: backup, expected: append([]byte(nil), expected...)}
}

// OwnershipForBackend captures ownership for a successfully applied backend.
// Per-link resolver backends are owned and reverted by the operating system.
func OwnershipForBackend(backend Backend, backupPath string) (*Ownership, error) {
	if backend != BackendResolvConf {
		return nil, nil
	}
	expected, err := os.ReadFile(ResolvConfPath)
	if err != nil {
		return nil, fmt.Errorf("dns: capture owned resolv.conf: %w", err)
	}
	return NewFileOwnership(ResolvConfPath, backupPath, expected), nil
}

// Check reports whether the owned DNS file is missing or was changed.
func (o *Ownership) Check() (DriftKind, bool, error) {
	if o == nil {
		return 0, false, nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.checkLocked()
}

func (o *Ownership) checkLocked() (DriftKind, bool, error) {
	if o.closed {
		return 0, false, nil
	}
	if o.inspect != nil {
		return o.inspect()
	}
	current, err := os.ReadFile(o.path)
	if errors.Is(err, os.ErrNotExist) {
		return DriftMissing, true, nil
	}
	if err != nil {
		return 0, false, err
	}
	if !bytes.Equal(current, o.expected) {
		return DriftChanged, true, nil
	}
	return 0, false, nil
}

// Repair recreates missing owned DNS state. A changed file is preserved.
func (o *Ownership) Repair() (DriftKind, bool, error) {
	if o == nil {
		return 0, false, nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	kind, drifted, err := o.checkLocked()
	if err != nil || !drifted || kind == DriftChanged {
		return kind, drifted, err
	}
	if o.repair != nil {
		return kind, true, o.repair()
	}
	if err := os.WriteFile(o.path, o.expected, 0644); err != nil {
		return kind, true, fmt.Errorf("dns: restore owned configuration: %w", err)
	}
	return kind, true, nil
}

// Cleanup restores the pre-VPN backup only if the active file still exactly
// matches this owner. Later administrator changes are preserved.
func (o *Ownership) Cleanup() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	o.closed = true
	if o.cleanup != nil {
		return o.cleanup()
	}
	current, err := os.ReadFile(o.path)
	if err == nil && bytes.Equal(current, o.expected) && o.backup != "" {
		backup, readErr := os.ReadFile(o.backup)
		if readErr != nil {
			return readErr
		}
		if writeErr := os.WriteFile(o.path, backup, 0644); writeErr != nil {
			return writeErr
		}
	}
	if o.backup != "" {
		if removeErr := os.Remove(o.backup); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return removeErr
		}
	}
	return nil
}
