package routing

import (
	"errors"
	"fmt"
	"sync"
)

// DriftKind describes how an expected VPN route differs from host state.
type DriftKind int

const (
	// DriftMissing means an owned route no longer exists.
	DriftMissing DriftKind = iota + 1
	// DriftChanged means the destination exists with different route identity.
	DriftChanged
)

// Drift describes a route discrepancy without mutating host state.
type Drift struct {
	Kind        DriftKind
	Destination string
}

// RouteIdentity is the complete identity used to distinguish a VPN-owned
// route from an administrator-owned route with the same destination.
type RouteIdentity struct {
	Destination string
	Gateway     string
	Interface   int
}

// Ownership records routes created by one client instance. Its callbacks are
// supplied by the platform route backend and are serialized by Ownership.
type Ownership struct {
	mu     sync.Mutex
	owned  []RouteIdentity
	lookup func(string) (*RouteIdentity, error)
	add    func(RouteIdentity) error
	remove func(RouteIdentity) error
	closed bool
}

// NewOwnership constructs a route ownership ledger. It is primarily useful
// to platform backends and deterministic tests.
func NewOwnership(owned []RouteIdentity, lookup func(string) (*RouteIdentity, error), add, remove func(RouteIdentity) error) *Ownership {
	copyOwned := append([]RouteIdentity(nil), owned...)
	return &Ownership{owned: copyOwned, lookup: lookup, add: add, remove: remove}
}

// Check reports missing or changed owned routes without repairing them.
func (o *Ownership) Check() ([]Drift, error) {
	if o == nil {
		return nil, nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.checkLocked()
}

func (o *Ownership) checkLocked() ([]Drift, error) {
	if o.closed || o.lookup == nil {
		return nil, nil
	}
	var drift []Drift
	for _, expected := range o.owned {
		current, err := o.lookup(expected.Destination)
		if err != nil {
			return nil, fmt.Errorf("routing: inspect %s: %w", expected.Destination, err)
		}
		if current == nil {
			drift = append(drift, Drift{Kind: DriftMissing, Destination: expected.Destination})
		} else if *current != expected {
			drift = append(drift, Drift{Kind: DriftChanged, Destination: expected.Destination})
		}
	}
	return drift, nil
}

// Repair restores missing routes owned by this ledger. Changed routes are
// left untouched because they represent later administrator or client work.
func (o *Ownership) Repair() ([]Drift, error) {
	if o == nil {
		return nil, nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, nil
	}
	drift, err := o.checkLocked()
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, item := range drift {
		if item.Kind != DriftMissing {
			continue
		}
		for _, expected := range o.owned {
			if expected.Destination == item.Destination && o.add != nil {
				if err := o.add(expected); err != nil {
					errs = append(errs, fmt.Errorf("restore %s: %w", item.Destination, err))
				}
				break
			}
		}
	}
	return drift, errors.Join(errs...)
}

// Cleanup removes only routes that are still byte-for-byte identical to an
// entry created by this ledger. Missing and changed routes are preserved.
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
	var errs []error
	for _, expected := range o.owned {
		current, err := o.lookup(expected.Destination)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if current != nil && *current == expected && o.remove != nil {
			if err := o.remove(expected); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
