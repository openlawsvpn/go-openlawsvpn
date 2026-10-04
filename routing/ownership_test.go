package routing

import (
	"errors"
	"testing"
)

func TestOwnershipDetectRepairAndCleanup(t *testing.T) {
	want := RouteIdentity{Destination: "10.0.0.0/8", Gateway: "10.8.0.1", Interface: 7}
	state := map[string]RouteIdentity{want.Destination: want}
	adds, removes := 0, 0
	owner := NewOwnership([]RouteIdentity{want}, func(destination string) (*RouteIdentity, error) {
		got, ok := state[destination]
		if !ok {
			return nil, nil
		}
		return &got, nil
	}, func(route RouteIdentity) error {
		adds++
		state[route.Destination] = route
		return nil
	}, func(route RouteIdentity) error {
		removes++
		delete(state, route.Destination)
		return nil
	})

	delete(state, want.Destination)
	drift, err := owner.Check()
	if err != nil || len(drift) != 1 || drift[0].Kind != DriftMissing {
		t.Fatalf("Check = %#v, %v", drift, err)
	}
	if _, err := owner.Repair(); err != nil || adds != 1 {
		t.Fatalf("Repair adds=%d err=%v", adds, err)
	}
	if err := owner.Cleanup(); err != nil || removes != 1 {
		t.Fatalf("Cleanup removes=%d err=%v", removes, err)
	}
}

func TestOwnershipPreservesAdministratorChange(t *testing.T) {
	want := RouteIdentity{Destination: "10.0.0.0/8", Gateway: "10.8.0.1", Interface: 7}
	admin := RouteIdentity{Destination: want.Destination, Gateway: "192.0.2.1", Interface: 2}
	state := admin
	removed := false
	owner := NewOwnership([]RouteIdentity{want}, func(string) (*RouteIdentity, error) { return &state, nil }, nil,
		func(RouteIdentity) error { removed = true; return nil })
	drift, err := owner.Repair()
	if err != nil || len(drift) != 1 || drift[0].Kind != DriftChanged {
		t.Fatalf("Repair = %#v, %v", drift, err)
	}
	if err := owner.Cleanup(); err != nil || removed {
		t.Fatalf("Cleanup removed administrator route=%v err=%v", removed, err)
	}
}

func TestOwnershipPartialFailure(t *testing.T) {
	a := RouteIdentity{Destination: "10.0.0.0/8"}
	b := RouteIdentity{Destination: "192.168.0.0/16"}
	owner := NewOwnership([]RouteIdentity{a, b}, func(string) (*RouteIdentity, error) { return nil, nil },
		func(route RouteIdentity) error {
			if route == a {
				return errors.New("denied")
			}
			return nil
		}, nil)
	drift, err := owner.Repair()
	if len(drift) != 2 || err == nil {
		t.Fatalf("Repair = %#v, %v", drift, err)
	}
}

func TestEmptyOwnershipNeverDeletesPreexistingRoute(t *testing.T) {
	removed := false
	owner := NewOwnership(nil, func(string) (*RouteIdentity, error) {
		return &RouteIdentity{Destination: "10.0.0.0/8"}, nil
	}, nil, func(RouteIdentity) error { removed = true; return nil })
	if err := owner.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("pre-existing route was deleted")
	}
}
