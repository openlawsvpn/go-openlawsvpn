package dns

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileOwnershipRepairAndCleanup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	backup := filepath.Join(dir, "backup")
	expected := []byte("nameserver 10.0.0.2\n")
	original := []byte("nameserver 1.1.1.1\n")
	if err := os.WriteFile(path, expected, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, original, 0600); err != nil {
		t.Fatal(err)
	}
	owner := NewFileOwnership(path, backup, expected)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	kind, drifted, err := owner.Repair()
	if err != nil || !drifted || kind != DriftMissing {
		t.Fatalf("Repair = %v %v %v", kind, drifted, err)
	}
	if err := owner.Cleanup(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(original) {
		t.Fatalf("restored = %q, %v", got, err)
	}
}

func TestFileOwnershipPreservesAdministratorChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	backup := filepath.Join(dir, "backup")
	expected := []byte("nameserver 10.0.0.2\n")
	admin := []byte("nameserver 9.9.9.9\n")
	os.WriteFile(path, expected, 0644)                         //nolint:errcheck
	os.WriteFile(backup, []byte("nameserver 1.1.1.1\n"), 0600) //nolint:errcheck
	owner := NewFileOwnership(path, backup, expected)
	os.WriteFile(path, admin, 0644) //nolint:errcheck
	kind, drifted, err := owner.Repair()
	if err != nil || !drifted || kind != DriftChanged {
		t.Fatalf("Repair = %v %v %v", kind, drifted, err)
	}
	if err := owner.Cleanup(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(admin) {
		t.Fatalf("administrator change overwritten: %q", got)
	}
}
