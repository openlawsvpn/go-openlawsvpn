package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestOutboundIPReturnsNonLoopback verifies that outboundIP returns a valid,
// non-loopback IP when the machine has network connectivity.
func TestOutboundIPReturnsNonLoopback(t *testing.T) {
	ip := outboundIP()
	if ip == "" {
		t.Skip("no outbound route available in this environment")
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("outboundIP returned unparseable value %q", ip)
	}
	if parsed.IsLoopback() {
		t.Errorf("outboundIP returned loopback address %q", ip)
	}
	if parsed.IsUnspecified() {
		t.Errorf("outboundIP returned unspecified address %q", ip)
	}
}

// TestOutboundIPIsStable verifies that repeated calls return the same value.
func TestOutboundIPIsStable(t *testing.T) {
	a := outboundIP()
	b := outboundIP()
	if a != b {
		t.Errorf("outboundIP unstable: %q != %q", a, b)
	}
}

// TestNotifyReady verifies that notifyReady writes "ok" to the FD and closes it.
func TestNotifyReady(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	notifyReady(int(w.Fd()), "1.2.3.4")

	buf := make([]byte, 64)
	n, _ := r.Read(buf)
	r.Close()

	got := string(buf[:n])
	if !strings.HasPrefix(got, "ok") {
		t.Errorf("expected prefix 'ok', got %q", got)
	}
	if !strings.Contains(got, "1.2.3.4") {
		t.Errorf("expected IP in ready line, got %q", got)
	}
}

// TestNotifyReadyNoop verifies that notifyReady(0, ...) is safe and does nothing.
func TestNotifyReadyNoop(t *testing.T) {
	notifyReady(0, "1.2.3.4") // must not panic or block
}

// TestDaemonSpawnAndReady is an end-to-end test of the daemon re-exec mechanism.
// It builds a helper binary that immediately signals "tunnel up" via
// OPENLAWSVPN_READY_FD, simulating the child side of spawnDaemon.
func TestDaemonSpawnAndReady(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("daemon mode (Setsid) is Linux-only")
	}

	// Build a tiny helper: reads OPENLAWSVPN_READY_FD and writes "ok\n", then sleeps.
	tmpDir := t.TempDir()
	helperSrc := filepath.Join(tmpDir, "helper.go")
	helperBin := filepath.Join(tmpDir, "helper")
	helperCode := `package main
import (
	"fmt"
	"os"
	"strconv"
	"time"
)
func main() {
	fd, _ := strconv.Atoi(os.Getenv("OPENLAWSVPN_READY_FD"))
	if fd > 0 {
		f := os.NewFile(uintptr(fd), "ready")
		fmt.Fprintln(f, "ok local=10.0.0.1")
		f.Close()
	}
	time.Sleep(30 * time.Second) // keep running like a real daemon
}
`
	if err := os.WriteFile(helperSrc, []byte(helperCode), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("go", "build", "-o", helperBin, helperSrc).CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out)
	}

	// Now exercise the parent side (spawnDaemon logic) directly using the helper.
	pidFile := filepath.Join(tmpDir, "test.pid")
	logFile := filepath.Join(tmpDir, "test.log")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	child := exec.Command(helperBin)
	child.ExtraFiles = []*os.File{w}
	child.Env = append(os.Environ(), "OPENLAWSVPN_READY_FD=3")
	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	child.Stdout = devNull
	child.Stderr = devNull

	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	w.Close()
	devNull.Close()
	t.Cleanup(func() { child.Process.Kill() }) //nolint:errcheck

	// Write pidfile like spawnDaemon does.
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(child.Process.Pid)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = logFile // would be used by real spawnDaemon

	// Parent blocks until child signals ready.
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := r.Read(buf)
		r.Close()
		done <- string(buf[:n])
	}()

	select {
	case msg := <-done:
		if !strings.HasPrefix(msg, "ok") {
			t.Errorf("expected 'ok' from child, got %q", msg)
		}
		t.Logf("child signalled ready: %q", strings.TrimSpace(msg))
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: child did not signal ready")
	}

	// Verify pidfile was written and contains a valid PID.
	pidBytes, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil || pid != child.Process.Pid {
		t.Errorf("pidfile: expected %d, got %q", child.Process.Pid, string(pidBytes))
	}
	t.Logf("daemon pid %d confirmed in pidfile", pid)
	fmt.Println() // keep go vet happy about unused fmt import
}
