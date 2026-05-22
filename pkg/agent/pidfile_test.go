package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunPID_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	// WriteRunPID with empty dir is a no-op.
	if err := WriteRunPID(""); err != nil {
		t.Errorf("empty dir should be a no-op, got %v", err)
	}

	if err := WriteRunPID(dir); err != nil {
		t.Fatalf("WriteRunPID error: %v", err)
	}
	pidPath := filepath.Join(dir, "run.pid")
	info := ReadRunPID(pidPath)
	if info == nil {
		t.Fatal("ReadRunPID returned nil for a freshly written file")
	}
	if info.PID != os.Getpid() {
		t.Errorf("PID = %d, want current pid %d", info.PID, os.Getpid())
	}
	if info.StartTime.IsZero() {
		t.Error("StartTime should be set")
	}

	// RemoveRunPID clears the file; subsequent read returns nil.
	RemoveRunPID(dir)
	if ReadRunPID(pidPath) != nil {
		t.Error("ReadRunPID should return nil after RemoveRunPID")
	}
	// Removing again is harmless.
	RemoveRunPID(dir)
	RemoveRunPID("")
}

func TestReadRunPID_BadInputs(t *testing.T) {
	if ReadRunPID(filepath.Join(t.TempDir(), "missing.pid")) != nil {
		t.Error("missing file should return nil")
	}

	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pid")
	if err := os.WriteFile(bad, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ReadRunPID(bad) != nil {
		t.Error("invalid JSON should return nil")
	}
}

func TestIsProcessAlive(t *testing.T) {
	if IsProcessAlive(os.Getpid()) != true {
		t.Error("current process should be alive")
	}
	if IsProcessAlive(0) || IsProcessAlive(-1) {
		t.Error("non-positive PIDs should be reported dead")
	}
	// A very high PID is almost certainly not a live process.
	if IsProcessAlive(1 << 30) {
		t.Error("an absurdly high PID should not be alive")
	}
}
