//go:build !windows

package procutil

import (
	"os/exec"
	"syscall"
	"testing"
)

func TestSetupProcessGroupSetsPgid(t *testing.T) {
	cmd := exec.Command("true")
	SetupProcessGroup(cmd)

	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr is nil after SetupProcessGroup")
	}
	if !cmd.SysProcAttr.Setpgid {
		t.Error("Setpgid = false, want true (group kill requires a new process group)")
	}
	if cmd.Cancel == nil {
		t.Error("Cancel func not installed")
	}
}

func TestSetupProcessGroupPreservesExistingAttr(t *testing.T) {
	cmd := exec.Command("true")
	cmd.SysProcAttr = &syscall.SysProcAttr{} // pre-existing, non-nil
	SetupProcessGroup(cmd)
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		t.Error("expected Setpgid set even when SysProcAttr pre-existed")
	}
}

func TestCancelNilProcessIsSafe(t *testing.T) {
	cmd := exec.Command("true")
	SetupProcessGroup(cmd)
	// Process was never started, so cmd.Process is nil. Cancel must not panic
	// and must return nil per the implementation contract.
	if err := cmd.Cancel(); err != nil {
		t.Errorf("Cancel() with nil Process = %v, want nil", err)
	}
}
