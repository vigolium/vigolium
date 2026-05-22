//go:build !windows

// Package procutil provides cross-platform process-management helpers shared by
// the command-execution surfaces (the olium bash tool and the JS extension
// exec() builtin).
package procutil

import (
	"os/exec"
	"syscall"
)

// SetupProcessGroup configures cmd so that cancelling its context (a timeout or
// caller cancellation) kills the entire process group — the spawned shell plus
// any pipeline or background children it created — instead of orphaning them
// when only the parent shell is signalled.
//
// It must be called after the command is constructed and before Start/Run. On
// Windows it is a no-op (see procgroup_windows.go).
func SetupProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	// Override exec.CommandContext's default cancel (Process.Kill, parent only)
	// with a group kill. A negative PID signals the whole process group.
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return cmd.Process.Kill()
	}
}
