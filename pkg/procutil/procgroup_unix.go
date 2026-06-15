//go:build !windows

// Package procutil provides cross-platform process-management helpers shared by
// the command-execution surfaces (the olium bash tool and the JS extension
// exec() builtin).
package procutil

import (
	"errors"
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

// ProcessGroupID returns the process group id for pid, falling back to pid
// itself when it can't be determined.
func ProcessGroupID(pid int) int {
	if pgid, err := syscall.Getpgid(pid); err == nil {
		return pgid
	}
	return pid
}

// IsProcessAlive reports whether pid is a live process, using signal 0 (the
// POSIX existence check). EPERM counts as alive — the process exists, we just
// lack permission to signal it.
func IsProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// IsProcessGroupAlive reports whether any process remains in the group led by pgid.
func IsProcessGroupAlive(pgid int) bool {
	if pgid <= 0 {
		return false
	}
	err := syscall.Kill(-pgid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// SignalProcessGroup signals every process in the group led by pgid: SIGKILL
// when kill is true, otherwise SIGTERM. A "no such process" result means the
// group is already gone and is reported as success.
func SignalProcessGroup(pgid int, kill bool) error {
	if pgid <= 0 {
		return nil
	}
	sig := syscall.SIGTERM
	if kill {
		sig = syscall.SIGKILL
	}
	if err := syscall.Kill(-pgid, sig); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}
