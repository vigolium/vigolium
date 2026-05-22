//go:build windows

package procutil

import "os/exec"

// SetupProcessGroup is a no-op on Windows, which has no POSIX process groups; the
// default exec.CommandContext cancellation (Process.Kill) applies. The shell
// commands these helpers run target a POSIX shell and are not expected to run on
// Windows.
func SetupProcessGroup(cmd *exec.Cmd) {}
