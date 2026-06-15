//go:build windows

package procutil

import (
	"os/exec"
	"strconv"

	"golang.org/x/sys/windows"
)

// stillActive is the exit code Windows reports for a process that is still
// running (STILL_ACTIVE / STATUS_PENDING).
const stillActive = 259

// SetupProcessGroup is a no-op on Windows, which has no POSIX process groups; the
// default exec.CommandContext cancellation (Process.Kill) applies. The shell
// commands these helpers run target a POSIX shell and are not expected to run on
// Windows.
func SetupProcessGroup(cmd *exec.Cmd) {}

// ProcessGroupID returns pid unchanged — Windows has no process groups, so the
// leader pid stands in for the group wherever these helpers take a "pgid".
func ProcessGroupID(pid int) int { return pid }

// IsProcessAlive reports whether pid is a live process.
func IsProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h) //nolint:errcheck
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}

// IsProcessGroupAlive reports whether the leader process pgid is still running.
// Windows can't cheaply test a whole tree's liveness, so the leader stands in.
func IsProcessGroupAlive(pgid int) bool { return IsProcessAlive(pgid) }

// SignalProcessGroup best-effort terminates the process tree rooted at pgid.
// Windows has no process-group signals and no graceful SIGTERM for non-console
// children, so both the graceful and forceful paths force-kill the whole tree
// via `taskkill /T`. Errors are ignored — the process may already be gone.
func SignalProcessGroup(pgid int, kill bool) error {
	if pgid <= 0 {
		return nil
	}
	_ = exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(pgid)).Run()
	return nil
}
