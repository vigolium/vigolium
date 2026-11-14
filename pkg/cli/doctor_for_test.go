package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/diagnostics"
)

// TestDoctorFor is RUN-5: --for scopes the verdict and its exit code; an
// unknown purpose is a usage error (exit 2).
func TestDoctorFor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	swapGlobal(t, &globalConfig, "")
	swapGlobal(t, &globalDB, filepath.Join(home, "doctor.sqlite"))
	swapGlobal(t, &globalJSON, true)
	swapGlobal(t, &doctorFix, false)
	swapGlobal(t, &doctorOnly, nil)
	swapGlobal(t, &doctorStrict, false)
	swapGlobal(t, &doctorTarget, "")

	swapGlobal(t, &doctorFor, "bogus")
	if err := runDoctorCmd(doctorCmd, nil); classifyExitCode(err) != ExitUsageError {
		t.Fatalf("--for bogus exit = %d (%v), want 2", classifyExitCode(err), err)
	}

	// The full verdict is ready, but the agent provider is down: --for agent
	// is not_ready (exit 1), --for scan is not affected by the agent row.
	swapGlobal(t, &doctorRunDiagnostics, func(diagnostics.Deps) *diagnostics.Report {
		return &diagnostics.Report{
			Status:   "ready",
			Config:   &diagnostics.CheckResult{Status: diagnostics.StatusOK},
			Database: &diagnostics.CheckResult{Status: diagnostics.StatusOK},
			Agent:    &diagnostics.AgentCheck{Status: diagnostics.StatusError, Name: "olium", Message: "no provider"},
			Tools:    map[string]*diagnostics.ToolCheck{},
		}
	})
	for purpose, wantExit := range map[string]int{"agent": ExitError, "server": ExitSuccess} {
		swapGlobal(t, &doctorFor, purpose)
		jsonResultEmitted = false
		var err error
		out := captureStdout(t, func() { err = runDoctorCmd(doctorCmd, nil) })
		jsonResultEmitted = false
		if got := classifyExitCode(err); got != wantExit {
			t.Fatalf("--for %s exit = %d (%v), want %d", purpose, got, err, wantExit)
		}
		if !strings.Contains(out, `"for":"`+purpose+`"`) || !strings.Contains(out, `"checks":[`) || !strings.Contains(out, `"counts":`) {
			t.Fatalf("--for %s -j lacks for/checks: %s", purpose, out)
		}
	}
}
