package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/diagnostics"
)

// TestInstallCoreDeps_FailsNotReady: an init whose downloads failed
// must not report success.
func TestInstallCoreDeps_FailsNotReady(t *testing.T) {
	marker := stageCoreDeps(t, coreDepState{chromeMissing: true, nucleiMissing: true})
	runCoreDepFixes = func(context.Context, *diagnostics.Report, *config.Settings, []string) []diagnostics.FixResult {
		return []diagnostics.FixResult{{Label: "chrome", Success: false, Message: "download failed"}}
	}
	var err error
	_ = captureStderr(t, func() { err = installCoreDeps() })
	var coded interface{ Code() apicontract.ErrorCode }
	if !errors.As(err, &coded) || coded.Code() != apicontract.CodeNotReady {
		t.Fatalf("installCoreDeps = %v, want a not_ready error", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("marker stamped although the install failed")
	}

	// --offline downloads nothing and does not fail.
	prevOffline := globalOffline
	globalOffline = true
	t.Cleanup(func() { globalOffline = prevOffline })
	runCoreDepFixes = func(context.Context, *diagnostics.Report, *config.Settings, []string) []diagnostics.FixResult {
		t.Fatal("--offline must not download")
		return nil
	}
	_ = captureStderr(t, func() { err = installCoreDeps() })
	if err != nil {
		t.Fatalf("--offline installCoreDeps = %v, want nil", err)
	}
}

// TestInstallCoreDeps_FailedInstallExitsNonZero: a dependency install that
// fails fails init (not_ready, exit 1, no marker) even when the check after
// it passes, so a driver can trust init's exit code rather than the marker.
func TestInstallCoreDeps_FailedInstallExitsNonZero(t *testing.T) {
	marker := stageCoreDeps(t, coreDepState{chromeMissing: true})
	calls := 0
	checkCoreDeps = func(*config.Settings) coreDepState {
		calls++
		if calls == 1 {
			return coreDepState{chromeMissing: true}
		}
		return coreDepState{} // a system browser turned up; the install still failed
	}
	runCoreDepFixes = func(context.Context, *diagnostics.Report, *config.Settings, []string) []diagnostics.FixResult {
		return []diagnostics.FixResult{
			{Label: "nuclei-templates", Success: true, Message: "installed"},
			{Label: "chrome", Success: false, Message: "download failed: connection reset"},
		}
	}
	var err error
	_ = captureStderr(t, func() { err = installCoreDeps() })
	var coded interface{ Code() apicontract.ErrorCode }
	if !errors.As(err, &coded) || coded.Code() != apicontract.CodeNotReady {
		t.Fatalf("installCoreDeps = %v, want a not_ready error", err)
	}
	if coded.Code().Exit() != apicontract.ExitError {
		t.Fatalf("not_ready exits %d, want %d", coded.Code().Exit(), apicontract.ExitError)
	}
	if !strings.Contains(err.Error(), "chrome (download failed: connection reset)") || strings.Contains(err.Error(), "nuclei-templates (") {
		t.Errorf("error %q should name the failed install only", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("marker stamped although an install failed")
	}
}

// TestBootstrapProfiles_WriteIfMissing: an existing profiles directory with
// one edited profile and the others deleted gets the missing ones back and
// keeps the edit.
func TestBootstrapProfiles_WriteIfMissing(t *testing.T) {
	dir := t.TempDir()
	profiles := filepath.Join(dir, "profiles")
	if err := os.MkdirAll(profiles, 0o755); err != nil {
		t.Fatal(err)
	}
	edited := filepath.Join(profiles, "quick.yaml")
	if err := os.WriteFile(edited, []byte("# mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bootstrapDefaultProfiles(dir)
	if data, _ := os.ReadFile(edited); string(data) != "# mine\n" {
		t.Fatalf("edited profile overwritten: %q", data)
	}
	for _, name := range []string{"standard.yaml", "full.yaml"} {
		if _, err := os.Stat(filepath.Join(profiles, name)); err != nil {
			t.Errorf("%s not restored: %v", name, err)
		}
	}
}

// Without a terminal init downloads nothing and says how to fetch the core
// dependencies; --with-deps and --offline override that either way.
func TestInitSkipsDownloadsWithoutTerminal(t *testing.T) {
	prevOffline, prevWith := globalOffline, initWithDeps
	t.Cleanup(func() { globalOffline, initWithDeps = prevOffline, prevWith })
	globalOffline, initWithDeps = false, false
	if stdinIsTerminal() {
		t.Skip("stdin is a terminal")
	}
	if initSkipsDownloads() == "" {
		t.Fatal("init without a terminal must skip the downloads")
	}
	initWithDeps = true
	if got := initSkipsDownloads(); got != "" {
		t.Fatalf("--with-deps must download, got skip reason %q", got)
	}
	globalOffline = true
	if initSkipsDownloads() != "--offline" {
		t.Fatal("--offline always skips")
	}
}
