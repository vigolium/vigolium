package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/diagnostics"
)

// TestInstallCoreDeps_FailsNotReady is RUN-7: an init whose downloads failed
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
	initOffline = true
	t.Cleanup(func() { initOffline = false })
	runCoreDepFixes = func(context.Context, *diagnostics.Report, *config.Settings, []string) []diagnostics.FixResult {
		t.Fatal("--offline must not download")
		return nil
	}
	_ = captureStderr(t, func() { err = installCoreDeps() })
	if err != nil {
		t.Fatalf("--offline installCoreDeps = %v, want nil", err)
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
