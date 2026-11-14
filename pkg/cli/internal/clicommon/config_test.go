package clicommon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
)

// captureWarnings redirects ConfigWarn for one test and returns the collected
// messages.
func captureWarnings(t *testing.T) *[]string {
	t.Helper()
	var got []string
	prev := ConfigWarn
	ConfigWarn = func(msg string) { got = append(got, msg) }
	ResetConfigWarningsForTest()
	t.Cleanup(func() {
		ConfigWarn = prev
		ResetConfigWarningsForTest()
	})
	return &got
}

// An explicit --config that cannot be parsed fails. This is the whole point of
// the helper: the old behaviour ran the command on defaults and exited 0.
func TestLoadSettingsExplicitBrokenFails(t *testing.T) {
	_ = captureWarnings(t)
	path := filepath.Join(t.TempDir(), "broken.yaml")
	if err := os.WriteFile(path, []byte("server: [1, 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSettings(path); err == nil {
		t.Fatal("expected an error for an explicit broken --config")
	}
}

// RUN-8: a DISCOVERED broken config is fatal (config_invalid, naming the path
// and the validate command) on every command the root marks; it used to
// degrade silently to built-in defaults, dropping scope excludes and rate
// limits.
func TestLoadSettingsDiscoveredBrokenFails(t *testing.T) {
	_ = captureWarnings(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".vigolium"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(home, ".vigolium", "vigolium-configs.yaml")
	if err := os.WriteFile(cfg, []byte("server: [1, 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := DiscoveredConfigFatal
	DiscoveredConfigFatal = true
	t.Cleanup(func() { DiscoveredConfigFatal = prev })

	_, err := LoadSettings("")
	var coded interface{ Code() apicontract.ErrorCode }
	if !errors.As(err, &coded) || coded.Code() != apicontract.CodeConfigInvalid {
		t.Fatalf("LoadSettings = %v, want a config_invalid error", err)
	}
	if !strings.Contains(err.Error(), cfg) || !strings.Contains(err.Error(), "vigolium config validate") {
		t.Errorf("error %q does not name the file and the validate command", err)
	}
}

// On the repair commands (DiscoveredConfigFatal unset) a DISCOVERED broken
// config degrades to defaults, with one warning naming it.
func TestLoadSettingsDiscoveredBrokenWarnsAndDefaults(t *testing.T) {
	warnings := captureWarnings(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".vigolium"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(home, ".vigolium", "vigolium-configs.yaml")
	if err := os.WriteFile(cfg, []byte("server: [1, 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	settings, err := LoadSettings("")
	if err != nil {
		t.Fatalf("a discovered broken config must not fail the command: %v", err)
	}
	if settings == nil {
		t.Fatal("settings = nil")
	}
	if len(*warnings) != 1 || !strings.Contains((*warnings)[0], cfg) {
		t.Fatalf("warnings = %v, want one naming %s", *warnings, cfg)
	}

	// Loading five times prints one warning: a scan loads settings repeatedly,
	// and five copies of the same line read as five problems.
	for i := 0; i < 4; i++ {
		if _, err := LoadSettings(""); err != nil {
			t.Fatalf("repeat load: %v", err)
		}
	}
	if len(*warnings) != 1 {
		t.Errorf("warnings = %d, want 1 (deduped per process)", len(*warnings))
	}
}

// TestGetDBExplicitConfigErrorDoesNotOpenDefault: the failure that mattered
// most. GetDB used to swallow the config error and fall back to defaults, which
// means a typo in --config pointed every write at the shared default database —
// and CREATED it on the way.
func TestGetDBExplicitConfigErrorDoesNotOpenDefault(t *testing.T) {
	_ = captureWarnings(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	ResetDBCache()
	t.Cleanup(ResetDBCache)

	if _, err := GetDB(filepath.Join(home, "nonexistent.yaml"), ""); err == nil {
		t.Fatal("GetDB with a missing explicit --config should fail")
	}
	defaultDB := filepath.Join(home, ".vigolium", "database-vgnm.sqlite")
	if _, err := os.Stat(defaultDB); err == nil {
		t.Errorf("GetDB created the default database %s after refusing the config", defaultDB)
	}
}

// The same path with a usable config still opens, so the guard above is the
// config error and not a blanket refusal.
func TestGetDBOpensWithValidConfig(t *testing.T) {
	_ = captureWarnings(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	ResetDBCache()
	t.Cleanup(ResetDBCache)

	cfg := filepath.Join(home, "ok.yaml")
	dbPath := filepath.Join(home, "explicit.sqlite")
	if err := os.WriteFile(cfg, []byte("database:\n  enabled: true\n  driver: sqlite\n  sqlite:\n    path: "+dbPath+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := GetDB(cfg, "")
	if err != nil {
		t.Fatalf("GetDB: %v", err)
	}
	if db == nil {
		t.Fatal("db = nil")
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("configured database %s was not opened: %v", dbPath, err)
	}
	if _, err := os.Stat(filepath.Join(home, ".vigolium", "database-vgnm.sqlite")); err == nil {
		t.Error("the default database was created alongside the configured one")
	}
}

// Warnings from a successful load reach ConfigWarn once.
func TestLoadSettingsEmitsUnknownKeyWarning(t *testing.T) {
	warnings := captureWarnings(t)
	path := filepath.Join(t.TempDir(), "typo.yaml")
	if err := os.WriteFile(path, []byte("scanning_strategy:\n  default_stratgy: deep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	settings, err := LoadSettings(path)
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if settings.ScanningStrategy.DefaultStrategy != config.DefaultSettings().ScanningStrategy.DefaultStrategy {
		t.Error("an unknown key should leave the real field at its default")
	}
	if len(*warnings) != 1 || !strings.Contains((*warnings)[0], "default_stratgy") {
		t.Fatalf("warnings = %v, want one naming the typo", *warnings)
	}
}
