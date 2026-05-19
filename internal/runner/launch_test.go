package runner

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

func TestLaunchScanRejectsEmptyTargets(t *testing.T) {
	_, err := LaunchScan(context.Background(), LaunchParams{})
	if err == nil {
		t.Fatal("expected error when Targets is empty")
	}
	if !strings.Contains(err.Error(), "target") {
		t.Errorf("expected target-related error, got: %v", err)
	}
}

func TestBuildLaunchOptions(t *testing.T) {
	params := LaunchParams{
		Targets:          []string{"https://example.com"},
		ProjectUUID:      "proj-123",
		ConfigPath:       "/tmp/cfg.yaml",
		Modules:          []string{"xss", "sqli"},
		PassiveModules:   []string{"secret_detect"},
		ExtensionsOnly:   true,
		ScanningStrategy: "lite",
		EnableDiscovery:  true,
		EnableSpidering:  false,
		Concurrency:      25,
	}
	opts := buildLaunchOptions(params)

	if got, want := opts.Targets[0], "https://example.com"; got != want {
		t.Errorf("Targets[0] = %q, want %q", got, want)
	}
	if opts.ProjectUUID != "proj-123" {
		t.Errorf("ProjectUUID = %q, want proj-123", opts.ProjectUUID)
	}
	if opts.ConfigPath != "/tmp/cfg.yaml" {
		t.Errorf("ConfigPath = %q, want /tmp/cfg.yaml", opts.ConfigPath)
	}
	if len(opts.Modules) != 2 || opts.Modules[0] != "xss" {
		t.Errorf("Modules = %v, want [xss sqli]", opts.Modules)
	}
	if len(opts.PassiveModules) != 1 || opts.PassiveModules[0] != "secret_detect" {
		t.Errorf("PassiveModules = %v, want [secret_detect]", opts.PassiveModules)
	}
	if !opts.ExtensionsOnly {
		t.Error("ExtensionsOnly should be true")
	}
	if opts.ScanningStrategy != "lite" {
		t.Errorf("ScanningStrategy = %q, want lite", opts.ScanningStrategy)
	}
	if !opts.DiscoverEnabled {
		t.Error("DiscoverEnabled should be true")
	}
	if opts.SpideringEnabled {
		t.Error("SpideringEnabled should be false")
	}
	if opts.Concurrency != 25 {
		t.Errorf("Concurrency = %d, want 25", opts.Concurrency)
	}
	if !opts.ConcurrencyExplicitlySet {
		t.Error("ConcurrencyExplicitlySet should be true when Concurrency is set")
	}
	if !opts.Silent {
		t.Error("Silent should default to true for library callers")
	}
	if opts.ScanUUID == "" {
		t.Error("ScanUUID should be auto-generated")
	}

	// Default-passive-modules path: empty PassiveModules in params
	// shouldn't clobber the DefaultOptions value of ["all"].
	params2 := LaunchParams{Targets: []string{"x"}}
	opts2 := buildLaunchOptions(params2)
	if len(opts2.PassiveModules) == 0 {
		t.Error("PassiveModules should retain DefaultOptions value when params is empty")
	}
}

func TestApplyExtensionOverridesNoop(t *testing.T) {
	settings := &config.Settings{}
	if err := applyExtensionOverrides(settings, nil); err != nil {
		t.Fatalf("nil paths should be a no-op: %v", err)
	}
	if settings.DynamicAssessment.Extensions.Enabled {
		t.Error("Extensions should not be enabled when no paths supplied")
	}
}

func TestApplyExtensionOverridesAppendsAndEnables(t *testing.T) {
	settings := &config.Settings{}
	settings.DynamicAssessment.Extensions.CustomDir = []string{"existing.js"}

	tmp := t.TempDir()
	scriptA := filepath.Join(tmp, "a.js")
	scriptB := filepath.Join(tmp, "b.js")
	// Files don't need to exist for path resolution — applyExtensionOverrides
	// only filepath.Abs's them. Validation happens later in jsext.LoadScripts.

	if err := applyExtensionOverrides(settings, []string{scriptA, scriptB}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ext := settings.DynamicAssessment.Extensions
	if !ext.Enabled {
		t.Error("Extensions should be enabled after overrides")
	}
	if len(ext.CustomDir) != 3 {
		t.Fatalf("CustomDir len = %d, want 3 (existing + 2 new)", len(ext.CustomDir))
	}
	if ext.CustomDir[0] != "existing.js" {
		t.Errorf("existing entry should be preserved at index 0, got %q", ext.CustomDir[0])
	}
	if !filepath.IsAbs(ext.CustomDir[1]) {
		t.Errorf("supplied path should be absolutized, got %q", ext.CustomDir[1])
	}
}
