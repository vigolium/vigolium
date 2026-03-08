//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/types"
)

// setupExtTestDB creates an in-memory SQLite DB for extension e2e tests.
func setupExtTestDB(t *testing.T) (*database.DB, *database.Repository) {
	t.Helper()
	cfg := &config.DatabaseConfig{
		Enabled: true,
		Driver:  "sqlite",
		SQLite: config.SQLiteConfig{
			Path:        ":memory:",
			BusyTimeout: 5000,
			JournalMode: "MEMORY",
			Synchronous: "OFF",
			CacheSize:   10000,
		},
	}
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	require.NoError(t, db.CreateSchema(context.Background()))
	t.Cleanup(func() { _ = db.Close() })
	return db, database.NewRepository(db)
}

// newExtScanRunner creates a Runner with an in-memory DB and the given settings.
func newExtScanRunner(t *testing.T, opts *types.Options, settings *config.Settings) (*runner.Runner, *database.Repository) {
	t.Helper()
	_, repo := setupExtTestDB(t)

	r, err := runner.New(opts)
	require.NoError(t, err)

	r.SetSettings(settings)
	r.SetRepository(repo)

	t.Cleanup(func() { r.Close() })
	return r, repo
}

// canaryActiveScript returns a JS active extension that fires a finding for every request.
// The extension injects a unique marker, sends a request, and always reports a finding to verify it ran.
const canaryActiveScript = `
module.exports = {
  id: "ext-canary-active",
  name: "Canary Active Extension",
  description: "Reports a finding for every scanned insertion point",
  type: "active",
  severity: "info",
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    return [{
      matched: "canary",
      url: ctx.request.url,
      name: "Canary Active: extension ran",
      description: "Extension-only canary finding",
      severity: "info"
    }];
  }
};
`

// canaryPassiveScript returns a JS passive extension that fires for every response.
const canaryPassiveScript = `
module.exports = {
  id: "ext-canary-passive",
  name: "Canary Passive Extension",
  description: "Reports a finding for every observed response",
  type: "passive",
  severity: "info",
  scope: "response",
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response) return null;
    return [{
      matched: "canary-passive",
      url: ctx.request.url,
      name: "Canary Passive: extension ran",
      description: "Extension-only passive canary finding",
      severity: "info"
    }];
  }
};
`

// TestExtensionOnlyPhase verifies that ExtensionsOnly=true disables all built-in Go modules
// and only JS extension modules produce findings.
func TestExtensionOnlyPhase(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx := context.Background()

	httpbinApp, err := StartContainer(ctx, ContainerConfig{
		Image:         "kennethreitz/httpbin",
		ExposedPort:   "80/tcp",
		WaitStrategy:  wait.ForHTTP("/get").WithStartupTimeout(60 * time.Second),
		ReadyEndpoint: "/get",
	})
	require.NoError(t, err, "Failed to start httpbin container")
	defer httpbinApp.Stop()

	t.Logf("httpbin started at: %s", httpbinApp.BaseURL)

	// Write canary extension to temp dir
	scriptDir := t.TempDir()
	writeScript(t, scriptDir, "canary_active.js", canaryActiveScript)

	settings := config.DefaultSettings()
	settings.DynamicAssessment.Extensions.Enabled = true
	settings.DynamicAssessment.Extensions.ExtensionDir = scriptDir

	opts := types.DefaultOptions()
	opts.Targets = []string{fmt.Sprintf("%s/get?a=1", httpbinApp.BaseURL)}
	opts.Modules = []string{"all"}
	opts.PassiveModules = []string{"all"}
	opts.Silent = true
	opts.SkipDynamicAssessment = false
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.SpideringEnabled = false
	opts.SPAEnabled = false
	opts.SkipIngestion = true
	opts.ExtensionsOnly = true // only run JS extensions

	r, repo := newExtScanRunner(t, opts, settings)

	err = r.RunEnumeration()
	require.NoError(t, err)

	// Query findings from DB
	findings, err := database.NewFindingsQueryBuilder(repo.DB(), database.QueryFilters{Limit: 100}).Execute(context.Background())
	require.NoError(t, err)

	// Verify that the JS extension produced at least one finding
	var extFindings int
	for _, f := range findings {
		if strings.Contains(f.ModuleName, "Canary Active") {
			extFindings++
		}
	}
	assert.Greater(t, extFindings, 0,
		"Expected at least one finding from the canary JS extension")

	// Verify no built-in module findings (built-in modules have IDs like "active-*")
	// Extension findings have module IDs with "active-ext-" prefix
	for _, f := range findings {
		if f.ModuleID != "" {
			assert.True(t,
				strings.HasPrefix(f.ModuleID, "active-ext-") || strings.HasPrefix(f.ModuleID, "passive-ext-"),
				"Expected only extension module findings, got module ID: %s", f.ModuleID)
		}
	}

	t.Logf("ExtensionOnly phase: %d total findings, %d from canary extension", len(findings), extFindings)
}

// TestExtensionScanWithExtraScript verifies that an extension added via the --ext flag
// (simulated by appending to Scripts slice) runs alongside built-in modules.
func TestExtensionScanWithExtraScript(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx := context.Background()

	httpbinApp, err := StartContainer(ctx, ContainerConfig{
		Image:         "kennethreitz/httpbin",
		ExposedPort:   "80/tcp",
		WaitStrategy:  wait.ForHTTP("/get").WithStartupTimeout(60 * time.Second),
		ReadyEndpoint: "/get",
	})
	require.NoError(t, err, "Failed to start httpbin container")
	defer httpbinApp.Stop()

	t.Logf("httpbin started at: %s", httpbinApp.BaseURL)

	// Write extra script to a separate path (simulating --ext <path>)
	extraDir := t.TempDir()
	extraPath := writeScript(t, extraDir, "canary_passive.js", canaryPassiveScript)

	settings := config.DefaultSettings()
	settings.DynamicAssessment.Extensions.Enabled = true
	settings.DynamicAssessment.Extensions.CustomDir = []string{extraPath} // --ext equivalent

	opts := types.DefaultOptions()
	opts.Targets = []string{fmt.Sprintf("%s/get?a=1", httpbinApp.BaseURL)}
	opts.Modules = []string{"all"}
	opts.PassiveModules = []string{"all"}
	opts.Silent = true
	opts.SkipDynamicAssessment = false
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.SpideringEnabled = false
	opts.SPAEnabled = false
	opts.SkipIngestion = true
	opts.ExtensionsOnly = false // built-in modules also run

	r, repo := newExtScanRunner(t, opts, settings)

	err = r.RunEnumeration()
	require.NoError(t, err)

	findings, err := database.NewFindingsQueryBuilder(repo.DB(), database.QueryFilters{Limit: 100}).Execute(context.Background())
	require.NoError(t, err)

	// Verify the extra passive extension produced at least one finding
	var extFindings int
	for _, f := range findings {
		if strings.Contains(f.ModuleName, "Canary Passive") {
			extFindings++
		}
	}
	assert.Greater(t, extFindings, 0,
		"Expected at least one finding from the extra passive JS extension")

	t.Logf("ExtraScript test: %d total findings, %d from canary passive extension", len(findings), extFindings)
}

// TestExtensionListing verifies that jsext.LoadScripts() populates metadata correctly
// for active, passive, and hook extensions (no Docker required).
func TestExtensionListing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	scriptDir := t.TempDir()

	// Write one of each type
	writeScript(t, scriptDir, "active.js", `
module.exports = {
  id: "listing-active",
  name: "Listing Active",
  type: "active",
  severity: "medium",
  scanTypes: ["per_insertion_point", "per_request"],
  description: "Active listing test module"
};
`)
	writeScript(t, scriptDir, "passive.js", `
module.exports = {
  id: "listing-passive",
  name: "Listing Passive",
  type: "passive",
  severity: "info",
  scope: "response",
  scanTypes: ["per_request"],
  description: "Passive listing test module"
};
`)
	writeScript(t, scriptDir, "hook.js", `
module.exports = {
  id: "listing-hook",
  name: "Listing Hook",
  type: "pre_hook",
  description: "Pre-hook listing test module",
  execute: function(req) { return req; }
};
`)

	cfg := &config.ExtensionsConfig{
		Enabled:    true,
		ExtensionDir: scriptDir,
		Limits: config.ScriptLimits{
			Timeout:     "10s",
			MaxMemoryMB: 64,
		},
	}

	scripts, err := jsext.LoadScripts(cfg)
	require.NoError(t, err)
	require.Len(t, scripts, 3, "Expected 3 scripts loaded")

	byID := make(map[string]jsext.ScriptMetadata)
	for _, s := range scripts {
		byID[s.Metadata.ID] = s.Metadata
	}

	// Verify active metadata
	active, ok := byID["listing-active"]
	require.True(t, ok, "listing-active not found")
	assert.Equal(t, jsext.ScriptTypeActive, active.Type)
	assert.Equal(t, "medium", active.Severity)
	assert.Contains(t, active.ScanTypes, "per_insertion_point")
	assert.Contains(t, active.ScanTypes, "per_request")
	assert.Equal(t, "Active listing test module", active.Description)

	// Verify passive metadata
	passive, ok := byID["listing-passive"]
	require.True(t, ok, "listing-passive not found")
	assert.Equal(t, jsext.ScriptTypePassive, passive.Type)
	assert.Equal(t, "info", passive.Severity)
	assert.Equal(t, "response", passive.Scope)
	assert.Contains(t, passive.ScanTypes, "per_request")

	// Verify hook metadata
	hook, ok := byID["listing-hook"]
	require.True(t, ok, "listing-hook not found")
	assert.Equal(t, jsext.ScriptTypePreHook, hook.Type)
	assert.Equal(t, "Pre-hook listing test module", hook.Description)

	t.Logf("Extension listing: loaded %d scripts with correct metadata", len(scripts))
}
