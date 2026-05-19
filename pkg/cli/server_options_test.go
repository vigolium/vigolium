package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNewServerRunnerOptions_LoadsActiveAndPassiveModules is a regression
// guard for a bug where pkg/cli/server.go constructed runnerOpts from scratch
// without setting PassiveModules, silently dropping all 91 passive modules in
// scan-on-receive mode. Symptom was server scans completing with 143/143
// modules while the equivalent CLI scan-request showed 234/234 (143 active +
// 91 passive) — and all passive-only findings (security headers, cookie
// flags, cacheability, etc.) missing from server-scanned traffic.
//
// Both fields MUST be "all" for server mode to match CLI scan behavior.
func TestNewServerRunnerOptions_LoadsActiveAndPassiveModules(t *testing.T) {
	opts := newServerRunnerOptions(&serverOptions{}, 50, 20, 30, "", false)

	assert.Equal(t, []string{"all"}, opts.Modules,
		"Modules must be 'all' — server mode must enable every active module")
	assert.Equal(t, []string{"all"}, opts.PassiveModules,
		"PassiveModules must be 'all' — server mode must enable every passive module. "+
			"If this fails, the runner will silently run 0 passive modules and scan-on-receive "+
			"will under-scan every ingested request compared to scan-request.")
}

// TestNewServerRunnerOptions_BasicFields sanity-checks the trivial fields so
// that a sweeping refactor of the helper is caught by tests.
func TestNewServerRunnerOptions_BasicFields(t *testing.T) {
	so := &serverOptions{Output: "/tmp/findings.jsonl"}
	opts := newServerRunnerOptions(so, 42, 15, 7, "http://proxy:8080", true)

	assert.Equal(t, 42, opts.Concurrency)
	assert.Equal(t, 15, opts.MaxPerHost)
	assert.Equal(t, 7, opts.MaxHostError)
	assert.Equal(t, "/tmp/findings.jsonl", opts.Output)
	assert.Equal(t, "http://proxy:8080", opts.ProxyURL)
	assert.True(t, opts.Verbose)
	assert.True(t, opts.Silent, "server mode always suppresses phase banners")
}
