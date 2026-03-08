//go:build agent_benchmark && canary

package agent

import (
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	agentpkg "github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/test/benchmark/harness"
)

// TestE2E_All loads all E2E definitions and runs each.
func TestE2E_All(t *testing.T) {
	dir := filepath.Join(definitionsDir(), "e2e")
	defs, err := harness.LoadAgentE2EDefinitionsFromDir(dir)
	require.NoError(t, err, "failed to load E2E definitions")
	require.NotEmpty(t, defs, "no E2E definitions found in %s", dir)

	for _, def := range defs {
		t.Run(def.App.Name, func(t *testing.T) {
			runE2EDefinition(t, def)
		})
	}
}

func TestE2E_VAmPI(t *testing.T) {
	defPath := filepath.Join(definitionsDir(), "e2e", "vampi-agent-scan.yaml")
	def, err := harness.LoadAgentE2EDefinition(defPath)
	require.NoError(t, err, "failed to load E2E definition")
	runE2EDefinition(t, def)
}

func runE2EDefinition(t *testing.T, def *harness.AgentE2EDefinition) {
	t.Helper()

	// Check that the target app is reachable
	waitURL := def.App.BaseURL + def.App.WaitPath
	if !waitForApp(t, waitURL, 10*time.Second) {
		t.Skipf("target app %s not reachable at %s, skipping", def.App.Name, waitURL)
		return
	}

	// Load fixture
	fPath := fixturePath(def.Fixture)
	fixture, err := harness.LoadAgentFixture(fPath)
	require.NoError(t, err, "failed to load fixture %s", fPath)

	// Parse HTTP records from fixture
	records, parseErr := agentpkg.ParseHTTPRecords(fixture.RawOutput)
	require.NoError(t, parseErr, "[%s] failed to parse HTTP records", def.Fixture)
	require.NotEmpty(t, records, "[%s] no HTTP records in fixture", def.Fixture)

	// Limit records if configured
	if def.ScanConfig.MaxRecords > 0 && len(records) > def.ScanConfig.MaxRecords {
		records = records[:def.ScanConfig.MaxRecords]
	}

	t.Logf("[%s] Loaded %d HTTP records, rewriting URLs to %s", def.App.Name, len(records), def.App.BaseURL)

	// Setup test infrastructure
	infra, err := harness.SetupTestInfra()
	require.NoError(t, err, "failed to setup test infra")
	defer infra.Cleanup()

	// Resolve modules
	mods, err := harness.ResolveActiveModules(def.ScanConfig.Modules)
	require.NoError(t, err, "failed to resolve modules: %v", def.ScanConfig.Modules)

	targetURL, _ := url.Parse(def.App.BaseURL)
	var totalFindings int

	for _, rec := range records {
		// Rewrite the record URL to target the actual vulnerable app
		rewrittenRec := rewriteRecordURL(rec, def.App.BaseURL)

		hrr, convErr := agentpkg.ToHTTPRequestResponse(rewrittenRec)
		if convErr != nil {
			t.Logf("[%s] Skip record %s %s: %v", def.App.Name, rec.Method, rec.URL, convErr)
			continue
		}

		// Create insertion points
		points, ipErr := httpmsg.CreateAllInsertionPoints(hrr.Request().Raw(), true)
		if ipErr != nil {
			t.Logf("[%s] Skip insertion points for %s %s: %v", def.App.Name, rec.Method, rec.URL, ipErr)
			continue
		}

		// Run each module against the record
		for _, mod := range mods {
			scanScopes := mod.ScanScopes()

			if scanScopes.Has(modkit.ScanScopeInsertionPoint) {
				// Filter insertion points by module's allowed types
				allowedTypes := mod.AllowedInsertionPointTypes()
				for _, ip := range points {
					if !allowedTypes.Contains(ip.Type()) {
						continue
					}
					findings, scanErr := mod.ScanPerInsertionPoint(hrr, ip, infra.HTTPClient, infra.ScanCtx)
					if scanErr != nil {
						continue
					}
					totalFindings += len(findings)
					for _, f := range findings {
						t.Logf("[%s] FINDING: %s (module=%s, severity=%s)",
							def.App.Name, f.Info.Name, mod.ID(), f.Info.Severity)
					}
				}
			} else if scanScopes.Has(modkit.ScanScopeRequest) {
				findings, scanErr := mod.ScanPerRequest(hrr, infra.HTTPClient, infra.ScanCtx)
				if scanErr != nil {
					continue
				}
				totalFindings += len(findings)
			} else if scanScopes.Has(modkit.ScanScopeHost) {
				findings, scanErr := mod.ScanPerHost(hrr, infra.HTTPClient, infra.ScanCtx)
				if scanErr != nil {
					continue
				}
				totalFindings += len(findings)
			}
		}
	}

	t.Logf("[%s] Total findings: %d (target: %s, modules: %v)",
		def.App.Name, totalFindings, targetURL.Host, def.ScanConfig.Modules)

	// Validate findings
	soft := def.Expected.Assertion == "soft"
	if soft {
		if totalFindings < def.Expected.MinFindings {
			t.Logf("SOFT ASSERTION: expected at least %d findings, got %d",
				def.Expected.MinFindings, totalFindings)
		}
	} else {
		assert.GreaterOrEqual(t, totalFindings, def.Expected.MinFindings,
			"[%s] expected at least %d findings, got %d",
			def.App.Name, def.Expected.MinFindings, totalFindings)
	}
}

// rewriteRecordURL replaces the host:port in a record's URL with the target base URL.
func rewriteRecordURL(rec agentpkg.AgentHTTPRecord, baseURL string) agentpkg.AgentHTTPRecord {
	result := rec
	parsedTarget, err := url.Parse(baseURL)
	if err != nil {
		return result
	}

	parsedOrig, err := url.Parse(rec.URL)
	if err != nil {
		return result
	}

	parsedOrig.Scheme = parsedTarget.Scheme
	parsedOrig.Host = parsedTarget.Host
	result.URL = parsedOrig.String()

	// Update Host header if present
	if result.Headers != nil {
		for k := range result.Headers {
			if strings.EqualFold(k, "Host") {
				result.Headers[k] = parsedTarget.Host
			}
		}
	}

	return result
}

// waitForApp polls the given URL until it returns a 2xx/3xx status or timeout.
func waitForApp(t *testing.T, url string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 5 * time.Second}

	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 400 {
				return true
			}
		}
		time.Sleep(1 * time.Second)
	}

	t.Logf("timeout waiting for %s after %s", url, timeout)
	return false
}

