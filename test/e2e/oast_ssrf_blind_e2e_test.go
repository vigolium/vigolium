//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/types"
)

// startSSRFVulnerableServer creates a fake HTTP server that simulates SSRF vulnerabilities.
// /fetch?url=... — fetches the URL (simulates blind SSRF)
// /api/data     — fetches URLs from Referer/X-Forwarded-For headers (for oast-probe)
func startSSRFVulnerableServer(t *testing.T) *httptest.Server {
	t.Helper()
	fetchClient := &http.Client{Timeout: 5 * time.Second}

	mux := http.NewServeMux()

	mux.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		targetURL := r.URL.Query().Get("url")
		if targetURL != "" {
			resp, err := fetchClient.Get(targetURL)
			if err == nil {
				resp.Body.Close()
			}
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>Fetched</body></html>`))
	})

	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		for _, header := range []string{"Referer", "X-Forwarded-For", "X-Forwarded-Host", "Origin"} {
			val := r.Header.Get(header)
			if val != "" && (strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://")) {
				resp, err := fetchClient.Get(val)
				if err == nil {
					resp.Body.Close()
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// runOASTScan runs a scan with OAST enabled, targeting specific modules.
func runOASTScan(t *testing.T, targets, modules []string) (*database.DB, *database.Repository) {
	t.Helper()
	oastCfg := oastTestConfig(t)

	db, repo, _ := setupStatelessDB(t)

	opts := types.DefaultOptions()
	opts.Targets = targets
	opts.Modules = modules
	opts.PassiveModules = []string{}
	opts.Silent = true
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.KnownIssueScanEnabled = false
	opts.HeuristicsCheck = "none"

	settings := config.DefaultSettings()
	settings.OAST = *oastCfg

	r, err := runner.New(opts)
	require.NoError(t, err)

	r.SetSettings(settings)
	r.SetRepository(repo)

	err = r.RunNativeScan()
	require.NoError(t, err, "RunNativeScan should complete without error")
	r.Close()

	return db, repo
}

func TestOAST_SSRFBlind_FullPipeline(t *testing.T) {
	srv := startSSRFVulnerableServer(t)

	db, _ := runOASTScan(t,
		[]string{srv.URL + "/fetch?url=http://example.com"},
		[]string{"ssrf-blind"},
	)

	ctx := context.Background()
	var interactions []*database.OASTInteraction
	err := db.NewSelect().Model(&interactions).
		Where("module_id = ?", "ssrf-blind").
		Scan(ctx)
	require.NoError(t, err)
	t.Logf("OAST interactions for ssrf-blind: %d", len(interactions))
	for i, ix := range interactions {
		t.Logf("  [%d] protocol=%s target=%s param=%s remote=%s",
			i, ix.Protocol, ix.TargetURL, ix.ParameterName, ix.RemoteAddress)
	}
	assert.GreaterOrEqual(t, len(interactions), 1,
		"expected at least 1 OAST interaction from ssrf-blind scanning a vulnerable endpoint")

	var findings []*database.Finding
	err = db.NewSelect().Model(&findings).
		Where("module_id = ?", "ssrf-blind").
		Scan(ctx)
	require.NoError(t, err)
	t.Logf("Findings for ssrf-blind: %d", len(findings))
	assert.GreaterOrEqual(t, len(findings), 1,
		"expected at least 1 finding from ssrf-blind")

	if len(findings) > 0 {
		f := findings[0]
		assert.Contains(t, f.URL, "/fetch", "finding URL should reference the vulnerable endpoint")
		t.Logf("  finding: severity=%s url=%s", f.Severity, f.URL)
	}
}

func TestOAST_OASTProbe_FullPipeline(t *testing.T) {
	srv := startSSRFVulnerableServer(t)

	db, _ := runOASTScan(t,
		[]string{srv.URL + "/api/data"},
		[]string{"oast-probe"},
	)

	ctx := context.Background()
	var interactions []*database.OASTInteraction
	err := db.NewSelect().Model(&interactions).
		Where("module_id = ?", "oast-probe").
		Scan(ctx)
	require.NoError(t, err)
	t.Logf("OAST interactions for oast-probe: %d", len(interactions))
	for i, ix := range interactions {
		t.Logf("  [%d] protocol=%s target=%s param=%s injection=%s",
			i, ix.Protocol, ix.TargetURL, ix.ParameterName, ix.InjectionType)
	}
	assert.GreaterOrEqual(t, len(interactions), 1,
		"expected at least 1 OAST interaction from oast-probe header injection")

	var findings []*database.Finding
	err = db.NewSelect().Model(&findings).
		Where("module_id = ?", "oast-probe").
		Scan(ctx)
	require.NoError(t, err)
	t.Logf("Findings for oast-probe: %d", len(findings))
	assert.GreaterOrEqual(t, len(findings), 1,
		"expected at least 1 finding from oast-probe")

	if len(findings) > 0 {
		f := findings[0]
		assert.Contains(t, f.URL, "/api/data", "finding URL should reference the target endpoint")
		t.Logf("  finding: severity=%s url=%s", f.Severity, f.URL)
	}

	// Verify OAST interactions recorded header injection type
	foundHeader := false
	for _, ix := range interactions {
		if ix.InjectionType == "header" {
			foundHeader = true
			break
		}
	}
	assert.True(t, foundHeader, "at least one OAST interaction should be from header injection")
}

func TestOAST_SSRFBlindAndProbe_Combined(t *testing.T) {
	srv := startSSRFVulnerableServer(t)

	db, _ := runOASTScan(t,
		[]string{
			srv.URL + "/fetch?url=http://example.com",
			srv.URL + "/api/data",
		},
		[]string{"ssrf-blind", "oast-probe"},
	)

	ctx := context.Background()
	var interactions []*database.OASTInteraction
	err := db.NewSelect().Model(&interactions).Scan(ctx)
	require.NoError(t, err)
	t.Logf("Total OAST interactions: %d", len(interactions))

	moduleIDs := make(map[string]int)
	for _, ix := range interactions {
		moduleIDs[ix.ModuleID]++
	}
	t.Logf("Interactions by module: %v", moduleIDs)

	assert.GreaterOrEqual(t, len(interactions), 2,
		"expected interactions from both modules combined")

	var findings []*database.Finding
	err = db.NewSelect().Model(&findings).Scan(ctx)
	require.NoError(t, err)
	t.Logf("Total findings: %d", len(findings))

	findingModules := make(map[string]int)
	for _, f := range findings {
		findingModules[f.ModuleID]++
	}
	t.Logf("Findings by module: %v", findingModules)

	assert.GreaterOrEqual(t, len(findings), 2,
		"expected findings from both ssrf-blind and oast-probe")
}
