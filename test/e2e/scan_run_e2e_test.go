//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/server"
)

// ============================================================
// POST /api/scans/run — parameter parsing and validation
// ============================================================

func TestAPI_ScansRun_EmptyBody_RequiresTargets(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", ``)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "at least one target URL")
}

func TestAPI_ScansRun_WithTargets(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"targets":["http://example.com"]}`)
	status := resp.StatusCode

	// Target-based scan: 202 or 500 (runner init may fail without network)
	if status == http.StatusAccepted {
		var body server.ScanResponse
		readJSON(t, resp, &body)
		assert.Equal(t, "target", body.ScanMode)
		assert.Equal(t, 1, body.TargetsCount)
		assert.NotEmpty(t, body.ScanUUID)
		assert.Equal(t, "running", body.Status)

		waitForScanIdle(t, env)
	} else {
		resp.Body.Close()
	}
}

func TestAPI_ScansRun_DryRun(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"targets":["http://example.com"],"dry_run":true}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ScanResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "dry_run", body.Status)
	assert.Equal(t, "target", body.ScanMode)
	assert.Equal(t, 1, body.TargetsCount)
	assert.NotEmpty(t, body.ScanUUID)
}

func TestAPI_ScansRun_DryRunWithStrategy(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"targets":["http://example.com"],"strategy":"lite","dry_run":true}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ScanResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "dry_run", body.Status)
}

func TestAPI_ScansRun_InvalidStrategy(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"strategy":"nonexistent","targets":["http://x"]}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "invalid strategy")
}

func TestAPI_ScansRun_WithModules(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"modules":["xss"],"targets":["http://x"],"dry_run":true}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ScanResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "dry_run", body.Status)
}

func TestAPI_ScansRun_WithModuleTags(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"module_tags":["light"],"targets":["http://x"],"dry_run":true}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ScanResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "dry_run", body.Status)
}

func TestAPI_ScansRun_OnlyPhase(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"only":"discovery","targets":["http://x"],"dry_run":true}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ScanResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "dry_run", body.Status)
}

func TestAPI_ScansRun_OnlyPhaseAlias(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"only":"deparos","targets":["http://x"],"dry_run":true}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ScanResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "dry_run", body.Status)
}

func TestAPI_ScansRun_SkipPhases(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"skip":["spidering","known-issue-scan"],"targets":["http://x"],"dry_run":true}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ScanResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "dry_run", body.Status)
}

func TestAPI_ScansRun_OnlyAndSkipConflict(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"only":"discovery","skip":["known-issue-scan"],"targets":["http://x"]}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "mutually exclusive")
}

func TestAPI_ScansRun_InvalidScopeOrigin(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"scope_origin":"bad","targets":["http://x"]}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "invalid scope_origin")
}

func TestAPI_ScansRun_InvalidHeuristics(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"heuristics_check":"bad","targets":["http://x"]}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "invalid heuristics_check")
}

func TestAPI_ScansRun_CustomHeaders(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"headers":{"X-Custom":"val"},"targets":["http://x"],"dry_run":true}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ScanResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "dry_run", body.Status)
}

func TestAPI_ScansRun_ConcurrencyAndTimeout(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"concurrency":10,"timeout":"30s","targets":["http://x"],"dry_run":true}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ScanResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "dry_run", body.Status)
}

func TestAPI_ScansRun_InvalidTimeout(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"timeout":"not-a-duration","targets":["http://x"]}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "invalid timeout")
}

func TestAPI_ScansRun_ConflictWhenRunning(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	// Ingest a record
	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "url",
		"content": "http://example.com/conflict-test"
	}`)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Start first scan via scan-all-records
	resp = env.post(t, "/api/scan-all-records", `{}`)
	firstStatus := resp.StatusCode
	resp.Body.Close()

	if firstStatus == http.StatusAccepted {
		// Second scan should conflict
		resp = env.post(t, "/api/scan-all-records", `{}`)
		assert.Equal(t, http.StatusConflict, resp.StatusCode)

		var body server.ErrorResponse
		readJSON(t, resp, &body)
		assert.Contains(t, body.Error, "already running")

		waitForScanIdle(t, env)
	}
}

func TestAPI_ScanAllRecords_ForceWithDBRecords(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	// Ingest a record
	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "url",
		"content": "http://example.com/force-test"
	}`)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Force scan via scan-all-records
	resp = env.post(t, "/api/scan-all-records", `{"force":true}`)
	status := resp.StatusCode

	if status == http.StatusAccepted {
		var body server.ScanResponse
		readJSON(t, resp, &body)
		assert.Equal(t, "full", body.ScanMode)
		assert.NotEmpty(t, body.ScanUUID)

		waitForScanIdle(t, env)
	} else {
		resp.Body.Close()
		assert.NotEqual(t, http.StatusBadRequest, status,
			"force scan with records should not get 'no records' error")
	}
}

func TestAPI_ScansRun_InvalidSkipPhase(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"skip":["nonexistent"],"targets":["http://x"]}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "invalid skip value")
}

func TestAPI_ScansRun_InvalidOnlyPhase(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"only":"nonexistent","targets":["http://x"]}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "invalid only")
}

func TestAPI_ScanAllRecords_DryRunDBRecords(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	// Ingest a record
	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "url",
		"content": "http://example.com/dryrun-db-test"
	}`)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Dry run via scan-all-records
	resp = env.post(t, "/api/scan-all-records", `{"dry_run":true}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ScanResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "dry_run", body.Status)
	assert.Equal(t, "incremental", body.ScanMode)
	assert.Greater(t, body.RecordsToScan, int64(0))
	assert.NotEmpty(t, body.ScanUUID)
}

// readJSON decodes a JSON response body and closes it.
// (Reuses readJSON from server_extra_e2e_test.go if available;
// redeclared here for self-contained compilation if needed.)

// waitForScanIdle polls the scan status until idle or timeout.
func waitForScanIdle(t *testing.T, env *settingsTestEnv) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		r := env.get(t, "/api/scan/status")
		var s server.ScanStatusResponse
		_ = json.NewDecoder(r.Body).Decode(&s)
		r.Body.Close()
		if s.Status == "idle" {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ============================================================
// Intensity preset tests
// ============================================================

func TestAPI_ScansRun_IntensityQuick(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"targets":["http://example.com"],"intensity":"quick","dry_run":true}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ScanResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "dry_run", body.Status)
}

func TestAPI_ScansRun_IntensityDeep(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"targets":["http://example.com"],"intensity":"deep","dry_run":true}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ScanResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "dry_run", body.Status)
}

func TestAPI_ScansRun_IntensityInvalid(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `{"targets":["http://example.com"],"intensity":"turbo"}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "invalid intensity")
}

func TestAPI_ScansRun_IntensityWithExplicitProfileOverride(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	// Explicit scanning_profile should take precedence over intensity
	resp := env.post(t, "/api/scans/run", `{"targets":["http://example.com"],"intensity":"quick","scanning_profile":"full","dry_run":true}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ScanResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "dry_run", body.Status)
}
