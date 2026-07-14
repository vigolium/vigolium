//go:build e2e

package e2e

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/server"
)

// These tests spin up the full Vigolium REST API server in-process and drive a
// native scan AND an agentic (autopilot/swarm) scan entirely through the HTTP
// API — the same way an operator or the workbench UI would. They are the
// end-to-end regression guard for the class of bug where a server
// mis-wiring (e.g. a nil repository behind a live db handle) turned every
// scan-triggering endpoint into a nil-pointer panic / HTTP 500 at runtime.
//
// The target is a small, self-contained app on 127.0.0.1 (no Docker, no
// external network), so the native scan is hermetic and always-on. The agentic
// tests assert the launch/track/cancel wiring rather than a paid LLM run — the
// real, provider-backed autopilot run stays behind `make test-smoke-autopilot`.

// newRESTScanTarget starts a tiny vulnerable-ish web app on 127.0.0.1 for the
// REST scan e2e tests: a reflected sink on /search?q= plus a couple of linked
// routes so a scan has a real surface to request. Torn down with the test.
func newRESTScanTarget(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>demo app</h1>`+
			`<a href="/search?q=hello">search</a> `+
			`<a href="/api/item?id=1">item</a>`+
			`</body></html>`)
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Reflected, unescaped — a classic reflected-XSS shape for the scanner.
		fmt.Fprintf(w, `<html><body>Results for: %s</body></html>`, r.URL.Query().Get("q"))
	})
	mux.HandleFunc("/api/item", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q,"name":"item"}`, r.URL.Query().Get("id"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// agentProviderConfigured reports whether an LLM provider looks configured in
// this environment (mirrors the gate the smoke-autopilot script uses). When
// false, the agentic tests still assert the REST wiring but don't require the
// run to reach "completed".
func agentProviderConfigured() bool {
	if os.Getenv("ANTHROPIC_API_KEY") != "" || os.Getenv("OPENAI_API_KEY") != "" {
		return true
	}
	if home, err := os.UserHomeDir(); err == nil {
		if _, err := os.Stat(filepath.Join(home, ".codex", "auth.json")); err == nil {
			return true
		}
	}
	return false
}

// getBytes adapts settingsTestEnv.get to the (status, body) getter shape that
// waitForTerminalStatus (test/e2e/helper_test.go) consumes.
func (env *settingsTestEnv) getBytes(t *testing.T, path string) (int, []byte) {
	resp := env.get(t, path)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// TestAPI_REST_NativeScan_EndToEnd drives a native scan from trigger to terminal
// entirely over the REST API and confirms the scan surface is queryable — no
// endpoint in the flow may 500.
func TestAPI_REST_NativeScan_EndToEnd(t *testing.T) {
	env := newSettingsTestEnv(t, "")
	target := newRESTScanTarget(t)

	// Trigger the scan. lite strategy keeps it quick; the /search?q= sink gives the
	// dynamic-assessment phase a real reflected parameter to exercise.
	scanURL := target.URL + "/search?q=canary"
	resp := env.post(t, "/api/scans/run", fmt.Sprintf(`{"targets":[%q],"strategy":"lite"}`, scanURL))
	require.Equal(t, http.StatusAccepted, resp.StatusCode, "scan trigger must be accepted, not error/panic")
	var run server.ScanResponse
	readJSON(t, resp, &run)
	require.NotEmpty(t, run.ScanUUID)
	assert.Equal(t, "target", run.ScanMode)
	assert.Equal(t, "running", run.Status)

	// Poll the scan record to a terminal state via REST.
	final := waitForTerminalStatus(t, env.getBytes, "/api/scans/"+run.ScanUUID, 250*time.Millisecond, 120*time.Second)
	require.NotEmptyf(t, final, "scan %s did not reach a terminal state within 120s", run.ScanUUID)
	assert.Equal(t, "completed", final, "native scan against a live local target should finish cleanly")

	// The traffic the scan generated must be queryable without a 500, and at least
	// the target itself should have been recorded.
	rec := env.get(t, "/api/http-records?limit=500")
	require.Equal(t, http.StatusOK, rec.StatusCode)
	var recs server.PaginatedResponse
	readJSON(t, rec, &recs)
	assert.Greater(t, recs.Total, int64(0), "native scan should persist at least one HTTP record")

	// Findings endpoint must respond cleanly (a finding may or may not land).
	fnd := env.get(t, "/api/findings?limit=500")
	require.Equal(t, http.StatusOK, fnd.StatusCode)
	var findings server.PaginatedResponse
	readJSON(t, fnd, &findings)

	t.Logf("native REST scan %s: status=%s records=%d findings=%d",
		run.ScanUUID, final, recs.Total, findings.Total)
}

// TestAPI_REST_AgenticScan_Autopilot drives the autopilot agentic scan through
// the REST API: it must accept the launch (202 + tracked run), keep the server
// healthy, expose the run over the status endpoint, and cancel + settle without
// ever 500-ing. This is the wiring regression guard; a real provider-backed run
// lives in `make test-smoke-autopilot`.
func TestAPI_REST_AgenticScan_Autopilot(t *testing.T) {
	env := newSettingsTestEnv(t, "")
	target := newRESTScanTarget(t)

	// Small, bounded run so it settles fast even without a live LLM provider. The
	// short timeout plus the explicit cancel below keep it from hanging on the
	// pre-scan / a dead provider.
	body := fmt.Sprintf(`{"target":%q,"intensity":"quick","max_commands":1,"timeout":"20s","no_audit":true}`, target.URL)
	resp := env.post(t, "/api/agent/run/autopilot", body)
	require.Equal(t, http.StatusAccepted, resp.StatusCode, "autopilot trigger must be accepted, not error/panic")
	var run server.AgenticScanResponse
	readJSON(t, resp, &run)
	require.NotEmpty(t, run.AgenticScanUUID)
	assert.Equal(t, "running", run.Status)

	// The run must be visible over the status endpoint (200, not 404/500)...
	st := env.get(t, "/api/agent/status/"+run.AgenticScanUUID)
	require.Equal(t, http.StatusOK, st.StatusCode)
	var status server.AgenticScanStatusResponse
	readJSON(t, st, &status)
	assert.Equal(t, run.AgenticScanUUID, status.AgenticScanUUID)

	// ...and the server must stay healthy after launching the background pipeline.
	health := env.get(t, "/health")
	assert.Equal(t, http.StatusOK, health.StatusCode, "server must stay healthy after launching an agent run")
	_ = health.Body.Close()

	// Cancel so the run unwinds deterministically regardless of provider state;
	// the endpoint must not 500 (404 is fine if it already finished).
	cancel := env.post(t, "/api/agent/scans/"+run.AgenticScanUUID+"/cancel", ``)
	assert.NotEqual(t, http.StatusInternalServerError, cancel.StatusCode)
	_ = cancel.Body.Close()

	// The run must settle to a clean terminal state through the API — never a 500.
	final := waitForTerminalStatus(t, env.getBytes, "/api/agent/status/"+run.AgenticScanUUID, 300*time.Millisecond, 90*time.Second)
	if final == "" {
		t.Logf("autopilot run %s had not reached a terminal state yet; server shutdown will cancel it", run.AgenticScanUUID)
		return
	}
	assert.Contains(t, terminalRunStatuses, final,
		"autopilot run must reach a clean terminal state, got %q", final)
	if agentProviderConfigured() && final != "cancelled" {
		assert.Equal(t, "completed", final, "with a provider configured, an un-cancelled autopilot run should complete")
	}
	t.Logf("autopilot REST run %s settled: status=%s", run.AgenticScanUUID, final)
}

// TestAPI_REST_AgenticScan_Swarm is the swarm counterpart of the autopilot
// wiring test: launch → track → cancel → settle, all over REST, none 500-ing.
func TestAPI_REST_AgenticScan_Swarm(t *testing.T) {
	env := newSettingsTestEnv(t, "")
	target := newRESTScanTarget(t)

	body := fmt.Sprintf(`{"input":%q,"intensity":"quick","timeout":"20s"}`, target.URL+"/search?q=canary")
	resp := env.post(t, "/api/agent/run/swarm", body)
	require.Equal(t, http.StatusAccepted, resp.StatusCode, "swarm trigger must be accepted, not error/panic")
	var run server.AgenticScanResponse
	readJSON(t, resp, &run)
	require.NotEmpty(t, run.AgenticScanUUID)
	assert.Equal(t, "running", run.Status)

	st := env.get(t, "/api/agent/status/"+run.AgenticScanUUID)
	require.Equal(t, http.StatusOK, st.StatusCode)
	_ = st.Body.Close()

	health := env.get(t, "/health")
	assert.Equal(t, http.StatusOK, health.StatusCode)
	_ = health.Body.Close()

	cancel := env.post(t, "/api/agent/scans/"+run.AgenticScanUUID+"/cancel", ``)
	assert.NotEqual(t, http.StatusInternalServerError, cancel.StatusCode)
	_ = cancel.Body.Close()

	final := waitForTerminalStatus(t, env.getBytes, "/api/agent/status/"+run.AgenticScanUUID, 300*time.Millisecond, 90*time.Second)
	if final == "" {
		t.Logf("swarm run %s had not reached a terminal state yet; server shutdown will cancel it", run.AgenticScanUUID)
		return
	}
	assert.Contains(t, terminalRunStatuses, final,
		"swarm run must reach a clean terminal state, got %q", final)
	t.Logf("swarm REST run %s settled: status=%s", run.AgenticScanUUID, final)
}
