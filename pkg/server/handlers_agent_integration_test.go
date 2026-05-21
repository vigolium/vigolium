package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
)

// newAgentTestHandlers builds a Handlers wired to an in-memory SQLite DB and a
// temp sessions dir. The Olium provider config is left empty so any agent run
// fails fast at preflight without making a network call. The cleanup goroutine
// is signalled to stop when the test finishes.
func newAgentTestHandlers(t *testing.T) (*Handlers, *database.Repository, string) {
	t.Helper()
	repo := newTestRepo(t)

	sessionsDir := t.TempDir()
	settings := config.DefaultSettings()
	settings.Agent.SessionsDir = sessionsDir
	// Wire a deliberately invalid provider so any code path that tries to
	// dispatch through olium fails fast on resolution. This keeps the agent
	// goroutine bounded — no network, no inherited dev credentials, and no
	// dependence on whether the runner happens to have openai-codex-oauth tokens.
	settings.Agent.Olium.Provider = "invalid-test-provider"
	settings.Agent.Olium.Model = "invalid-test-model"
	settings.Agent.Olium.OAuthCredPath = ""
	settings.Agent.Olium.OAuthToken = ""
	settings.Agent.Olium.LLMAPIKey = ""

	cfg := ServerConfig{NoAgent: false}
	h := NewHandlers(nil, nil, repo, nil, cfg, settings, nil, nil)
	t.Cleanup(func() {
		// Stop the background cleanup goroutine so it doesn't keep ticking
		// against a closed DB after the test returns.
		select {
		case <-h.agentCleanupStop:
		default:
			close(h.agentCleanupStop)
		}
	})
	return h, repo, sessionsDir
}

// newAgentTestApp mounts the agent endpoints on a Fiber app so tests can
// drive them via app.Test. The full route table from registerRoutes pulls in
// auth middleware and DB-backed concerns we don't need; here we wire only the
// handlers under test.
func newAgentTestApp(h *Handlers) *fiber.App {
	app := fiber.New()
	app.Post("/api/agent/run/query", h.HandleAgentQuery)
	app.Post("/api/agent/run/autopilot", h.HandleAgentAutopilot)
	app.Post("/api/agent/run/swarm", h.HandleAgentSwarm)
	app.Post("/api/agent/run/audit", h.HandleAgentAudit)
	app.Get("/api/agent/status/list", h.HandleAgenticScanList)
	app.Get("/api/agent/status/:id", h.HandleAgenticScanStatus)
	app.Get("/api/agent/sessions/:id/logs", h.HandleAgentSessionLogs)
	app.Get("/api/agent/sessions/:id/artifacts", h.HandleAgentSessionArtifacts)
	app.Get("/api/agent/sessions/:id/artifacts/*", h.HandleAgentSessionArtifact)
	return app
}

func postJSON(app *fiber.App, path string, body any) (*http.Response, []byte, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 30 * time.Second})
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp, data, nil
}

func getRequest(app *fiber.App, path string, headers map[string]string) (*http.Response, []byte, error) {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 30 * time.Second})
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp, data, nil
}

// -----------------------------------------------------------------------------
// Request validation: autopilot
// -----------------------------------------------------------------------------

func TestHandleAgentAutopilot_BadJSON(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	req := httptest.NewRequest(http.MethodPost, "/api/agent/run/autopilot",
		strings.NewReader("{not-json"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for malformed JSON, got %d", resp.StatusCode)
	}
}

func TestHandleAgentAutopilot_MissingTarget(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	resp, body, err := postJSON(app, "/api/agent/run/autopilot", map[string]any{})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for empty body, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "target") {
		t.Errorf("expected error to mention target, got: %s", body)
	}
}

func TestHandleAgentAutopilot_InvalidAuditDriverMode(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	resp, body, err := postJSON(app, "/api/agent/run/autopilot", map[string]any{
		"target":      "https://example.com",
		"audit_mode": "ridiculous",
	})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid audit_mode, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "audit_mode") {
		t.Errorf("expected error to mention audit_mode, got: %s", body)
	}
}

func TestHandleAgentAutopilot_InvalidIntensity(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	resp, body, err := postJSON(app, "/api/agent/run/autopilot", map[string]any{
		"target":    "https://example.com",
		"intensity": "ludicrous",
	})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid intensity, got %d body=%s", resp.StatusCode, body)
	}
}

// TestHandleAgentAutopilot_LegacyAuditDriverMaps verifies the deprecated `audit`
// field still maps "off" → NoAudit=true and "deep" → AuditDriverMode="deep" on the
// request side. This guards the back-compat path called out in types.go.
func TestHandleAgentAutopilot_LegacyAuditDriverMaps(t *testing.T) {
	cases := []struct {
		audit       string
		wantNoAudit bool
		wantMode     string
	}{
		{"off", true, "lite"},   // off → disabled, mode falls back to default "lite"
		{"deep", false, "deep"}, // legacy alias → mode=deep
		{"", false, "lite"},     // empty → default lite
	}
	for _, tc := range cases {
		req := AgentAutopilotRequest{Audit: tc.audit}
		if got := req.ResolvedNoAudit(); got != tc.wantNoAudit {
			t.Errorf("audit=%q ResolvedNoAudit=%v want %v", tc.audit, got, tc.wantNoAudit)
		}
		if got := req.ResolvedAuditDriverMode(); got != tc.wantMode {
			t.Errorf("audit=%q ResolvedAuditDriverMode=%q want %q", tc.audit, got, tc.wantMode)
		}
	}
}

// -----------------------------------------------------------------------------
// Request validation: swarm
// -----------------------------------------------------------------------------

func TestHandleAgentSwarm_BadJSON(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	req := httptest.NewRequest(http.MethodPost, "/api/agent/run/swarm",
		strings.NewReader("not json at all"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandleAgentSwarm_NoInputs(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	resp, body, err := postJSON(app, "/api/agent/run/swarm", map[string]any{})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for missing inputs, got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "input") {
		t.Errorf("expected error to mention inputs, got: %s", body)
	}
}

func TestHandleAgentSwarm_InvalidIntensity(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	resp, body, err := postJSON(app, "/api/agent/run/swarm", map[string]any{
		"input":     "https://example.com",
		"intensity": "elephantine",
	})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid intensity, got %d body=%s", resp.StatusCode, body)
	}
}

// TestHandleAgentSwarm_LegacySourcePath verifies the back-compat
// "source_path" JSON alias still falls back into SourcePath when "source" is
// absent — the UnmarshalJSON shim in types.go.
func TestHandleAgentSwarm_LegacySourcePath(t *testing.T) {
	body := []byte(`{"input":"https://example.com","source_path":"/legacy/path"}`)
	var req AgentSwarmRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.SourcePath != "/legacy/path" {
		t.Errorf("legacy source_path alias not honored, got %q", req.SourcePath)
	}
}

// -----------------------------------------------------------------------------
// Async run path: handler accepts → goroutine fails at preflight → status flips
// -----------------------------------------------------------------------------

// pollAgentStatus polls /api/agent/status/:id until the status leaves
// "running" or the deadline elapses. Returns the final status row.
func pollAgentStatus(t *testing.T, app *fiber.App, agenticScanUUID string, deadline time.Duration) *AgenticScanStatusResponse {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		resp, body, err := getRequest(app, "/api/agent/status/"+agenticScanUUID, nil)
		if err != nil {
			t.Fatalf("status fetch: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		var status AgenticScanStatusResponse
		if err := json.Unmarshal(body, &status); err != nil {
			t.Fatalf("status unmarshal: %v body=%s", err, body)
		}
		if status.Status != "running" && status.Status != "" {
			return &status
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("agent run %s did not reach a terminal status within %v", agenticScanUUID, deadline)
	return nil
}

// TestHandleAgentAutopilot_AsyncRunFailsAtPreflight asserts the *fatal*
// preflight path: a preflight failure is only fatal when there is no
// target to fall back to. A target-bearing run instead degrades to a
// native blackbox scan (see runBlackboxFallback), so this test uses a
// source-only request — no target — to keep the failure terminal and the
// run offline (no native scan is launched).
func TestHandleAgentAutopilot_AsyncRunFailsAtPreflight(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	resp, body, err := postJSON(app, "/api/agent/run/autopilot", map[string]any{
		"source":    t.TempDir(), // source-only: no target → preflight failure is fatal
		"no_audit": true,        // skip audit so the failure surfaces on the operator preflight
	})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", resp.StatusCode, body)
	}
	var ack AgenticScanResponse
	if err := json.Unmarshal(body, &ack); err != nil {
		t.Fatalf("unmarshal accept body: %v", err)
	}
	if ack.AgenticScanUUID == "" {
		t.Fatalf("expected non-empty agentic_scan_uuid, got body=%s", body)
	}
	if ack.Status != "running" {
		t.Errorf("expected status=running, got %q", ack.Status)
	}

	// The background goroutine calls engine.Preflight, which fails fast
	// because the test's olium config is empty. With no target there is
	// nothing to blackbox-scan, so the run stays failed without ever
	// touching a real LLM or the native scanner.
	final := pollAgentStatus(t, app, ack.AgenticScanUUID, 10*time.Second)
	if final.Status != "failed" {
		t.Errorf("expected final status=failed, got %q (error=%q)", final.Status, final.Error)
	}
	lowerErr := strings.ToLower(final.Error)
	if !strings.Contains(lowerErr, "olium") &&
		!strings.Contains(lowerErr, "preflight") &&
		!strings.Contains(lowerErr, "provider") {
		t.Errorf("expected olium/preflight/provider error, got %q", final.Error)
	}
}

func TestHandleAgentSwarm_AsyncRunFailsAtPreflight(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	resp, body, err := postJSON(app, "/api/agent/run/swarm", map[string]any{
		"input": "https://example.test",
	})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", resp.StatusCode, body)
	}
	var ack AgenticScanResponse
	if err := json.Unmarshal(body, &ack); err != nil {
		t.Fatalf("unmarshal accept body: %v body=%s", err, body)
	}
	if ack.AgenticScanUUID == "" {
		t.Fatalf("expected non-empty agentic_scan_uuid")
	}

	final := pollAgentStatus(t, app, ack.AgenticScanUUID, 10*time.Second)
	if final.Status != "failed" {
		t.Errorf("expected final status=failed, got %q (error=%q)", final.Status, final.Error)
	}
}

// TestHandleAgentQuery_AsyncFailureIsPersisted guards the query-mode failure
// path: when the background goroutine fails (here, because the test's olium
// provider is invalid), the agentic_scans row must flip to "failed" with an
// error message — not stay stuck on "running" forever. The status endpoint
// reads in-memory first and would mask a stale DB row, so we go direct to the
// repository.
func TestHandleAgentQuery_AsyncFailureIsPersisted(t *testing.T) {
	h, repo, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	resp, body, err := postJSON(app, "/api/agent/run/query", map[string]any{
		"prompt": "trivial inline prompt that should never reach the LLM",
	})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", resp.StatusCode, body)
	}
	var ack AgenticScanResponse
	if err := json.Unmarshal(body, &ack); err != nil {
		t.Fatalf("unmarshal accept body: %v body=%s", err, body)
	}
	if ack.AgenticScanUUID == "" {
		t.Fatalf("expected non-empty agentic_scan_uuid")
	}

	// Poll the in-memory status first so we know the goroutine has finished.
	final := pollAgentStatus(t, app, ack.AgenticScanUUID, 10*time.Second)
	if final.Status != "failed" {
		t.Fatalf("expected in-memory final status=failed, got %q", final.Status)
	}

	// Now read the row directly. Before the fix, the row would still be
	// "running" because the failure path skipped DB persistence.
	run, err := repo.GetAgenticScan(context.Background(), ack.AgenticScanUUID)
	if err != nil {
		t.Fatalf("GetAgenticScan: %v", err)
	}
	if run.Status != "failed" {
		t.Errorf("expected DB status=failed, got %q", run.Status)
	}
	if run.ErrorMessage == "" {
		t.Errorf("expected non-empty error_message in DB row")
	}
	if run.CompletedAt.IsZero() {
		t.Errorf("expected non-zero completed_at in DB row")
	}
}

// TestHandleAgentAutopilot_SSERunFailureIsPersisted guards the SSE-mode
// autopilot failure path. The streaming handler used to flip in-memory status
// to "failed" but never write to the DB, leaving the row stuck on "running"
// after the SSE stream closed. Uses a source-only request (no target) so the
// preflight failure stays terminal — a target-bearing run would degrade to a
// native blackbox scan and complete instead (see runBlackboxFallback).
func TestHandleAgentAutopilot_SSERunFailureIsPersisted(t *testing.T) {
	h, repo, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	body, _ := json.Marshal(map[string]any{
		"source":    t.TempDir(), // source-only: no target → preflight failure is fatal
		"no_audit": true,
		"stream":    true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/agent/run/autopilot", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	resp, err := app.Test(req, fiber.TestConfig{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Drain the SSE stream and capture the run ID from the first
	// status-tracking write. The handler doesn't return an agentic_scan_uuid
	// in SSE mode (it goes straight to streaming), so we ask the repo for
	// the latest agentic_scans row instead.
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("drain SSE: %v", err)
	}

	rows, _, err := repo.ListAgenticScans(context.Background(), "", "autopilot", 10, 0)
	if err != nil {
		t.Fatalf("ListAgenticScans: %v", err)
	}
	if len(rows) == 0 {
		t.Fatalf("no agentic_scans rows found after SSE run")
	}
	run := rows[0]
	if run.Status != "failed" {
		t.Errorf("expected DB status=failed, got %q (error=%q)", run.Status, run.ErrorMessage)
	}
	if run.ErrorMessage == "" {
		t.Errorf("expected non-empty error_message in DB row")
	}
	if run.CompletedAt.IsZero() {
		t.Errorf("expected non-zero completed_at in DB row")
	}
}

// -----------------------------------------------------------------------------
// Concurrency cap: exhaust heavy slots → 429 Too Many Requests
// -----------------------------------------------------------------------------

// TestAutopilotConcurrencyCap_429 saturates the heavy semaphore and verifies
// that the next autopilot request gets bounced with 429 instead of queuing
// indefinitely. Recent commits (9035514f) introduced the semaphore — this
// test pins down its 429 path so future engine changes can't regress it.
func TestAutopilotConcurrencyCap_429(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	// Replace the heavy semaphore with a single-slot one and pre-fill it so
	// the next acquire times out fast (queue timeout ≤ 50ms).
	h.agentHeavySem = make(chan struct{}, 1)
	h.agentHeavySem <- struct{}{}
	h.config.AgentQueueTimeout = 50 * time.Millisecond
	app := newAgentTestApp(h)

	resp, body, err := postJSON(app, "/api/agent/run/autopilot", map[string]any{
		"target": "https://example.test",
	})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 when slots saturated, got %d body=%s", resp.StatusCode, body)
	}
}

// -----------------------------------------------------------------------------
// Artifact endpoints
// -----------------------------------------------------------------------------

// seedAgentSession inserts an agentic_scans row pointing at a session_dir
// that the caller has already populated with test fixtures.
func seedAgentSession(t *testing.T, repo *database.Repository, sessionDir string) string {
	t.Helper()
	agenticScanUUID := uuid.NewString()
	if err := repo.CreateAgenticScan(context.Background(), &database.AgenticScan{
		UUID:       agenticScanUUID,
		Mode:       "autopilot",
		AgentName:  "olium",
		Status:     "completed",
		SessionDir: sessionDir,
		StartedAt:  time.Now(),
	}); err != nil {
		t.Fatalf("seed agentic_scans row: %v", err)
	}
	return agenticScanUUID
}

func TestHandleAgentSessionArtifacts_ListsFiles(t *testing.T) {
	h, repo, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	sessionDir := t.TempDir()
	files := map[string]string{
		"runtime.log":             "phase one\nphase two\n",
		"output.md":               "# results",
		"plan.json":               `{"phase":"plan"}`,
		"audit-stream.jsonl":      `{"event":"chunk"}`,
		"extensions/check.js":     "module.exports = {};",
		"vigolium-results/state.json": `{"audit":1}`,
	}
	for rel, body := range files {
		full := filepath.Join(sessionDir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}

	agenticScanUUID := seedAgentSession(t, repo, sessionDir)
	resp, body, err := getRequest(app, "/api/agent/sessions/"+agenticScanUUID+"/artifacts", nil)
	if err != nil {
		t.Fatalf("getRequest: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.StatusCode, body)
	}
	var listing AgentArtifactListResponse
	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, body)
	}
	if listing.AgenticScanUUID != agenticScanUUID {
		t.Errorf("expected agentic_scan_uuid=%q, got %q", agenticScanUUID, listing.AgenticScanUUID)
	}
	if listing.SessionDir != sessionDir {
		t.Errorf("expected session_dir=%q, got %q", sessionDir, listing.SessionDir)
	}
	if listing.Truncated {
		t.Errorf("expected non-truncated listing, got truncated=true")
	}
	if got, want := len(listing.Artifacts), len(files); got != want {
		t.Errorf("expected %d artifacts, got %d (%+v)", want, got, listing.Artifacts)
	}

	// Spot-check that nested files are reported with forward-slash paths and
	// that the kind classifier picked up the obvious extensions.
	wantKind := map[string]string{
		"runtime.log":             "log",
		"plan.json":               "json",
		"output.md":               "markdown",
		"audit-stream.jsonl":      "jsonl",
		"vigolium-results/state.json": "json",
		"extensions/check.js":     "text",
	}
	gotKind := map[string]string{}
	for _, a := range listing.Artifacts {
		gotKind[a.Name] = a.Kind
	}
	for name, kind := range wantKind {
		if got := gotKind[name]; got != kind {
			t.Errorf("artifact %q kind=%q want %q", name, got, kind)
		}
	}
}

func TestHandleAgentSessionArtifacts_RunNotFound(t *testing.T) {
	h, _, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	resp, body, err := getRequest(app, "/api/agent/sessions/00000000-no-such-run/artifacts", nil)
	if err != nil {
		t.Fatalf("getRequest: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for unknown run, got %d body=%s", resp.StatusCode, body)
	}
}

func TestHandleAgentSessionArtifact_ReadsFile(t *testing.T) {
	h, repo, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	sessionDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sessionDir, "plan.json"), []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatalf("write plan.json: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(sessionDir, "vigolium-results"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, "vigolium-results", "state.json"), []byte(`{"audit":2}`), 0o644); err != nil {
		t.Fatalf("write state.json: %v", err)
	}

	agenticScanUUID := seedAgentSession(t, repo, sessionDir)

	t.Run("top-level json", func(t *testing.T) {
		resp, body, err := getRequest(app, "/api/agent/sessions/"+agenticScanUUID+"/artifacts/plan.json", nil)
		if err != nil {
			t.Fatalf("getRequest: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d body=%s", resp.StatusCode, body)
		}
		if string(body) != `{"ok":true}` {
			t.Errorf("body mismatch: %q", body)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("expected application/json content-type, got %q", ct)
		}
	})

	t.Run("nested path via wildcard", func(t *testing.T) {
		resp, body, err := getRequest(app, "/api/agent/sessions/"+agenticScanUUID+"/artifacts/vigolium-results/state.json", nil)
		if err != nil {
			t.Fatalf("getRequest: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 for nested artifact, got %d body=%s", resp.StatusCode, body)
		}
		if string(body) != `{"audit":2}` {
			t.Errorf("body mismatch: %q", body)
		}
	})
}

func TestHandleAgentSessionArtifact_PathTraversalRejected(t *testing.T) {
	h, repo, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	sessionDir := t.TempDir()
	// File outside the session_dir that the request must NOT be able to reach.
	parentDir := filepath.Dir(sessionDir)
	secretPath := filepath.Join(parentDir, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("DO NOT LEAK"), 0o644); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(secretPath) })

	agenticScanUUID := seedAgentSession(t, repo, sessionDir)

	traversals := []string{
		"../secret.txt",
		"sub/../../secret.txt",
		"%2e%2e/secret.txt", // URL-encoded ../
		"/etc/passwd",       // absolute
	}
	for _, name := range traversals {
		path := "/api/agent/sessions/" + agenticScanUUID + "/artifacts/" + name
		resp, body, err := getRequest(app, path, nil)
		if err != nil {
			t.Fatalf("getRequest %q: %v", name, err)
		}
		if resp.StatusCode == http.StatusOK {
			t.Errorf("traversal %q should be rejected, got 200 body=%s", name, body)
		}
		if bytes.Contains(body, []byte("DO NOT LEAK")) {
			t.Errorf("traversal %q leaked file contents: %s", name, body)
		}
	}
}

func TestHandleAgentSessionArtifact_NotFound(t *testing.T) {
	h, repo, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	sessionDir := t.TempDir()
	agenticScanUUID := seedAgentSession(t, repo, sessionDir)

	resp, _, err := getRequest(app, "/api/agent/sessions/"+agenticScanUUID+"/artifacts/missing.json", nil)
	if err != nil {
		t.Fatalf("getRequest: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for missing artifact, got %d", resp.StatusCode)
	}
}

func TestHandleAgentSessionArtifact_TruncatesLargeFile(t *testing.T) {
	h, repo, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	sessionDir := t.TempDir()
	big := bytes.Repeat([]byte("A"), 4096)
	if err := os.WriteFile(filepath.Join(sessionDir, "big.txt"), big, 0o644); err != nil {
		t.Fatalf("write big.txt: %v", err)
	}
	agenticScanUUID := seedAgentSession(t, repo, sessionDir)

	resp, body, err := getRequest(app,
		fmt.Sprintf("/api/agent/sessions/%s/artifacts/big.txt?max_bytes=%d", agenticScanUUID, 1024), nil)
	if err != nil {
		t.Fatalf("getRequest: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.StatusCode, body)
	}
	if len(body) != 1024 {
		t.Errorf("expected truncated body of 1024 bytes, got %d", len(body))
	}
	if resp.Header.Get("X-Artifact-Truncated") != "1" {
		t.Errorf("expected X-Artifact-Truncated=1 header on truncated read")
	}
	if got := resp.Header.Get("X-Artifact-Total-Size"); got != "4096" {
		t.Errorf("expected X-Artifact-Total-Size=4096, got %q", got)
	}
}

// -----------------------------------------------------------------------------
// Pure-unit coverage for safeArtifactPath / artifactKind
// -----------------------------------------------------------------------------

func TestSafeArtifactPath(t *testing.T) {
	dir := t.TempDir()
	// safeArtifactPath returns paths rooted at the symlink-resolved session
	// directory, so derive expected values the same way for portability
	// (macOS tempdirs resolve /var → /private/var).
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}

	allowed := []struct {
		name string
		want string
	}{
		{"plan.json", filepath.Join(resolvedDir, "plan.json")},
		{"a/b/c.txt", filepath.Join(resolvedDir, "a", "b", "c.txt")},
		{"./plan.json", filepath.Join(resolvedDir, "plan.json")},
	}
	for _, tc := range allowed {
		got, err := safeArtifactPath(dir, tc.name)
		if err != nil {
			t.Errorf("safeArtifactPath(%q) unexpected err: %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("safeArtifactPath(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}

	rejected := []string{
		"../escape.txt",
		"a/../../escape.txt",
		"/etc/passwd",
		"",
		".",
	}
	for _, name := range rejected {
		if _, err := safeArtifactPath(dir, name); err == nil {
			t.Errorf("safeArtifactPath(%q) should have been rejected", name)
		}
	}
}

func TestArtifactKind(t *testing.T) {
	cases := map[string]string{
		"runtime.log":        "log",
		"plan.json":          "json",
		"audit-stream.jsonl": "jsonl",
		"events.ndjson":      "jsonl",
		"output.md":          "markdown",
		"README.markdown":    "markdown",
		"auth-config.yaml":   "yaml",
		"auth-config.yml":    "yaml",
		"prompt.txt":         "text",
		"check.js":           "text",
		"unknown":            "text",
	}
	for name, want := range cases {
		if got := artifactKind(name); got != want {
			t.Errorf("artifactKind(%q) = %q, want %q", name, got, want)
		}
	}
}

// -----------------------------------------------------------------------------
// SSE event format — pin the JSON shape that streaming clients rely on.
// -----------------------------------------------------------------------------

// captureSSE marshals each event with writeSSE and returns the raw text so we
// can assert the wire format directly.
func captureSSE(t *testing.T, events ...sseEvent) string {
	t.Helper()
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	for _, evt := range events {
		if err := writeSSE(w, evt); err != nil {
			t.Fatalf("writeSSE: %v", err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	return buf.String()
}

func TestSSEEventFormat_AllVariants(t *testing.T) {
	progress := &agent.ProgressEvent{Phase: "scan", Message: "starting"}
	out := captureSSE(t,
		sseEvent{Type: "chunk", Text: "hello"},
		sseEvent{Type: "phase", Phase: "discover"},
		sseEvent{Type: "progress", Progress: progress},
		sseEvent{Type: "error", Error: "boom"},
		sseEvent{Type: "done"},
	)

	// Each event must be on its own `data: ...\n\n` line.
	frames := strings.Split(strings.TrimSuffix(out, "\n\n"), "\n\n")
	if got, want := len(frames), 5; got != want {
		t.Fatalf("expected %d SSE frames, got %d (raw=%q)", want, got, out)
	}

	for i, frame := range frames {
		if !strings.HasPrefix(frame, "data: ") {
			t.Errorf("frame %d missing 'data: ' prefix: %q", i, frame)
			continue
		}
		payload := strings.TrimPrefix(frame, "data: ")
		var evt sseEvent
		if err := json.Unmarshal([]byte(payload), &evt); err != nil {
			t.Errorf("frame %d JSON decode failed: %v (payload=%q)", i, err, payload)
		}
	}

	// Spot-check the JSON shape of each variant so refactors that drop a
	// field (e.g., renaming "progress" → "event") would be caught.
	wantSubstrings := []string{
		`"type":"chunk"`, `"text":"hello"`,
		`"type":"phase"`, `"phase":"discover"`,
		`"type":"progress"`, `"progress":{`,
		`"type":"error"`, `"error":"boom"`,
		`"type":"done"`,
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(out, s) {
			t.Errorf("expected SSE output to contain %q, got: %s", s, out)
		}
	}
}

// -----------------------------------------------------------------------------
// HandleAgentSessionLogs — full-text and SSE variants exercised end-to-end.
// -----------------------------------------------------------------------------

func TestHandleAgentSessionLogs_PlainText(t *testing.T) {
	h, repo, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	sessionDir := t.TempDir()
	logBody := "line one\nline two\n"
	if err := os.WriteFile(filepath.Join(sessionDir, config.RuntimeLogFilename), []byte(logBody), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	agenticScanUUID := seedAgentSession(t, repo, sessionDir)

	resp, body, err := getRequest(app, "/api/agent/sessions/"+agenticScanUUID+"/logs", nil)
	if err != nil {
		t.Fatalf("getRequest: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.StatusCode, body)
	}
	if string(body) != logBody {
		t.Errorf("expected log body %q, got %q", logBody, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("expected text/plain, got %q", ct)
	}
}

func TestHandleAgentSessionLogs_SSE(t *testing.T) {
	h, repo, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)

	sessionDir := t.TempDir()
	logBody := "alpha\nbeta\n"
	if err := os.WriteFile(filepath.Join(sessionDir, config.RuntimeLogFilename), []byte(logBody), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	agenticScanUUID := seedAgentSession(t, repo, sessionDir)

	resp, body, err := getRequest(app, "/api/agent/sessions/"+agenticScanUUID+"/logs", map[string]string{
		"Accept": "text/event-stream",
	})
	if err != nil {
		t.Fatalf("getRequest: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("expected text/event-stream, got %q", ct)
	}
	out := string(body)
	if !strings.Contains(out, `"type":"chunk"`) {
		t.Errorf("expected chunk event, got: %q", out)
	}
	if !strings.Contains(out, `"type":"done"`) {
		t.Errorf("expected done event, got: %q", out)
	}
	if !strings.Contains(out, "alpha") || !strings.Contains(out, "beta") {
		t.Errorf("expected log payload in SSE chunks, got: %q", out)
	}
}
