//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/queue"
	"github.com/vigolium/vigolium/pkg/server"
)

// TestAuditAgent_FastFailsOnMissingSourcePath is the always-on, offline
// proof of the bug fix in pkg/agent/audit_agent.go:Start.
//
// Old behavior (the bug): cmd.Dir was set to a missing source path,
// the kernel's chdir failed during fork/exec, and Go's exec error
// formatter blamed the binary instead, producing the misleading line:
//
//	fork/exec /Users/.../.local/bin/claude: no such file or directory
//
// New behavior: an os.Stat preflight on r.cfg.SourcePath fails fast
// with a clear message that names the bad path:
//
//	audit source path "<x>" is not accessible: stat <x>: no such file or directory
//
// This test calls Start() directly with a non-existent source path so
// the assertion is precise — no preflight, no provider, no network.
func TestAuditAgent_FastFailsOnMissingSourcePath(t *testing.T) {
	bogus := filepath.Join(t.TempDir(), "definitely-not-real-"+uniqueSuffix())
	require.NoFileExists(t, bogus, "test precondition: bogus path must not exist")

	cfg := agent.AuditAgentConfig{
		Mode:       "lite",
		Platform:   "claude",
		SourcePath: bogus,
		SessionDir: t.TempDir(),
	}
	runner := agent.NewAuditAgenticScanner(cfg, nil)

	err := runner.Start(context.Background())
	require.Error(t, err, "Start() must return an error when SourcePath is missing")

	msg := err.Error()
	t.Logf("Start() error: %v", err)

	assert.Contains(t, msg, "audit source path",
		"expected the new os.Stat-preflight wording")
	assert.Contains(t, msg, bogus,
		"expected the error to name the bad path %q", bogus)
	assert.NotContains(t, msg, "fork/exec",
		"the misleading 'fork/exec ...claude: no such file or directory' wording must be gone")
}

// TestAutopilot_AuditDriverFastFailsOnMissingSourcePath_E2E reproduces the
// user-reported scenario end-to-end: boot a real Fiber server on a
// real port (the in-process equivalent of `vigolium server -A`), POST
// /api/agent/run/autopilot with a missing source path, poll the status
// endpoint until the run settles, and fetch the runtime log via
// /api/agent/sessions/:id/logs.
//
// Skipped automatically when no usable olium provider is configured,
// because the autopilot pipeline calls Engine.Preflight() *before*
// the audit phase and that step makes a live provider ping. To run it,
// either:
//   - have ~/.codex/auth.json present (openai-codex-oauth, the default), or
//   - export ANTHROPIC_API_KEY / OPENAI_API_KEY and override the
//     provider via env (see selectProviderForE2E).
//
// dry_run=true is passed so the operator-agent dispatch is skipped after
// preflight + audit — keeping the test cheap (one preflight ping, no
// scanning) while still exercising the exact code path that produced
// the bug.
func TestAutopilot_AuditDriverFastFailsOnMissingSourcePath_E2E(t *testing.T) {
	settings := config.DefaultSettings()
	if reason := selectProviderForE2E(&settings.Agent.Olium); reason != "" {
		t.Skipf("skipping HTTP-roundtrip e2e: %s", reason)
	}
	settings.Agent.SessionsDir = t.TempDir()

	// 1. Capture os.Stderr — printPhaseLine writes the audit failure
	// there and it is not teed into runtime.log.
	stderrBuf, restoreStderr := captureStderr(t)
	_ = stderrBuf // kept around for godoc; restoreStderr returns the drained string

	// 2. Boot the server on a random port (closest in-process analog
	// to `vigolium server -A`).
	apiURL := startE2EServer(t, settings)

	// 3. POST /api/agent/run/autopilot with a bogus source path.
	bogusSource := filepath.Join(t.TempDir(), "definitely-not-real-"+uniqueSuffix())
	require.NoFileExists(t, bogusSource)

	body := fmt.Sprintf(
		`{"target":"http://example.test","source":%q,"dry_run":true}`,
		bogusSource,
	)
	t.Logf("POST %s/api/agent/run/autopilot\n  body: %s", apiURL, body)

	resp, err := http.Post(apiURL+"/api/agent/run/autopilot",
		"application/json", strings.NewReader(body))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	var ack server.AgenticScanResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&ack))
	require.NotEmpty(t, ack.AgenticScanUUID)
	t.Logf("autopilot run started: run_id=%s status=%s", ack.AgenticScanUUID, ack.Status)

	// 4. Poll /api/agent/status/:id until the run settles.
	var lastStatusBody []byte
	require.Eventually(t, func() bool {
		r, err := http.Get(apiURL + "/api/agent/status/" + ack.AgenticScanUUID)
		if err != nil {
			return false
		}
		defer func() { _ = r.Body.Close() }()
		lastStatusBody, _ = io.ReadAll(r.Body)
		var s struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(lastStatusBody, &s)
		return s.Status == "failed" || s.Status == "completed"
	}, 60*time.Second, 250*time.Millisecond,
		"autopilot run never settled; last status body: %s", string(lastStatusBody))
	t.Logf("status response:\n%s", string(lastStatusBody))

	// 5. Fetch /api/agent/sessions/:id/logs (runtime.log content).
	logsResp, err := http.Get(apiURL + "/api/agent/sessions/" + ack.AgenticScanUUID + "/logs")
	require.NoError(t, err)
	defer func() { _ = logsResp.Body.Close() }()
	logsBody, _ := io.ReadAll(logsResp.Body)
	t.Logf("session logs (status=%d, %d bytes):\n%s",
		logsResp.StatusCode, len(logsBody), string(logsBody))

	// 6. Drain captured stderr.
	stderr := restoreStderr()
	t.Logf("captured stderr (%d bytes):\n%s", len(stderr), stderr)

	combined := stderr + "\n" + string(lastStatusBody) + "\n" + string(logsBody)

	// 7. Assertions: the new fast-fail wording must be present, and the
	// old misleading fork/exec line must not.
	assert.Contains(t, combined, "audit source path",
		"expected the new fast-fail message that the os.Stat preflight emits")
	assert.Contains(t, combined, bogusSource,
		"expected the error to identify the bogus path %q the user passed", bogusSource)
	assert.NotContains(t, combined, "fork/exec",
		"the misleading 'fork/exec ...claude: no such file or directory' wording should be gone")
}

// selectProviderForE2E mutates oliumCfg so the autopilot Preflight ping
// has a chance of succeeding. Returns a non-empty reason string when no
// usable provider is available, in which case the caller should t.Skip.
//
// Order of preference (matches what a developer is most likely to have
// already set up):
//  1. openai-codex-oauth via ~/.codex/auth.json (vigolium's default)
//  2. anthropic-api-key via $ANTHROPIC_API_KEY
//  3. openai-api-key via $OPENAI_API_KEY
func selectProviderForE2E(oliumCfg *config.OliumConfig) string {
	codexPath := agenttypes.ExpandHome(oliumCfg.OAuthCredPath)
	if codexPath == "" {
		codexPath = agenttypes.ExpandHome("~/.codex/auth.json")
	}
	if _, err := os.Stat(codexPath); err == nil {
		oliumCfg.Provider = "openai-codex-oauth"
		oliumCfg.OAuthCredPath = codexPath
		return ""
	}
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		oliumCfg.Provider = "anthropic-api-key"
		oliumCfg.LLMAPIKey = key
		return ""
	}
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		oliumCfg.Provider = "openai-api-key"
		oliumCfg.LLMAPIKey = key
		oliumCfg.Model = "gpt-4o-mini"
		return ""
	}
	return "no olium provider credential found (~/.codex/auth.json, $ANTHROPIC_API_KEY, or $OPENAI_API_KEY)"
}

// startE2EServer boots the in-process server on a random port using the
// provided settings (caller fills in olium provider config). Returns the
// base URL the test can curl against.
func startE2EServer(t *testing.T, settings *config.Settings) string {
	t.Helper()

	db, repo := setupTestDB(t)

	taskQueue, err := queue.NewDiskQueue(queue.DiskQueueConfig{
		BaseDir:              t.TempDir(),
		MaxRecordsPerSegment: 100,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = taskQueue.Close() })

	port := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	srv := server.NewServer(server.ServerConfig{
		ServiceAddr:          addr,
		NoAuth:               true,
		Version:              "test-e2e",
		DisableFetchResponse: true,
	}, taskQueue, db, repo, settings, nil, nil)

	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	apiURL := "http://" + addr
	require.Eventually(t, func() bool {
		resp, err := http.Get(apiURL + "/health")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond, "server failed to come up at %s", apiURL)

	return apiURL
}

// captureStderr swaps os.Stderr for a pipe and starts a goroutine that
// drains the read end into an internal buffer. Calling restore() puts
// os.Stderr back, closes the pipe, waits for the drain goroutine, and
// returns the captured contents as a string. restore() is idempotent —
// subsequent calls return the already-drained string.
func captureStderr(t *testing.T) (*bytes.Buffer, func() string) {
	t.Helper()

	rPipe, wPipe, err := os.Pipe()
	require.NoError(t, err)

	origStderr := os.Stderr
	os.Stderr = wPipe

	var (
		mu      sync.Mutex
		buf     bytes.Buffer
		drained = make(chan struct{})
	)

	go func() {
		defer close(drained)
		_, _ = io.Copy(&lockedWriter{w: &buf, mu: &mu}, rPipe)
	}()

	var (
		restoreOnce sync.Once
		captured    string
	)
	restore := func() string {
		restoreOnce.Do(func() {
			os.Stderr = origStderr
			_ = wPipe.Close()
			<-drained
			mu.Lock()
			captured = buf.String()
			mu.Unlock()
		})
		return captured
	}

	t.Cleanup(func() { _ = restore() })
	return &buf, restore
}

// lockedWriter serializes writes to a bytes.Buffer so the drain goroutine
// and any concurrent reader can share it safely.
type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (lw *lockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.Write(p)
}

// uniqueSuffix returns a path-safe nanosecond timestamp so concurrent
// runs don't collide on the same bogus path.
func uniqueSuffix() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
