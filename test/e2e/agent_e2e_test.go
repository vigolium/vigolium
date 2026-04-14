//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/queue"
	"github.com/vigolium/vigolium/pkg/server"
)

// agentTestEnv is like apiTestEnv but with agent settings configured.
type agentTestEnv struct {
	server   *server.Server
	url      string
	db       *database.DB
	repo     *database.Repository
	queue    queue.Queue
	settings *config.Settings
}

// newAgentTestEnv starts an API server with a fake agent configured and default concurrency limits.
func newAgentTestEnv(t *testing.T) *agentTestEnv {
	t.Helper()
	env := newAgentTestEnvWithConfig(t, server.ServerConfig{})
	// Add alt-agent used by some tests
	env.settings.Agent.Backends["alt-agent"] = config.AgentDef{
		Command:     "cat",
		Description: "Alternative fake agent for testing",
	}
	return env
}

func newAgentTestEnvWithBackendCommand(t *testing.T, command string) *agentTestEnv {
	t.Helper()
	db, repo := setupTestDB(t)

	tmpDir := t.TempDir()
	taskQueue, err := queue.NewDiskQueue(queue.DiskQueueConfig{
		BaseDir:              tmpDir,
		MaxRecordsPerSegment: 100,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = taskQueue.Close() })

	port := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	settings := &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: "fake-agent",
			Backends: map[string]config.AgentDef{
				"fake-agent": {
					Command:     command,
					Description: "Fake agent for testing",
				},
			},
		},
	}

	cfg := server.ServerConfig{
		ServiceAddr:          addr,
		NoAuth:               true,
		CORSAllowedOrigins:   "reflect-origin",
		Version:              "test-agent-v0.0.1",
		DisableFetchResponse: true,
		WriteTimeout:         120 * time.Second,
	}

	srv := server.NewServer(cfg, taskQueue, db, repo, settings, nil)
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	apiURL := "http://" + addr
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(apiURL + "/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	return &agentTestEnv{
		server:   srv,
		url:      apiURL,
		db:       db,
		repo:     repo,
		queue:    taskQueue,
		settings: settings,
	}
}

func fakeIntentAgentScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-intent-agent.sh")
	content := `#!/bin/sh
cat > /dev/null
cat <<'JSON'
{"apps":[{"target":"http://localhost:3005","source_path":"~/src/VAmPI","focus":"IDOR","instruction":"prioritize authenticated object access checks","discover":true,"code_audit":false,"archon":"scan","browser":true,"credentials":"admin/admin123, compare user/user123","credential_sets":[{"name":"admin","role":"primary","username":"admin","password":"admin123"},{"name":"user","role":"compare","username":"user","password":"user123"}],"auth_required":true,"requires_browser":true,"browser_start_url":"http://localhost:3005/login","focus_routes":["/books","/users"],"intensity":"deep"}]}
JSON
`
	require.NoError(t, os.WriteFile(script, []byte(content), 0o755))
	return script
}

// newAgentTestEnvWithConfig starts an API server with custom ServerConfig overrides.
func newAgentTestEnvWithConfig(t *testing.T, cfgOverride server.ServerConfig) *agentTestEnv {
	t.Helper()

	db, repo := setupTestDB(t)

	tmpDir := t.TempDir()
	taskQueue, err := queue.NewDiskQueue(queue.DiskQueueConfig{
		BaseDir:              tmpDir,
		MaxRecordsPerSegment: 100,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = taskQueue.Close() })

	port := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	settings := &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: "fake-agent",
			Backends: map[string]config.AgentDef{
				"fake-agent": {
					Command:     "cat",
					Description: "Fake agent for testing (echoes stdin)",
				},
			},
		},
	}

	cfg := server.ServerConfig{
		ServiceAddr:          addr,
		NoAuth:               true,
		CORSAllowedOrigins:   "reflect-origin",
		Version:              "test-agent-v0.0.1",
		DisableFetchResponse: true,
		WriteTimeout:         120 * time.Second,
		AgentHeavyMax:        cfgOverride.AgentHeavyMax,
		AgentLightMax:        cfgOverride.AgentLightMax,
		AgentQueueTimeout:    cfgOverride.AgentQueueTimeout,
	}

	srv := server.NewServer(cfg, taskQueue, db, repo, settings, nil)

	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	apiURL := "http://" + addr
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(apiURL + "/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	return &agentTestEnv{
		server:   srv,
		url:      apiURL,
		db:       db,
		repo:     repo,
		queue:    taskQueue,
		settings: settings,
	}
}

func (env *agentTestEnv) post(t *testing.T, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, env.url+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func (env *agentTestEnv) get(t *testing.T, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, env.url+path, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// ============================================================
// POST /api/agent/run/query — validation
// ============================================================

func TestAgentAPI_Run_MissingPrompt(t *testing.T) {
	env := newAgentTestEnv(t)

	resp := env.post(t, "/api/agent/run/query", `{"agent": "fake-agent"}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "prompt")
}

func TestAgentAPI_SwarmPromptDryRun_ResolvesRichIntent(t *testing.T) {
	env := newAgentTestEnvWithBackendCommand(t, fakeIntentAgentScript(t))

	resp := env.post(t, "/api/agent/run/swarm", `{
		"prompt": "scan VAmPI source at ~/src/VAmPI on localhost:3005 with admin/admin123, compare user/user123, focus on IDOR, use browser for login, run deep",
		"dry_run": true
	}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]json.RawMessage
	readJSON(t, resp, &body)

	var intent struct {
		Apps []struct {
			Target          string   `json:"target"`
			SourcePath      string   `json:"source_path"`
			Intensity       string   `json:"intensity"`
			Credentials     string   `json:"credentials"`
			AuthRequired    bool     `json:"auth_required"`
			RequiresBrowser bool     `json:"requires_browser"`
			BrowserStartURL string   `json:"browser_start_url"`
			FocusRoutes     []string `json:"focus_routes"`
			CredentialSets  []struct {
				Role string `json:"role"`
			} `json:"credential_sets"`
		} `json:"apps"`
	}
	require.NoError(t, json.Unmarshal(body["intent"], &intent))
	require.Len(t, intent.Apps, 1)

	app := intent.Apps[0]
	assert.Equal(t, "http://localhost:3005", app.Target)
	assert.Equal(t, "/Users/j3ssie/src/VAmPI", app.SourcePath)
	assert.Equal(t, "deep", app.Intensity)
	assert.Equal(t, "admin/admin123, compare user/user123", app.Credentials)
	assert.True(t, app.AuthRequired)
	assert.True(t, app.RequiresBrowser)
	assert.Equal(t, "http://localhost:3005/login", app.BrowserStartURL)
	assert.Equal(t, []string{"/books", "/users"}, app.FocusRoutes)
	require.Len(t, app.CredentialSets, 2)
	assert.Equal(t, "primary", app.CredentialSets[0].Role)
	assert.Equal(t, "compare", app.CredentialSets[1].Role)
}

func TestAgentAPI_Run_InvalidJSON(t *testing.T) {
	env := newAgentTestEnv(t)

	resp := env.post(t, "/api/agent/run/query", `not valid json`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestAgentAPI_Run_InlinePrompt(t *testing.T) {
	env := newAgentTestEnv(t)

	resp := env.post(t, "/api/agent/run/query", `{
		"prompt": "Hello from test",
		"agent": "fake-agent"
	}`)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	var body server.AgentRunResponse
	readJSON(t, resp, &body)
	assert.NotEmpty(t, body.RunID)
	assert.Equal(t, "running", body.Status)
	// RunID is now a bare UUID (no agt- prefix) so it matches the session dir
	// name 1:1 — `~/.vigolium/agent-sessions/<run_id>/`.
	_, parseErr := uuid.Parse(body.RunID)
	assert.NoError(t, parseErr, "run_id should be a valid UUID")

	// Poll for completion
	var status server.AgentRunStatusResponse
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		r := env.get(t, "/api/agent/status/"+body.RunID)
		readJSON(t, r, &status)
		if status.Status != "running" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	assert.Equal(t, "completed", status.Status)
	assert.NotNil(t, status.Result)
	assert.Contains(t, status.Result.RawOutput, "Hello from test")
}

func TestAgentAPI_Run_DefaultAgent(t *testing.T) {
	env := newAgentTestEnv(t)

	// No "agent" field — should use default
	resp := env.post(t, "/api/agent/run/query", `{
		"prompt": "test default agent"
	}`)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	var body server.AgentRunResponse
	readJSON(t, resp, &body)

	// Poll for completion
	var status server.AgentRunStatusResponse
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		r := env.get(t, "/api/agent/status/"+body.RunID)
		readJSON(t, r, &status)
		if status.Status != "running" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	assert.Equal(t, "completed", status.Status)
	assert.Equal(t, "fake-agent", status.AgentName)
}

// ============================================================
// GET /api/agent/status/list
// ============================================================

func TestAgentAPI_StatusList_Empty(t *testing.T) {
	env := newAgentTestEnv(t)

	resp := env.get(t, "/api/agent/status/list")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body []*server.AgentRunStatusResponse
	readJSON(t, resp, &body)
	assert.Empty(t, body)
}

func TestAgentAPI_StatusList_AfterRun(t *testing.T) {
	env := newAgentTestEnv(t)

	// Start an agent run
	resp := env.post(t, "/api/agent/run/query", `{"prompt": "list test"}`)
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	var runResp server.AgentRunResponse
	readJSON(t, resp, &runResp)

	// Wait for completion
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		r := env.get(t, "/api/agent/status/"+runResp.RunID)
		var s server.AgentRunStatusResponse
		readJSON(t, r, &s)
		if s.Status != "running" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// List should contain the run
	resp = env.get(t, "/api/agent/status/list")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var list []*server.AgentRunStatusResponse
	readJSON(t, resp, &list)
	assert.NotEmpty(t, list)

	found := false
	for _, s := range list {
		if s.RunID == runResp.RunID {
			found = true
			assert.Equal(t, "completed", s.Status)
		}
	}
	assert.True(t, found, "expected to find run %s in status list", runResp.RunID)
}

// ============================================================
// GET /api/agent/status/:id
// ============================================================

func TestAgentAPI_Status_NotFound(t *testing.T) {
	env := newAgentTestEnv(t)

	resp := env.get(t, "/api/agent/status/agt-nonexistent-id")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "not found")
}

// ============================================================
// POST /api/agent/run/query — concurrency semaphore
// ============================================================

func TestAgentAPI_Run_ConcurrencyLimit(t *testing.T) {
	// Use a single light slot so we can saturate it with one request
	env := newAgentTestEnvWithConfig(t, server.ServerConfig{
		AgentLightMax:     1,
		AgentQueueTimeout: 500 * time.Millisecond,
	})

	// Start an agent run with a slow command
	env.settings.Agent.Backends["slow-agent"] = config.AgentDef{
		Command: "sh",
		Args:    []string{"-c", "sleep 3 && echo done"},
	}

	resp1 := env.post(t, "/api/agent/run/query", `{
		"prompt": "slow run",
		"agent": "slow-agent"
	}`)
	require.Equal(t, http.StatusAccepted, resp1.StatusCode)
	resp1.Body.Close()

	// Give it a moment to start
	time.Sleep(500 * time.Millisecond)

	// Second request should get 429 Too Many Requests (slot full, queue timeout)
	resp2 := env.post(t, "/api/agent/run/query", `{
		"prompt": "should be rejected"
	}`)
	assert.Equal(t, http.StatusTooManyRequests, resp2.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp2, &body)
	assert.Contains(t, body.Error, "busy")

	// Wait for first run to finish to not interfere with other tests
	time.Sleep(4 * time.Second)
}

// ============================================================
// POST /api/agent/chat/completions — validation
// ============================================================

func TestAgentAPI_ChatCompletions_EmptyMessages(t *testing.T) {
	env := newAgentTestEnv(t)

	resp := env.post(t, "/api/agent/chat/completions", `{
		"model": "gpt-4o-mini",
		"messages": []
	}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "messages")
}

func TestAgentAPI_ChatCompletions_InvalidJSON(t *testing.T) {
	env := newAgentTestEnv(t)

	resp := env.post(t, "/api/agent/chat/completions", `not valid json`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestAgentAPI_ChatCompletions_MissingMessages(t *testing.T) {
	env := newAgentTestEnv(t)

	resp := env.post(t, "/api/agent/chat/completions", `{
		"model": "gpt-4o-mini"
	}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "messages")
}

// ============================================================
// POST /api/agent/chat/completions — successful completion
// ============================================================

func TestAgentAPI_ChatCompletions_Success(t *testing.T) {
	env := newAgentTestEnv(t)

	resp := env.post(t, "/api/agent/chat/completions", `{
		"model": "gpt-4o-mini",
		"messages": [
			{"role": "user", "content": "Hello, how are you?"}
		]
	}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ChatCompletionResponse
	readJSON(t, resp, &body)

	// Verify OpenAI-compatible response structure
	assert.Contains(t, body.ID, "chatcmpl-")
	assert.Equal(t, "chat.completion", body.Object)
	assert.Equal(t, "gpt-4o-mini", body.Model)
	assert.NotZero(t, body.Created)
	require.Len(t, body.Choices, 1)
	assert.Equal(t, 0, body.Choices[0].Index)
	assert.Equal(t, "assistant", body.Choices[0].Message.Role)
	assert.Equal(t, "stop", body.Choices[0].FinishReason)

	// The fake agent (cat) echoes the prompt, so output should contain the message
	assert.Contains(t, body.Choices[0].Message.Content, "Hello, how are you?")
}

func TestAgentAPI_ChatCompletions_MultipleMessages(t *testing.T) {
	env := newAgentTestEnv(t)

	resp := env.post(t, "/api/agent/chat/completions", `{
		"model": "fake-agent",
		"messages": [
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": "What is 2+2?"},
			{"role": "assistant", "content": "4"},
			{"role": "user", "content": "And 3+3?"}
		]
	}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ChatCompletionResponse
	readJSON(t, resp, &body)

	// All messages should be concatenated in the output
	content := body.Choices[0].Message.Content
	assert.Contains(t, content, "You are a helpful assistant.")
	assert.Contains(t, content, "What is 2+2?")
	assert.Contains(t, content, "And 3+3?")
}

// ============================================================
// POST /api/agent/chat/completions — model mapping
// ============================================================

func TestAgentAPI_ChatCompletions_ModelMapsToKnownAgent(t *testing.T) {
	env := newAgentTestEnv(t)

	// "alt-agent" is a configured agent name
	resp := env.post(t, "/api/agent/chat/completions", `{
		"model": "alt-agent",
		"messages": [
			{"role": "user", "content": "test known agent mapping"}
		]
	}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ChatCompletionResponse
	readJSON(t, resp, &body)

	// Model field should reflect what was requested
	assert.Equal(t, "alt-agent", body.Model)
	assert.Contains(t, body.Choices[0].Message.Content, "test known agent mapping")
}

func TestAgentAPI_ChatCompletions_UnknownModelFallsBackToDefault(t *testing.T) {
	env := newAgentTestEnv(t)

	// "gpt-4o-mini" is not a configured agent, should use default "fake-agent"
	resp := env.post(t, "/api/agent/chat/completions", `{
		"model": "gpt-4o-mini",
		"messages": [
			{"role": "user", "content": "test fallback"}
		]
	}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ChatCompletionResponse
	readJSON(t, resp, &body)

	// Should still succeed — model in response matches request
	assert.Equal(t, "gpt-4o-mini", body.Model)
	assert.Contains(t, body.Choices[0].Message.Content, "test fallback")
}

// ============================================================
// POST /api/agent/chat/completions — concurrency semaphore
// ============================================================

func TestAgentAPI_ChatCompletions_ConcurrencyLimit(t *testing.T) {
	env := newAgentTestEnvWithConfig(t, server.ServerConfig{
		AgentLightMax:     1,
		AgentQueueTimeout: 500 * time.Millisecond,
	})

	// Start a slow agent run via the /run endpoint
	env.settings.Agent.Backends["slow-agent"] = config.AgentDef{
		Command: "sh",
		Args:    []string{"-c", "sleep 3 && echo done"},
	}

	resp1 := env.post(t, "/api/agent/run/query", `{
		"prompt": "hold the slot",
		"agent": "slow-agent"
	}`)
	require.Equal(t, http.StatusAccepted, resp1.StatusCode)
	resp1.Body.Close()

	// Give it a moment to start
	time.Sleep(500 * time.Millisecond)

	// Chat completions shares light semaphore — should get 429
	resp2 := env.post(t, "/api/agent/chat/completions", `{
		"model": "fake-agent",
		"messages": [{"role": "user", "content": "should fail"}]
	}`)
	assert.Equal(t, http.StatusTooManyRequests, resp2.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp2, &body)
	assert.Contains(t, body.Error, "busy")

	// Wait for first run to finish
	time.Sleep(4 * time.Second)
}

// ============================================================
// POST /api/agent/chat/completions — response format
// ============================================================

func TestAgentAPI_ChatCompletions_ResponseFormat(t *testing.T) {
	env := newAgentTestEnv(t)

	resp := env.post(t, "/api/agent/chat/completions", `{
		"model": "fake-agent",
		"messages": [{"role": "user", "content": "format test"}]
	}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Decode as raw JSON to verify exact structure
	defer resp.Body.Close()
	var raw map[string]json.RawMessage
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&raw))

	// Required top-level fields
	assert.Contains(t, raw, "id")
	assert.Contains(t, raw, "object")
	assert.Contains(t, raw, "created")
	assert.Contains(t, raw, "model")
	assert.Contains(t, raw, "choices")

	// Verify object value
	var object string
	require.NoError(t, json.Unmarshal(raw["object"], &object))
	assert.Equal(t, "chat.completion", object)

	// Verify choices structure
	var choices []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw["choices"], &choices))
	require.Len(t, choices, 1)
	assert.Contains(t, choices[0], "index")
	assert.Contains(t, choices[0], "message")
	assert.Contains(t, choices[0], "finish_reason")

	// Verify message structure
	var msg map[string]string
	require.NoError(t, json.Unmarshal(choices[0]["message"], &msg))
	assert.Equal(t, "assistant", msg["role"])
	assert.NotEmpty(t, msg["content"])
}

// ============================================================
// POST /api/agent/chat/completions — shared semaphore with /agent/run/query
// ============================================================

func TestAgentAPI_ChatCompletions_BlocksAgentRun(t *testing.T) {
	env := newAgentTestEnvWithConfig(t, server.ServerConfig{
		AgentLightMax:     1,
		AgentQueueTimeout: 500 * time.Millisecond,
	})

	// Use a slow agent via chat completions by configuring a slow command
	env.settings.Agent.Backends["slow-chat"] = config.AgentDef{
		Command: "sh",
		Args:    []string{"-c", "sleep 3 && echo done"},
	}

	// Start chat completion with a slow agent in a goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp := env.post(t, "/api/agent/chat/completions", `{
			"model": "slow-chat",
			"messages": [{"role": "user", "content": "slow"}]
		}`)
		resp.Body.Close()
	}()

	// Give it a moment to acquire the slot
	time.Sleep(300 * time.Millisecond)

	// Agent run should be rejected (light semaphore full)
	resp := env.post(t, "/api/agent/run/query", `{
		"prompt": "should be blocked"
	}`)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	resp.Body.Close()

	// Wait for chat completion to finish
	<-done
}

// ============================================================
// Agent concurrency — multiple concurrent light runs
// ============================================================

func TestAgentAPI_ConcurrentLightRuns(t *testing.T) {
	// Allow 3 concurrent light runs
	env := newAgentTestEnvWithConfig(t, server.ServerConfig{
		AgentLightMax:     3,
		AgentQueueTimeout: 500 * time.Millisecond,
	})

	env.settings.Agent.Backends["slow-agent"] = config.AgentDef{
		Command: "sh",
		Args:    []string{"-c", "sleep 3 && echo done"},
	}

	// Fire 3 concurrent runs — all should be accepted
	var responses [3]*http.Response
	for i := range 3 {
		resp := env.post(t, "/api/agent/run/query", fmt.Sprintf(`{
			"prompt": "run %d",
			"agent": "slow-agent"
		}`, i))
		responses[i] = resp
	}

	for i, resp := range responses {
		assert.Equal(t, http.StatusAccepted, resp.StatusCode, "run %d should be accepted", i)
		resp.Body.Close()
	}

	// Give agents a moment to start
	time.Sleep(300 * time.Millisecond)

	// 4th request should get 429 (all 3 slots occupied)
	resp4 := env.post(t, "/api/agent/run/query", `{
		"prompt": "should be rejected",
		"agent": "slow-agent"
	}`)
	assert.Equal(t, http.StatusTooManyRequests, resp4.StatusCode)
	resp4.Body.Close()

	// Wait for all runs to complete
	time.Sleep(4 * time.Second)
}

// ============================================================
// Agent concurrency — heavy and light are independent
// ============================================================

func TestAgentAPI_HeavyAndLightIndependent(t *testing.T) {
	// 1 heavy slot, 1 light slot — they don't block each other
	env := newAgentTestEnvWithConfig(t, server.ServerConfig{
		AgentHeavyMax:     1,
		AgentLightMax:     1,
		AgentQueueTimeout: 500 * time.Millisecond,
	})

	env.settings.Agent.Backends["slow-agent"] = config.AgentDef{
		Command: "sh",
		Args:    []string{"-c", "sleep 3 && echo done"},
	}

	// Start a light agent run (occupies the 1 light slot)
	resp1 := env.post(t, "/api/agent/run/query", `{
		"prompt": "light run",
		"agent": "slow-agent"
	}`)
	require.Equal(t, http.StatusAccepted, resp1.StatusCode)
	resp1.Body.Close()

	time.Sleep(200 * time.Millisecond)

	// Heavy run should still succeed (different semaphore)
	resp2 := env.post(t, "/api/agent/run/autopilot", `{
		"source": "/tmp/nonexistent-test-path",
		"agent": "slow-agent",
		"dry_run": true
	}`)
	// dry_run autopilot returns 200 (renders prompt) or 400 (validation),
	// but NOT 429 — proving heavy semaphore is independent
	assert.NotEqual(t, http.StatusTooManyRequests, resp2.StatusCode)
	resp2.Body.Close()

	// Wait for light run to complete
	time.Sleep(4 * time.Second)
}

// ============================================================
// Agent concurrency — slot released after completion
// ============================================================

func TestAgentAPI_SlotReleasedAfterCompletion(t *testing.T) {
	env := newAgentTestEnvWithConfig(t, server.ServerConfig{
		AgentLightMax:     1,
		AgentQueueTimeout: 500 * time.Millisecond,
	})

	// First run: fast agent that completes quickly
	resp1 := env.post(t, "/api/agent/run/query", `{
		"prompt": "fast run"
	}`)
	require.Equal(t, http.StatusAccepted, resp1.StatusCode)
	var run1 server.AgentRunResponse
	readJSON(t, resp1, &run1)

	// Poll until first run completes
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r := env.get(t, "/api/agent/status/"+run1.RunID)
		var status server.AgentRunStatusResponse
		readJSON(t, r, &status)
		if status.Status != "running" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Second run should succeed (slot was released)
	resp2 := env.post(t, "/api/agent/run/query", `{
		"prompt": "second run after first completed"
	}`)
	assert.Equal(t, http.StatusAccepted, resp2.StatusCode)
	resp2.Body.Close()

	// Wait for completion
	time.Sleep(2 * time.Second)
}

// ============================================================
// Agent concurrency — queue waits for slot
// ============================================================

func TestAgentAPI_QueueWaitsForSlot(t *testing.T) {
	env := newAgentTestEnvWithConfig(t, server.ServerConfig{
		AgentLightMax:     1,
		AgentQueueTimeout: 5 * time.Second, // generous wait
	})

	// Start a fast agent (completes in ~1s)
	env.settings.Agent.Backends["brief-agent"] = config.AgentDef{
		Command: "sh",
		Args:    []string{"-c", "sleep 1 && echo done"},
	}

	resp1 := env.post(t, "/api/agent/run/query", `{
		"prompt": "brief",
		"agent": "brief-agent"
	}`)
	require.Equal(t, http.StatusAccepted, resp1.StatusCode)
	resp1.Body.Close()

	time.Sleep(200 * time.Millisecond)

	// Second request: slot is busy but queue timeout is generous,
	// so it should wait and eventually acquire the slot after first finishes
	resp2 := env.post(t, "/api/agent/run/query", `{
		"prompt": "waited in queue"
	}`)
	assert.Equal(t, http.StatusAccepted, resp2.StatusCode)
	resp2.Body.Close()

	// Wait for all to finish
	time.Sleep(3 * time.Second)
}

// ============================================================
// Agent concurrency — default config allows multiple runs
// ============================================================

func TestAgentAPI_DefaultConfigAllowsMultipleRuns(t *testing.T) {
	// Default config (no overrides) should allow multiple concurrent runs
	env := newAgentTestEnv(t)

	env.settings.Agent.Backends["slow-agent"] = config.AgentDef{
		Command: "sh",
		Args:    []string{"-c", "sleep 3 && echo done"},
	}

	// Fire 3 concurrent light runs — default is 10 slots, all should succeed
	for i := range 3 {
		resp := env.post(t, "/api/agent/run/query", fmt.Sprintf(`{
			"prompt": "run %d",
			"agent": "slow-agent"
		}`, i))
		assert.Equal(t, http.StatusAccepted, resp.StatusCode, "run %d should be accepted", i)
		resp.Body.Close()
	}

	// Wait for all to complete
	time.Sleep(3 * time.Second)
}
