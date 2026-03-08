//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

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

// newAgentTestEnv starts an API server with a fake agent configured.
// The fake agent uses "cat" which echoes stdin to stdout, simulating
// an agent that returns the prompt as its output.
func newAgentTestEnv(t *testing.T) *agentTestEnv {
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
			Agents: map[string]config.AgentDef{
				"fake-agent": {
					Command:     "cat",
					Description: "Fake agent for testing (echoes stdin)",
				},
				"alt-agent": {
					Command:     "cat",
					Description: "Alternative fake agent for testing",
				},
			},
		},
	}

	srv := server.NewServer(server.ServerConfig{
		ServiceAddr:          addr,
		NoAuth:               true,
		CORSAllowedOrigins:   "reflect-origin",
		Version:              "test-agent-v0.0.1",
		DisableFetchResponse: true,
		WriteTimeout:         120 * time.Second,
	}, taskQueue, db, repo, settings, nil)

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
	assert.Contains(t, body.RunID, "agt-")

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
// POST /api/agent/run/query — concurrency lock
// ============================================================

func TestAgentAPI_Run_ConcurrencyLock(t *testing.T) {
	env := newAgentTestEnv(t)

	// Start an agent run with a slow command
	// Use "sleep 2" as a slow agent so it stays running while we test
	env.settings.Agent.Agents["slow-agent"] = config.AgentDef{
		Command: "sleep",
		Args:    []string{"2"},
	}

	resp1 := env.post(t, "/api/agent/run/query", `{
		"prompt": "slow run",
		"agent": "slow-agent"
	}`)
	require.Equal(t, http.StatusAccepted, resp1.StatusCode)
	resp1.Body.Close()

	// Give it a moment to start
	time.Sleep(200 * time.Millisecond)

	// Second request should get 409 Conflict
	resp2 := env.post(t, "/api/agent/run/query", `{
		"prompt": "should be rejected"
	}`)
	assert.Equal(t, http.StatusConflict, resp2.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp2, &body)
	assert.Contains(t, body.Error, "already")

	// Wait for first run to finish to not interfere with other tests
	time.Sleep(3 * time.Second)
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
// POST /api/agent/chat/completions — concurrency lock
// ============================================================

func TestAgentAPI_ChatCompletions_ConcurrencyLock(t *testing.T) {
	env := newAgentTestEnv(t)

	// Start a slow agent run via the /run endpoint
	env.settings.Agent.Agents["slow-agent"] = config.AgentDef{
		Command: "sleep",
		Args:    []string{"2"},
	}

	resp1 := env.post(t, "/api/agent/run/query", `{
		"prompt": "hold the lock",
		"agent": "slow-agent"
	}`)
	require.Equal(t, http.StatusAccepted, resp1.StatusCode)
	resp1.Body.Close()

	// Give it a moment to start
	time.Sleep(200 * time.Millisecond)

	// Chat completions should also get 409
	resp2 := env.post(t, "/api/agent/chat/completions", `{
		"model": "fake-agent",
		"messages": [{"role": "user", "content": "should fail"}]
	}`)
	assert.Equal(t, http.StatusConflict, resp2.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp2, &body)
	assert.Contains(t, body.Error, "already")

	// Wait for first run to finish
	time.Sleep(3 * time.Second)
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
// POST /api/agent/chat/completions — shared lock with /agent/run/query
// ============================================================

func TestAgentAPI_ChatCompletions_BlocksAgentRun(t *testing.T) {
	env := newAgentTestEnv(t)

	// Use a slow agent via chat completions by configuring a slow command
	env.settings.Agent.Agents["slow-chat"] = config.AgentDef{
		Command: "sleep",
		Args:    []string{"2"},
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

	// Give it a moment to acquire the lock
	time.Sleep(300 * time.Millisecond)

	// Agent run should be blocked
	resp := env.post(t, "/api/agent/run/query", `{
		"prompt": "should be blocked"
	}`)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp.Body.Close()

	// Wait for chat completion to finish
	<-done
}
