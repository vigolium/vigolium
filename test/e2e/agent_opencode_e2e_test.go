//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
)

// buildFakeOpenCodeServer compiles the fake OpenCode HTTP server Go program and
// returns the path to the binary. The binary implements the OpenCode REST API + SSE
// and is spawned as a subprocess by the opencodesdk.Client.
func buildFakeOpenCodeServer(t *testing.T) string {
	t.Helper()

	binDir := t.TempDir()
	binary := filepath.Join(binDir, "fake-opencode-server")
	srcFile := filepath.Join("testdata", "fake_opencode_server.go")

	cmd := exec.Command("go", "build", "-o", binary, srcFile)
	cmd.Dir = filepath.Join(".")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to build fake opencode server: %s", string(out))

	return binary
}

// newOpenCodeTestEngine creates an agent engine with a fake opencode-sdk backend.
// agentResponse is the text the fake server will return for every prompt.
func newOpenCodeTestEngine(t *testing.T, binary string, agentResponse string, warmSession *config.WarmSessionConfig) *agent.Engine {
	t.Helper()

	db, repo := setupTestDB(t)
	t.Cleanup(func() { db.Close() })

	ws := config.WarmSessionConfig{}
	if warmSession != nil {
		ws = *warmSession
	}

	settings := &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: "fake-opencode",
			Backends: map[string]config.AgentDef{
				"fake-opencode": {
					Command:  binary,
					Protocol: "opencode-sdk",
					Env: map[string]string{
						"FAKE_OPENCODE_RESPONSE": agentResponse,
					},
				},
			},
			WarmSession: ws,
		},
	}

	engine := agent.NewEngine(settings, repo)
	t.Cleanup(func() { engine.Close() })
	return engine
}

// ============================================================
// E2E: OpenCode SDK — basic engine dispatch
// ============================================================

func TestOpenCodeSDK_EngineDispatch(t *testing.T) {
	binary := buildFakeOpenCodeServer(t)
	engine := newOpenCodeTestEngine(t, binary, "Engine dispatched response", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := engine.Run(ctx, agent.Options{
		AgentName:    "fake-opencode",
		PromptInline: "Test engine dispatch",
	})
	require.NoError(t, err)
	assert.Contains(t, result.RawOutput, "Engine dispatched response")
	assert.NotEmpty(t, result.SessionID, "session ID should be populated")
}

func TestOpenCodeSDK_EngineDispatch_DefaultAgent(t *testing.T) {
	binary := buildFakeOpenCodeServer(t)
	engine := newOpenCodeTestEngine(t, binary, "Default agent response", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// No AgentName — should use default (fake-opencode)
	result, err := engine.Run(ctx, agent.Options{
		PromptInline: "Use default agent",
	})
	require.NoError(t, err)
	assert.Contains(t, result.RawOutput, "Default agent response")
	assert.Equal(t, "fake-opencode", result.AgentName)
}

// ============================================================
// E2E: OpenCode SDK — streaming output
// ============================================================

func TestOpenCodeSDK_Streaming(t *testing.T) {
	binary := buildFakeOpenCodeServer(t)
	engine := newOpenCodeTestEngine(t, binary, "Streamed via engine", nil)

	var streamBuf bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := engine.Run(ctx, agent.Options{
		AgentName:    "fake-opencode",
		PromptInline: "Stream test",
		StreamWriter: &streamBuf,
	})
	require.NoError(t, err)

	// Stream writer should have received the deltas
	assert.Contains(t, streamBuf.String(), "Streamed via engine")
	// RawOutput should also be populated
	assert.NotEmpty(t, result.RawOutput)
}

// ============================================================
// E2E: OpenCode SDK — warm session pool with session reuse
// ============================================================

func TestOpenCodeSDK_Pool_SessionReuse(t *testing.T) {
	binary := buildFakeOpenCodeServer(t)
	boolTrue := true
	engine := newOpenCodeTestEngine(t, binary, "Pooled response", &config.WarmSessionConfig{
		Enable:      &boolTrue,
		IdleTimeout: 60,
		MaxSessions: 2,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// First prompt — creates a new session
	result1, err := engine.Run(ctx, agent.Options{
		AgentName:    "fake-opencode",
		PromptInline: "First prompt",
	})
	require.NoError(t, err)
	assert.Contains(t, result1.RawOutput, "Pooled response")
	sessionID1 := result1.SessionID

	// Second prompt — should reuse the session (same pool key)
	result2, err := engine.Run(ctx, agent.Options{
		AgentName:    "fake-opencode",
		PromptInline: "Second prompt",
	})
	require.NoError(t, err)
	assert.Contains(t, result2.RawOutput, "Pooled response")
	// Session ID should be the same (session reuse)
	assert.Equal(t, sessionID1, result2.SessionID, "session should be reused across prompts")
}

func TestOpenCodeSDK_Pool_DifferentSessionKeys(t *testing.T) {
	binary := buildFakeOpenCodeServer(t)
	boolTrue := true
	engine := newOpenCodeTestEngine(t, binary, "Keyed response", &config.WarmSessionConfig{
		Enable:      &boolTrue,
		IdleTimeout: 60,
		MaxSessions: 4,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Different session keys should create separate sessions
	result1, err := engine.Run(ctx, agent.Options{
		AgentName:    "fake-opencode",
		PromptInline: "Phase 1",
		SessionKey:   "source-analysis",
	})
	require.NoError(t, err)
	assert.Contains(t, result1.RawOutput, "Keyed response")

	result2, err := engine.Run(ctx, agent.Options{
		AgentName:    "fake-opencode",
		PromptInline: "Phase 2",
		SessionKey:   "triage",
	})
	require.NoError(t, err)
	assert.Contains(t, result2.RawOutput, "Keyed response")

	// Both prompts completed successfully with separate sessions
	assert.NotEmpty(t, result1.SessionID)
	assert.NotEmpty(t, result2.SessionID)
}

// ============================================================
// E2E: OpenCode SDK — source path context
// ============================================================

func TestOpenCodeSDK_WithSourcePath(t *testing.T) {
	binary := buildFakeOpenCodeServer(t)
	engine := newOpenCodeTestEngine(t, binary, "Source-aware response", nil)

	sourceDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "main.go"), []byte("package main"), 0o644))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := engine.Run(ctx, agent.Options{
		AgentName:    "fake-opencode",
		PromptInline: "Review the code",
		SourcePath:   sourceDir,
	})
	require.NoError(t, err)
	assert.Contains(t, result.RawOutput, "Source-aware response")
}

// ============================================================
// E2E: OpenCode SDK — config validation
// ============================================================

func TestOpenCodeSDK_ConfigValidation(t *testing.T) {
	cfg := config.AgentConfig{
		DefaultAgent: "opencode",
		Backends: map[string]config.AgentDef{
			"opencode": {
				Command:  "opencode",
				Protocol: "opencode-sdk",
			},
		},
	}
	assert.NoError(t, cfg.Validate())
}

func TestOpenCodeSDK_ConfigValidation_InvalidProtocol(t *testing.T) {
	cfg := config.AgentConfig{
		DefaultAgent: "bad",
		Backends: map[string]config.AgentDef{
			"bad": {
				Command:  "opencode",
				Protocol: "opencode-rpc",
			},
		},
	}
	assert.Error(t, cfg.Validate())
}

// ============================================================
// E2E: OpenCode SDK — dry run
// ============================================================

func TestOpenCodeSDK_DryRun(t *testing.T) {
	binary := buildFakeOpenCodeServer(t)
	engine := newOpenCodeTestEngine(t, binary, "Should not be called", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := engine.Run(ctx, agent.Options{
		AgentName:    "fake-opencode",
		PromptInline: "Dry run test prompt",
		DryRun:       true,
	})
	require.NoError(t, err)
	assert.True(t, result.DryRun)
	// Dry run returns the rendered prompt as RawOutput
	assert.Contains(t, result.RawOutput, "Dry run test prompt")
}
