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

// buildFakeCodexServer compiles the fake codex app-server Go program and
// returns the path to the binary. The binary speaks JSON-RPC v2 over stdio
// and returns agentResponse as the agent's text output.
func buildFakeCodexServer(t *testing.T) string {
	t.Helper()

	binDir := t.TempDir()
	binary := filepath.Join(binDir, "fake-codex-server")
	srcFile := filepath.Join("testdata", "fake_codex_server.go")

	cmd := exec.Command("go", "build", "-o", binary, srcFile)
	cmd.Dir = filepath.Join(".") // test/e2e/
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to build fake codex server: %s", string(out))

	return binary
}

// newCodexTestEngine creates an agent engine with a fake codex-sdk backend.
// The fake server binary is compiled once and reused; agentResponse is passed as a CLI arg.
func newCodexTestEngine(t *testing.T, binary string, agentResponse string, warmSession *config.WarmSessionConfig) *agent.Engine {
	t.Helper()

	db, repo := setupTestDB(t)
	t.Cleanup(func() { db.Close() })

	ws := config.WarmSessionConfig{}
	if warmSession != nil {
		ws = *warmSession
	}

	settings := &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: "fake-codex",
			Backends: map[string]config.AgentDef{
				"fake-codex": {
					Command:  binary,
					Args:     []string{agentResponse},
					Protocol: "codex-sdk",
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
// E2E: Codex SDK — basic engine dispatch
// ============================================================

func TestCodexSDK_EngineDispatch(t *testing.T) {
	binary := buildFakeCodexServer(t)
	engine := newCodexTestEngine(t, binary, "Engine dispatched response", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := engine.Run(ctx, agent.Options{
		AgentName:    "fake-codex",
		PromptInline: "Test engine dispatch",
	})
	require.NoError(t, err)
	assert.Contains(t, result.RawOutput, "Engine dispatched response")
	assert.NotEmpty(t, result.SessionID, "session ID (thread ID) should be populated")
}

func TestCodexSDK_EngineDispatch_DefaultAgent(t *testing.T) {
	binary := buildFakeCodexServer(t)
	engine := newCodexTestEngine(t, binary, "Default agent response", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// No AgentName — should use default (fake-codex)
	result, err := engine.Run(ctx, agent.Options{
		PromptInline: "Use default agent",
	})
	require.NoError(t, err)
	assert.Contains(t, result.RawOutput, "Default agent response")
	assert.Equal(t, "fake-codex", result.AgentName)
}

// ============================================================
// E2E: Codex SDK — streaming output
// ============================================================

func TestCodexSDK_Streaming(t *testing.T) {
	binary := buildFakeCodexServer(t)
	engine := newCodexTestEngine(t, binary, "Streamed via engine", nil)

	var streamBuf bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := engine.Run(ctx, agent.Options{
		AgentName:    "fake-codex",
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
// E2E: Codex SDK — warm session pool with thread reuse
// ============================================================

func TestCodexSDK_Pool_ThreadReuse(t *testing.T) {
	binary := buildFakeCodexServer(t)
	boolTrue := true
	engine := newCodexTestEngine(t, binary, "Pooled response", &config.WarmSessionConfig{
		Enable:      &boolTrue,
		IdleTimeout: 60,
		MaxSessions: 2,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// First prompt — creates a new session + thread
	result1, err := engine.Run(ctx, agent.Options{
		AgentName:    "fake-codex",
		PromptInline: "First prompt",
	})
	require.NoError(t, err)
	assert.Contains(t, result1.RawOutput, "Pooled response")
	sessionID1 := result1.SessionID

	// Second prompt — should reuse the thread (same pool key)
	result2, err := engine.Run(ctx, agent.Options{
		AgentName:    "fake-codex",
		PromptInline: "Second prompt",
	})
	require.NoError(t, err)
	assert.Contains(t, result2.RawOutput, "Pooled response")
	// Thread ID should be the same (thread reuse)
	assert.Equal(t, sessionID1, result2.SessionID, "thread should be reused across prompts")
}

func TestCodexSDK_Pool_DifferentSessionKeys(t *testing.T) {
	binary := buildFakeCodexServer(t)
	boolTrue := true
	engine := newCodexTestEngine(t, binary, "Keyed response", &config.WarmSessionConfig{
		Enable:      &boolTrue,
		IdleTimeout: 60,
		MaxSessions: 4,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Different session keys should create separate threads
	result1, err := engine.Run(ctx, agent.Options{
		AgentName:    "fake-codex",
		PromptInline: "Phase 1",
		SessionKey:   "source-analysis",
	})
	require.NoError(t, err)
	assert.Contains(t, result1.RawOutput, "Keyed response")

	result2, err := engine.Run(ctx, agent.Options{
		AgentName:    "fake-codex",
		PromptInline: "Phase 2",
		SessionKey:   "triage",
	})
	require.NoError(t, err)
	assert.Contains(t, result2.RawOutput, "Keyed response")
}

// ============================================================
// E2E: Codex SDK — source path context
// ============================================================

func TestCodexSDK_WithSourcePath(t *testing.T) {
	binary := buildFakeCodexServer(t)
	engine := newCodexTestEngine(t, binary, "Source-aware response", nil)

	sourceDir := t.TempDir()
	// Create a dummy source file
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "main.go"), []byte("package main"), 0o644))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := engine.Run(ctx, agent.Options{
		AgentName:    "fake-codex",
		PromptInline: "Review the code",
		SourcePath:   sourceDir,
	})
	require.NoError(t, err)
	assert.Contains(t, result.RawOutput, "Source-aware response")
}

// ============================================================
// E2E: Codex SDK — config validation
// ============================================================

func TestCodexSDK_ConfigValidation(t *testing.T) {
	cfg := config.AgentConfig{
		DefaultAgent: "codex",
		Backends: map[string]config.AgentDef{
			"codex": {
				Command:  "codex",
				Protocol: "codex-sdk",
			},
		},
	}
	assert.NoError(t, cfg.Validate())
}

func TestCodexSDK_ConfigValidation_InvalidProtocol(t *testing.T) {
	cfg := config.AgentConfig{
		DefaultAgent: "bad",
		Backends: map[string]config.AgentDef{
			"bad": {
				Command:  "codex",
				Protocol: "codex-rpc",
			},
		},
	}
	assert.Error(t, cfg.Validate())
}

// ============================================================
// E2E: Codex SDK — dry run
// ============================================================

func TestCodexSDK_DryRun(t *testing.T) {
	binary := buildFakeCodexServer(t)
	engine := newCodexTestEngine(t, binary, "Should not be called", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := engine.Run(ctx, agent.Options{
		AgentName:    "fake-codex",
		PromptInline: "Dry run test prompt",
		DryRun:       true,
	})
	require.NoError(t, err)
	assert.True(t, result.DryRun)
	// Dry run returns the rendered prompt as RawOutput
	assert.Contains(t, result.RawOutput, "Dry run test prompt")
}
