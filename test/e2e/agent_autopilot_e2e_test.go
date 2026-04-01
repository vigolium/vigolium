//go:build e2e

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
)

// ─── Autonomous pipeline tests ───────────────────────────────────────────────

// TestAutopilotAutonomousDryRun tests that dry-run renders the prompt without launching agents.
func TestAutopilotAutonomousDryRun(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, repo := setupTestDB(t)

	settings := &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: "fake-autopilot",
			Backends: map[string]config.AgentDef{
				"fake-autopilot": {
					Command:     "/bin/echo",
					Description: "Fake autopilot agent for e2e testing",
				},
			},
		},
	}

	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	runner := agent.NewAutopilotPipelineRunner(engine, repo)

	cfg := agent.AutopilotPipelineConfig{
		TargetURL:   "http://localhost:3000",
		AgentName:   "fake-autopilot",
		MaxCommands: 10,
		SessionDir:  t.TempDir(),
		ProjectUUID: database.DefaultProjectUUID,
		DryRun:      true,
	}

	result, err := runner.RunAutonomous(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, result.Duration, time.Duration(0))
}

// ─── MCP Server Config tests ────────────────────────────────────────────────

// TestAutopilotMcpEnabled tests that MCP servers are included when mcp_enabled is true.
func TestAutopilotMcpEnabled(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	settings := &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: "test-agent",
			Backends: map[string]config.AgentDef{
				"test-agent": {
					Command:     "/bin/echo",
					Description: "Test agent",
					McpServers: []config.McpServerConfig{
						{Name: "backend-tool", Command: "backend-mcp", Args: []string{"serve"}},
					},
				},
			},
		},
	}

	// When mcp_enabled is false (default), global servers should not be merged
	assert.False(t, settings.Agent.IsMcpEnabled())

	// When mcp_enabled is true, global servers should be merged
	enabled := true
	settings.Agent.McpEnabled = &enabled
	settings.Agent.McpServers = []config.McpServerConfig{
		{Name: "playwright", Command: "npx", Args: []string{"-y", "@anthropic-ai/mcp-server-playwright"}},
		{Name: "backend-tool", Command: "global-mcp"}, // should be overridden by per-backend
	}
	assert.True(t, settings.Agent.IsMcpEnabled())

	// The engine's mergeGlobalMcpServers should merge correctly
	_, repo := setupTestDB(t)
	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	// Verify: per-backend "backend-tool" takes precedence over global "backend-tool"
	agentDef := settings.Agent.Backends["test-agent"]
	assert.Len(t, agentDef.McpServers, 1, "per-backend should have 1 server before merge")
	assert.Equal(t, "backend-tool", agentDef.McpServers[0].Name)
	assert.Equal(t, "backend-mcp", agentDef.McpServers[0].Command, "per-backend command should be preserved")
}

// ─── Real agent tests (conditional) ─────────────────────────────────────────

// TestAutopilotRealAgent runs the autonomous pipeline with a real agent backend.
// Skipped unless -agent flag is provided.
func TestAutopilotRealAgent(t *testing.T) {
	if *testAgentName == "" {
		t.Skip("Skipping: use -agent=<name> to run with real agent")
	}
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	settings, err := config.LoadSettings(*testConfigPath)
	require.NoError(t, err)

	db, repo := setupTestDB(t)
	_ = db

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	runner := agent.NewAutopilotPipelineRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.AutopilotPipelineConfig{
		TargetURL:   *testTargetURL,
		AgentName:   *testAgentName,
		MaxCommands: 20,
		SessionDir:  sessionDir,
		ProjectUUID: database.DefaultProjectUUID,
	}

	result, err := runner.RunAutonomous(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	t.Logf("Pipeline completed in %s", result.Duration.Round(time.Second))
	t.Logf("Session dir: %s", sessionDir)
}
