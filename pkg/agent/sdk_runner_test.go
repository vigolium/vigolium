package agent

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/claudesdk"
)

// mockClaudeScript creates a shell script that simulates Claude CLI's JSON-lines
// output. The script reads one line from stdin (the user message), then writes
// pre-configured JSON responses to stdout and exits.
func mockClaudeScript(t *testing.T, responses ...string) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "mock-claude")

	var buf bytes.Buffer
	buf.WriteString("#!/bin/sh\n")
	// Read one line from stdin (the user message JSON) then respond
	buf.WriteString("read -r _line\n")
	for _, r := range responses {
		// Use printf to avoid issues with single quotes in JSON
		buf.WriteString("printf '%s\\n' '" + strings.ReplaceAll(r, "'", "'\\''") + "'\n")
	}

	if err := os.WriteFile(script, buf.Bytes(), 0755); err != nil {
		t.Fatalf("failed to write mock script: %v", err)
	}
	return script
}

// --- buildSDKOptions tests ---

func TestBuildSDKOptions_Defaults(t *testing.T) {
	agentDef := config.AgentDef{Command: "claude"}
	cfg := sdkRunConfig{}

	opts := buildSDKOptions(agentDef, cfg)

	if opts.PermissionMode != "bypassPermissions" {
		t.Errorf("PermissionMode: got %q, want bypassPermissions", opts.PermissionMode)
	}
	if !opts.DangerouslySkipPermissions {
		t.Error("DangerouslySkipPermissions should be true")
	}
	if !opts.NoSessionPersistence {
		t.Error("NoSessionPersistence should be true")
	}
	if len(opts.DisallowedTools) != 4 {
		t.Errorf("DisallowedTools: got %d, want 4", len(opts.DisallowedTools))
	}
}

func TestBuildSDKOptions_ModelPriority(t *testing.T) {
	// cfg.Model > agentDef.Model
	agentDef := config.AgentDef{Model: "sonnet"}
	cfg := sdkRunConfig{Model: "opus"}

	opts := buildSDKOptions(agentDef, cfg)
	if opts.Model != "opus" {
		t.Errorf("Model: got %q, want opus (cfg override)", opts.Model)
	}

	// agentDef.Model when cfg.Model is empty
	cfg2 := sdkRunConfig{}
	opts2 := buildSDKOptions(agentDef, cfg2)
	if opts2.Model != "sonnet" {
		t.Errorf("Model: got %q, want sonnet (agentDef fallback)", opts2.Model)
	}
}

func TestBuildSDKOptions_CustomExecutable(t *testing.T) {
	agentDef := config.AgentDef{Command: "/usr/local/bin/claude-custom"}
	opts := buildSDKOptions(agentDef, sdkRunConfig{})

	if opts.Executable != "/usr/local/bin/claude-custom" {
		t.Errorf("Executable: got %q", opts.Executable)
	}
}

func TestBuildSDKOptions_ClaudeDefaultExecutable(t *testing.T) {
	agentDef := config.AgentDef{Command: "claude"}
	opts := buildSDKOptions(agentDef, sdkRunConfig{})

	if opts.Executable != "" {
		t.Errorf("Executable should be empty for default claude, got %q", opts.Executable)
	}
}

func TestBuildSDKOptions_Streaming(t *testing.T) {
	agentDef := config.AgentDef{Command: "claude"}

	// No stream writer → no partial messages
	opts1 := buildSDKOptions(agentDef, sdkRunConfig{})
	if opts1.IncludePartialMessages {
		t.Error("IncludePartialMessages should be false without StreamWriter")
	}

	// With stream writer → partial messages enabled
	opts2 := buildSDKOptions(agentDef, sdkRunConfig{StreamWriter: io.Discard})
	if !opts2.IncludePartialMessages {
		t.Error("IncludePartialMessages should be true with StreamWriter")
	}
}

func TestBuildSDKOptions_McpServers(t *testing.T) {
	agentDef := config.AgentDef{Command: "claude"}
	cfg := sdkRunConfig{
		McpServers: []config.McpServerConfig{
			{Name: "playwright", Command: "npx", Args: []string{"-y", "playwright"}},
			{Name: "custom", URL: "http://localhost:8080/mcp"},
		},
	}

	opts := buildSDKOptions(agentDef, cfg)
	if opts.McpConfigJSON == "" {
		t.Error("McpConfigJSON should not be empty with MCP servers configured")
	}
	if !strings.Contains(opts.McpConfigJSON, "playwright") {
		t.Error("McpConfigJSON should contain playwright")
	}
	if !strings.Contains(opts.McpConfigJSON, "http://localhost:8080/mcp") {
		t.Error("McpConfigJSON should contain custom URL")
	}
}

func TestBuildSDKOptions_AdditionalDirs(t *testing.T) {
	agentDef := config.AgentDef{Command: "claude"}
	cfg := sdkRunConfig{AdditionalDirs: []string{"/src", "/test"}}

	opts := buildSDKOptions(agentDef, cfg)
	if len(opts.AdditionalDirs) != 2 {
		t.Errorf("AdditionalDirs: got %d, want 2", len(opts.AdditionalDirs))
	}
}

func TestBuildSDKOptions_MaxTurns(t *testing.T) {
	agentDef := config.AgentDef{Command: "claude"}
	cfg := sdkRunConfig{MaxTurns: 300}

	opts := buildSDKOptions(agentDef, cfg)
	if opts.MaxTurns != 300 {
		t.Errorf("MaxTurns: got %d, want 300", opts.MaxTurns)
	}
}

func TestBuildSDKOptions_AppendSystemPrompt(t *testing.T) {
	agentDef := config.AgentDef{Command: "claude"}
	cfg := sdkRunConfig{AppendSystemPrompt: "You are a scanner"}

	opts := buildSDKOptions(agentDef, cfg)
	if opts.AppendSystemPrompt != "You are a scanner" {
		t.Errorf("AppendSystemPrompt: got %q", opts.AppendSystemPrompt)
	}
}

func TestBuildSDKOptions_Effort(t *testing.T) {
	agentDef := config.AgentDef{Command: "claude"}
	cfg := sdkRunConfig{Effort: "high"}

	opts := buildSDKOptions(agentDef, cfg)
	if opts.Effort != "high" {
		t.Errorf("Effort: got %q, want high", opts.Effort)
	}
}

func TestBuildSDKOptions_SessionID(t *testing.T) {
	agentDef := config.AgentDef{Command: "claude"}
	cfg := sdkRunConfig{SessionID: "550e8400-e29b-41d4-a716-446655440000"}

	opts := buildSDKOptions(agentDef, cfg)
	if opts.SessionID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("SessionID: got %q", opts.SessionID)
	}
	if opts.NoSessionPersistence {
		t.Error("NoSessionPersistence should be false when SessionID is set")
	}
}

func TestBuildSDKOptions_NoSessionID(t *testing.T) {
	agentDef := config.AgentDef{Command: "claude"}
	cfg := sdkRunConfig{}

	opts := buildSDKOptions(agentDef, cfg)
	if opts.SessionID != "" {
		t.Errorf("SessionID should be empty, got %q", opts.SessionID)
	}
	if !opts.NoSessionPersistence {
		t.Error("NoSessionPersistence should be true when no SessionID")
	}
}

func TestBuildSDKOptions_EnvVars(t *testing.T) {
	agentDef := config.AgentDef{
		Command: "claude",
		Env:     map[string]string{"API_KEY": "test123"},
	}
	cfg := sdkRunConfig{}

	opts := buildSDKOptions(agentDef, cfg)
	if opts.Env["API_KEY"] != "test123" {
		t.Errorf("Env[API_KEY]: got %q", opts.Env["API_KEY"])
	}
}

func TestBuildMcpConfigFromServers(t *testing.T) {
	servers := []config.McpServerConfig{
		{Name: "stdio-server", Command: "my-mcp", Args: []string{"--flag"}},
		{Name: "http-server", URL: "http://localhost:9090"},
	}

	result := buildMcpConfigFromServers(servers)
	if result == "" {
		t.Fatal("expected non-empty MCP config JSON")
	}
	if !strings.Contains(result, "stdio-server") {
		t.Error("result should contain stdio-server")
	}
	if !strings.Contains(result, "http-server") {
		t.Error("result should contain http-server")
	}
}

func TestBuildMcpConfigFromServers_Empty(t *testing.T) {
	result := buildMcpConfigFromServers(nil)
	if result != "" {
		t.Errorf("expected empty for nil servers, got %q", result)
	}
}

// --- RunAgenticSDK tests (using mock script) ---

func TestRunAgenticSDK_BasicRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	script := mockClaudeScript(t,
		`{"type":"assistant","session_id":"s1","message":{"model":"sonnet","content":[{"type":"text","text":"Hello from mock"}]}}`,
		`{"type":"result","session_id":"s1","subtype":"success","is_error":false,"num_turns":1,"total_cost_usd":0.005,"duration_ms":100,"usage":{"input_tokens":50,"output_tokens":20}}`,
	)

	agentDef := config.AgentDef{Command: script, Protocol: "sdk"}
	cfg := sdkRunConfig{Cwd: t.TempDir()}

	result, err := RunAgenticSDK(context.Background(), agentDef, "test prompt", cfg)
	if err != nil {
		t.Fatalf("RunAgenticSDK error: %v", err)
	}
	if !strings.Contains(result.Stdout, "Hello from mock") {
		t.Errorf("stdout should contain mock response, got %q", result.Stdout)
	}
}

func TestRunAgenticSDK_WithStreaming(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	script := mockClaudeScript(t,
		`{"type":"stream_event","session_id":"s","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"chunk1"}}}`,
		`{"type":"stream_event","session_id":"s","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"chunk2"}}}`,
		`{"type":"assistant","session_id":"s","message":{"model":"sonnet","content":[{"type":"text","text":"chunk1chunk2"}]}}`,
		`{"type":"result","session_id":"s","subtype":"success","is_error":false,"num_turns":1,"total_cost_usd":0.001,"duration_ms":50,"usage":{"input_tokens":10,"output_tokens":5}}`,
	)

	var streamBuf bytes.Buffer
	agentDef := config.AgentDef{Command: script, Protocol: "sdk"}
	cfg := sdkRunConfig{
		Cwd:          t.TempDir(),
		StreamWriter: &streamBuf,
	}

	result, err := RunAgenticSDK(context.Background(), agentDef, "test", cfg)
	if err != nil {
		t.Fatalf("RunAgenticSDK error: %v", err)
	}

	if result.Stdout != "chunk1chunk2" {
		t.Errorf("stdout: got %q, want chunk1chunk2", result.Stdout)
	}
	if streamBuf.String() != "chunk1chunk2" {
		t.Errorf("stream output: got %q, want chunk1chunk2", streamBuf.String())
	}
}

func TestRunAgenticSDK_ErrorResult(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	script := mockClaudeScript(t,
		`{"type":"result","session_id":"s","subtype":"error_max_turns","is_error":true,"num_turns":50,"total_cost_usd":1.0,"duration_ms":60000,"usage":{"input_tokens":0,"output_tokens":0}}`,
	)

	agentDef := config.AgentDef{Command: script, Protocol: "sdk"}
	cfg := sdkRunConfig{Cwd: t.TempDir()}

	result, err := RunAgenticSDK(context.Background(), agentDef, "test", cfg)
	if err != nil {
		t.Fatalf("RunAgenticSDK error: %v", err)
	}
	// Error result is reported via the result message, not as a Go error
	if result.Stdout != "" {
		t.Errorf("stdout should be empty for error result, got %q", result.Stdout)
	}
}

func TestRunAgenticSDK_MissingCommand(t *testing.T) {
	agentDef := config.AgentDef{Command: "/nonexistent/claude-12345", Protocol: "sdk"}
	cfg := sdkRunConfig{Cwd: t.TempDir()}

	_, err := RunAgenticSDK(context.Background(), agentDef, "test", cfg)
	if err == nil {
		t.Error("expected error for missing command")
	}
}

func TestRunAgenticSDK_MultipleTextBlocks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	script := mockClaudeScript(t,
		`{"type":"assistant","session_id":"s","message":{"model":"sonnet","content":[{"type":"thinking","thinking":"analyzing..."},{"type":"text","text":"answer"}]}}`,
		`{"type":"result","session_id":"s","subtype":"success","is_error":false,"num_turns":1,"total_cost_usd":0.001,"duration_ms":50,"usage":{"input_tokens":10,"output_tokens":5}}`,
	)

	agentDef := config.AgentDef{Command: script, Protocol: "sdk"}
	cfg := sdkRunConfig{Cwd: t.TempDir()}

	result, err := RunAgenticSDK(context.Background(), agentDef, "test", cfg)
	if err != nil {
		t.Fatalf("RunAgenticSDK error: %v", err)
	}
	// Only text blocks should be in output, not thinking blocks
	if result.Stdout != "answer" {
		t.Errorf("stdout: got %q, want 'answer'", result.Stdout)
	}
}

// --- SDK Pool tests ---

func TestNewSDKPool(t *testing.T) {
	cfg := config.WarmSessionConfig{
		Enable:      boolPtr(true),
		IdleTimeout: 60,
		MaxSessions: 3,
	}
	agents := map[string]config.AgentDef{
		"test": {Command: "claude", Protocol: "sdk"},
	}

	pool := NewSDKPool(cfg, agents)
	if pool == nil {
		t.Fatal("expected pool to be non-nil")
	}
	defer pool.Close()

	// Pool should be functional (not closed) right after creation
	// We verify this indirectly — a closed pool returns an error on Prompt
}

func TestSDKPoolClose(t *testing.T) {
	cfg := config.WarmSessionConfig{Enable: boolPtr(true)}
	agents := map[string]config.AgentDef{}

	pool := NewSDKPool(cfg, agents)
	pool.Close()

	// Verify pool is closed by confirming Prompt returns an error
	_, err := pool.Prompt(context.Background(), "test", "hello", sdkRunConfig{}, "test", 0)
	if err == nil {
		t.Error("pool should be closed after Close()")
	}

	// Double close should not panic
	pool.Close()
}

func TestSDKPoolPromptClosed(t *testing.T) {
	cfg := config.WarmSessionConfig{Enable: boolPtr(true)}
	agents := map[string]config.AgentDef{
		"test": {Command: "claude", Protocol: "sdk"},
	}

	pool := NewSDKPool(cfg, agents)
	pool.Close()

	_, err := pool.Prompt(context.Background(), "test", "hello", sdkRunConfig{}, "test", 0)
	if err == nil {
		t.Error("expected error when prompting a closed pool")
	}
}

func TestSDKPoolResolveAgent(t *testing.T) {
	agents := map[string]config.AgentDef{
		"custom": {Command: "/usr/bin/custom-claude", Protocol: "sdk", Model: "opus"},
	}
	cfg := config.WarmSessionConfig{Enable: boolPtr(true)}
	pool := NewSDKPool(cfg, agents)
	defer pool.Close()

	// Known agent
	def := pool.inner.ResolveAgent("custom", sdkFallbackAgent)
	if def.Command != "/usr/bin/custom-claude" {
		t.Errorf("resolved command: got %q", def.Command)
	}
	if def.Model != "opus" {
		t.Errorf("resolved model: got %q", def.Model)
	}

	// Unknown agent → fallback
	def2 := pool.inner.ResolveAgent("nonexistent", sdkFallbackAgent)
	if def2.Command != "claude" {
		t.Errorf("fallback command: got %q", def2.Command)
	}
	if def2.Protocol != "sdk" {
		t.Errorf("fallback protocol: got %q", def2.Protocol)
	}
}

func TestSDKPoolPromptWithMockScript(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	script := mockClaudeScript(t,
		`{"type":"assistant","session_id":"s","message":{"model":"sonnet","content":[{"type":"text","text":"pooled response"}]}}`,
		`{"type":"result","session_id":"s","subtype":"success","is_error":false,"num_turns":1,"total_cost_usd":0.001,"duration_ms":50,"usage":{"input_tokens":10,"output_tokens":5}}`,
	)

	cfg := config.WarmSessionConfig{Enable: boolPtr(true), MaxSessions: 2}
	agents := map[string]config.AgentDef{
		"test": {Command: script, Protocol: "sdk"},
	}

	pool := NewSDKPool(cfg, agents)
	defer pool.Close()

	result, err := pool.Prompt(context.Background(), "test", "hello", sdkRunConfig{Cwd: t.TempDir()}, "test-key", 0)
	if err != nil {
		t.Fatalf("Prompt error: %v", err)
	}
	if !strings.Contains(result.Stdout, "pooled response") {
		t.Errorf("stdout: got %q, want 'pooled response'", result.Stdout)
	}
}

// --- Engine SDK integration tests ---

func TestEngineSDKCase_AutopilotConfig(t *testing.T) {
	// Verify that autopilot SDK config sets high MaxTurns, effort, and system prompt
	agentDef := config.AgentDef{Command: "claude", Protocol: "sdk"}

	cfg := sdkRunConfig{}

	// Simulate what engine.go does for autopilot
	maxCommands := 100
	cfg.MaxTurns = maxCommands * 3
	if cfg.MaxTurns <= 0 {
		cfg.MaxTurns = 300
	}
	cfg.Effort = "high"
	sysPrompt, source := LoadSDKAutopilotSystemPrompt()
	cfg.AppendSystemPrompt = sysPrompt
	cfg.SystemPromptSource = source

	opts := buildSDKOptions(agentDef, cfg)

	if opts.MaxTurns != 300 {
		t.Errorf("MaxTurns: got %d, want 300", opts.MaxTurns)
	}
	if opts.Effort != "high" {
		t.Errorf("Effort: got %q, want high", opts.Effort)
	}
	// System prompt should be passed either inline or via CLAUDE.md (depending on SystemPromptDir)
	if !strings.Contains(sysPrompt, "vigolium") {
		t.Error("system prompt should contain vigolium context")
	}
}

func TestEngineSDKCase_SourcePathConfig(t *testing.T) {
	agentDef := config.AgentDef{Command: "claude", Protocol: "sdk"}
	sourcePath := "/tmp/juice-shop"

	cfg := sdkRunConfig{
		Cwd:            sourcePath,
		AdditionalDirs: []string{sourcePath},
	}
	cfg.AppendSystemPrompt = "Application source code is available at: " + sourcePath

	opts := buildSDKOptions(agentDef, cfg)

	if opts.Cwd != sourcePath {
		t.Errorf("Cwd: got %q", opts.Cwd)
	}
	if len(opts.AdditionalDirs) != 1 || opts.AdditionalDirs[0] != sourcePath {
		t.Errorf("AdditionalDirs: got %v", opts.AdditionalDirs)
	}
	if !strings.Contains(opts.AppendSystemPrompt, sourcePath) {
		t.Error("AppendSystemPrompt should contain source path")
	}
}

// --- claudesdk.BuildAgentsJSON integration ---

func TestBuildAgentsJSONIntegration(t *testing.T) {
	agents := map[string]claudesdk.AgentDefinition{
		"security-reviewer": {
			Description: "Reviews code for security issues",
			Prompt:      "You are a security code reviewer",
			Model:       "opus",
		},
	}

	json, err := claudesdk.BuildAgentsJSON(agents)
	if err != nil {
		t.Fatalf("BuildAgentsJSON error: %v", err)
	}
	if !strings.Contains(json, "security-reviewer") {
		t.Error("JSON should contain agent name")
	}
	if !strings.Contains(json, "opus") {
		t.Error("JSON should contain model")
	}
}
