package claudesdk

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestBuildArgs_BaseFlags(t *testing.T) {
	opts := &Options{}
	args := opts.buildArgs()

	for _, want := range []string{"--print", "--output-format=stream-json", "--input-format=stream-json", "--verbose"} {
		if !slices.Contains(args, want) {
			t.Errorf("missing base flag %q in args: %v", want, args)
		}
	}
}

func TestBuildArgs_Model(t *testing.T) {
	opts := &Options{Model: "sonnet"}
	args := opts.buildArgs()
	assertFlagValue(t, args, "--model", "sonnet")
}

func TestBuildArgs_PermissionMode(t *testing.T) {
	opts := &Options{PermissionMode: "bypassPermissions"}
	args := opts.buildArgs()
	assertFlagValue(t, args, "--permission-mode", "bypassPermissions")
}

func TestBuildArgs_BooleanFlags(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		flag string
	}{
		{"dangerously-skip-permissions", Options{DangerouslySkipPermissions: true}, "--dangerously-skip-permissions"},
		{"include-partial-messages", Options{IncludePartialMessages: true}, "--include-partial-messages"},
		{"no-session-persistence", Options{NoSessionPersistence: true}, "--no-session-persistence"},
		{"bare", Options{Bare: true}, "--bare"},
		{"continue", Options{Continue: true}, "--continue"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.opts.buildArgs()
			if !slices.Contains(args, tt.flag) {
				t.Errorf("expected flag %q in args: %v", tt.flag, args)
			}
		})
	}
}

func TestBuildArgs_BooleanFlagsOmittedWhenFalse(t *testing.T) {
	opts := &Options{}
	args := opts.buildArgs()

	for _, flag := range []string{
		"--dangerously-skip-permissions", "--include-partial-messages",
		"--no-session-persistence", "--bare", "--continue",
	} {
		if slices.Contains(args, flag) {
			t.Errorf("flag %q should not be present when false: %v", flag, args)
		}
	}
}

func TestBuildArgs_RepeatableFlags(t *testing.T) {
	opts := &Options{
		AllowedTools:    []string{"Read", "Grep"},
		DisallowedTools: []string{"Bash"},
		AdditionalDirs:  []string{"/tmp/a", "/tmp/b"},
		PluginDirs:      []string{"/plugins/a"},
		McpConfigs:      []string{"config1.json", "config2.json"},
	}
	args := opts.buildArgs()

	assertRepeatedFlag(t, args, "--allowed-tools", []string{"Read", "Grep"})
	assertRepeatedFlag(t, args, "--disallowed-tools", []string{"Bash"})
	assertRepeatedFlag(t, args, "--add-dir", []string{"/tmp/a", "/tmp/b"})
	assertRepeatedFlag(t, args, "--plugin-dir", []string{"/plugins/a"})
	assertRepeatedFlag(t, args, "--mcp-config", []string{"config1.json", "config2.json"})
}

func TestBuildArgs_SystemPrompt(t *testing.T) {
	opts := &Options{SystemPrompt: "You are a scanner"}
	args := opts.buildArgs()
	assertFlagValue(t, args, "--system-prompt", "You are a scanner")
}

func TestBuildArgs_AppendSystemPrompt(t *testing.T) {
	opts := &Options{AppendSystemPrompt: "Extra instructions"}
	args := opts.buildArgs()
	assertFlagValue(t, args, "--append-system-prompt", "Extra instructions")
}

func TestBuildArgs_McpConfigJSON(t *testing.T) {
	opts := &Options{McpConfigJSON: `{"server":{"command":"test"}}`}
	args := opts.buildArgs()
	assertFlagValue(t, args, "--mcp-config", `{"server":{"command":"test"}}`)
}

func TestBuildArgs_MaxTurns(t *testing.T) {
	opts := &Options{MaxTurns: 300}
	args := opts.buildArgs()
	assertFlagValue(t, args, "--max-turns", "300")
}

func TestBuildArgs_MaxTurnsOmittedWhenZero(t *testing.T) {
	opts := &Options{MaxTurns: 0}
	args := opts.buildArgs()
	if slices.Contains(args, "--max-turns") {
		t.Error("--max-turns should not be present when 0")
	}
}

func TestBuildArgs_MaxBudgetUSD(t *testing.T) {
	opts := &Options{MaxBudgetUSD: 5.50}
	args := opts.buildArgs()
	assertFlagValue(t, args, "--max-budget-usd", "5.50")
}

func TestBuildArgs_Effort(t *testing.T) {
	opts := &Options{Effort: "high"}
	args := opts.buildArgs()
	assertFlagValue(t, args, "--effort", "high")
}

func TestBuildArgs_SettingSources(t *testing.T) {
	// nil = omitted
	opts := &Options{}
	args := opts.buildArgs()
	if slices.Contains(args, "--setting-sources") {
		t.Error("--setting-sources should not be present when nil")
	}

	// empty string = pass empty value
	empty := ""
	opts = &Options{SettingSources: &empty}
	args = opts.buildArgs()
	assertFlagValue(t, args, "--setting-sources", "")
}

func TestBuildArgs_Resume(t *testing.T) {
	opts := &Options{Resume: "session-abc123"}
	args := opts.buildArgs()
	assertFlagValue(t, args, "--resume", "session-abc123")
}

func TestBuildArgs_SessionID(t *testing.T) {
	opts := &Options{SessionID: "550e8400-e29b-41d4-a716-446655440000"}
	args := opts.buildArgs()
	assertFlagValue(t, args, "--session-id", "550e8400-e29b-41d4-a716-446655440000")
}

func TestBuildArgs_SessionID_OverridesNoSessionPersistence(t *testing.T) {
	// When SessionID is set, --no-session-persistence must NOT be emitted
	// even if NoSessionPersistence is true.
	opts := &Options{
		SessionID:            "550e8400-e29b-41d4-a716-446655440000",
		NoSessionPersistence: true,
	}
	args := opts.buildArgs()
	assertFlagValue(t, args, "--session-id", "550e8400-e29b-41d4-a716-446655440000")
	if slices.Contains(args, "--no-session-persistence") {
		t.Error("--no-session-persistence should not be present when SessionID is set")
	}
}

func TestBuildArgs_AgentsJSON(t *testing.T) {
	opts := &Options{AgentsJSON: `{"reviewer":{"description":"Reviews code","prompt":"You are a reviewer"}}`}
	args := opts.buildArgs()
	assertFlagValue(t, args, "--agents", opts.AgentsJSON)
}

func TestBuildArgs_McpConfigsAndMcpConfigJSON(t *testing.T) {
	// Both McpConfigJSON and McpConfigs should produce --mcp-config entries
	opts := &Options{
		McpConfigJSON: `{"inline":"config"}`,
		McpConfigs:    []string{"file.json"},
	}
	args := opts.buildArgs()

	values := collectFlagValues(args, "--mcp-config")
	if len(values) != 2 {
		t.Fatalf("expected 2 --mcp-config entries, got %d: %v", len(values), values)
	}
	if values[0] != `{"inline":"config"}` {
		t.Errorf("first --mcp-config: got %q, want inline JSON", values[0])
	}
	if values[1] != "file.json" {
		t.Errorf("second --mcp-config: got %q, want file.json", values[1])
	}
}

func TestBuildArgs_FullScanner(t *testing.T) {
	// Simulate the full scanner configuration from buildSDKOptions
	opts := &Options{
		Model:                      "sonnet",
		PermissionMode:             "bypassPermissions",
		DangerouslySkipPermissions: true,
		IncludePartialMessages:     true,
		NoSessionPersistence:       true,
		DisallowedTools:            []string{"AskUserQuestion", "EnterWorktree"},
		AdditionalDirs:             []string{"/source/path"},
		MaxTurns:                   300,
		Effort:                     "medium",
	}
	args := opts.buildArgs()

	// Verify key flags are present
	for _, flag := range []string{
		"--print", "--model", "--permission-mode", "--dangerously-skip-permissions",
		"--include-partial-messages", "--no-session-persistence",
		"--max-turns", "--effort",
	} {
		if !slices.Contains(args, flag) {
			t.Errorf("missing flag %q in scanner config args", flag)
		}
	}
}

// --- Helper builders ---

func TestBuildMcpConfigJSON(t *testing.T) {
	servers := map[string]any{
		"playwright": McpStdioServer{
			Command: "npx",
			Args:    []string{"-y", "@anthropic-ai/mcp-server-playwright"},
		},
		"custom": McpHTTPServer{
			Type: "http",
			URL:  "http://localhost:8080/mcp",
		},
	}

	result, err := BuildMcpConfigJSON(servers)
	if err != nil {
		t.Fatalf("BuildMcpConfigJSON failed: %v", err)
	}
	if result == "" {
		t.Fatal("expected non-empty JSON")
	}

	// Verify it's valid JSON
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if _, ok := parsed["playwright"]; !ok {
		t.Error("missing 'playwright' key in JSON output")
	}
	if _, ok := parsed["custom"]; !ok {
		t.Error("missing 'custom' key in JSON output")
	}
}

func TestBuildMcpConfigJSON_Empty(t *testing.T) {
	result, err := BuildMcpConfigJSON(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty string for nil servers, got %q", result)
	}
}

func TestBuildAgentsJSON(t *testing.T) {
	agents := map[string]AgentDefinition{
		"reviewer": {
			Description: "Reviews code for security issues",
			Prompt:      "You are a security reviewer",
			Model:       "opus",
		},
		"scanner": {
			Description:     "Scans for vulnerabilities",
			Prompt:          "You are a scanner",
			DisallowedTools: []string{"Edit", "Write"},
		},
	}

	result, err := BuildAgentsJSON(agents)
	if err != nil {
		t.Fatalf("BuildAgentsJSON failed: %v", err)
	}

	var parsed map[string]AgentDefinition
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if parsed["reviewer"].Model != "opus" {
		t.Errorf("reviewer model: got %q, want opus", parsed["reviewer"].Model)
	}
	if len(parsed["scanner"].DisallowedTools) != 2 {
		t.Errorf("scanner disallowed tools: got %v, want [Edit Write]", parsed["scanner"].DisallowedTools)
	}
}

func TestBuildAgentsJSON_Empty(t *testing.T) {
	result, err := BuildAgentsJSON(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty string for nil agents, got %q", result)
	}
}

// --- test helpers ---

func assertFlagValue(t *testing.T, args []string, flag, value string) {
	t.Helper()
	for i, a := range args {
		if a == flag {
			if i+1 >= len(args) {
				t.Errorf("flag %q found at end of args with no value", flag)
				return
			}
			if args[i+1] != value {
				t.Errorf("flag %q value: got %q, want %q", flag, args[i+1], value)
			}
			return
		}
	}
	t.Errorf("flag %q not found in args: %v", flag, args)
}

func assertRepeatedFlag(t *testing.T, args []string, flag string, wantValues []string) {
	t.Helper()
	values := collectFlagValues(args, flag)
	if len(values) != len(wantValues) {
		t.Errorf("flag %q: got %d values %v, want %d values %v", flag, len(values), values, len(wantValues), wantValues)
		return
	}
	for i, v := range values {
		if v != wantValues[i] {
			t.Errorf("flag %q value[%d]: got %q, want %q", flag, i, v, wantValues[i])
		}
	}
}

func collectFlagValues(args []string, flag string) []string {
	var values []string
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			values = append(values, args[i+1])
		}
	}
	return values
}
