package agent

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

func TestInferProvider(t *testing.T) {
	tests := []struct {
		name    string
		def     config.AgentDef
		want    acpProvider
	}{
		{
			name: "claude via npx",
			def:  config.AgentDef{Command: "npx", Args: []string{"-y", "@zed-industries/claude-agent-acp@latest"}},
			want: providerClaude,
		},
		{
			name: "claude via bunx",
			def:  config.AgentDef{Command: "bunx", Args: []string{"-y", "@zed-industries/claude-agent-acp@latest"}},
			want: providerClaude,
		},
		{
			name: "claude direct",
			def:  config.AgentDef{Command: "claude"},
			want: providerClaude,
		},
		{
			name: "gemini",
			def:  config.AgentDef{Command: "gemini", Args: []string{"--experimental-acp"}},
			want: providerGemini,
		},
		{
			name: "opencode",
			def:  config.AgentDef{Command: "opencode", Args: []string{"acp"}},
			want: providerOpenCode,
		},
		{
			name: "codex",
			def:  config.AgentDef{Command: "codex", Args: []string{"app-server"}},
			want: providerCodex,
		},
		{
			name: "cursor",
			def:  config.AgentDef{Command: "cursor", Args: []string{"acp"}},
			want: providerCursor,
		},
		{
			name: "unknown command",
			def:  config.AgentDef{Command: "my-custom-agent"},
			want: providerUnknown,
		},
		{
			name: "npx without claude package",
			def:  config.AgentDef{Command: "npx", Args: []string{"-y", "some-other-package"}},
			want: providerUnknown,
		},
		{
			name: "claude substring in command",
			def:  config.AgentDef{Command: "/usr/local/bin/claude-code"},
			want: providerClaude,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferProvider(tt.def)
			if got != tt.want {
				t.Errorf("inferProvider() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestBuildProviderArgs_Gemini(t *testing.T) {
	def := config.AgentDef{
		Command: "gemini",
		Args:    []string{"--experimental-acp"},
		Model:   "gemini-2.5-pro",
	}
	got := buildProviderArgs(def)
	want := []string{"-m", "gemini-2.5-pro", "--experimental-acp"}
	assertStrSlice(t, got, want)
}

func TestBuildProviderArgs_Cursor(t *testing.T) {
	def := config.AgentDef{
		Command: "cursor",
		Args:    []string{"acp"},
		Model:   "claude-sonnet-4-5",
	}
	got := buildProviderArgs(def)
	want := []string{"--model", "claude-sonnet-4-5", "acp"}
	assertStrSlice(t, got, want)
}

func TestBuildProviderArgs_Codex(t *testing.T) {
	def := config.AgentDef{
		Command: "codex",
		Args:    []string{"app-server"},
		Model:   "o3",
	}
	got := buildProviderArgs(def)
	want := []string{"--model", "o3", "app-server"}
	assertStrSlice(t, got, want)
}

func TestBuildProviderArgs_Claude_Unchanged(t *testing.T) {
	def := config.AgentDef{
		Command: "npx",
		Args:    []string{"-y", "@zed-industries/claude-agent-acp@latest"},
		Model:   "opus",
	}
	got := buildProviderArgs(def)
	want := []string{"-y", "@zed-industries/claude-agent-acp@latest"}
	assertStrSlice(t, got, want)
}

func TestBuildProviderArgs_NoModel(t *testing.T) {
	def := config.AgentDef{
		Command: "gemini",
		Args:    []string{"--experimental-acp"},
	}
	got := buildProviderArgs(def)
	want := []string{"--experimental-acp"}
	assertStrSlice(t, got, want)
}

func TestBuildProviderEnv_OpenCode(t *testing.T) {
	def := config.AgentDef{
		Command: "opencode",
		Args:    []string{"acp"},
		Model:   "anthropic/claude-sonnet-4-5",
		ProviderConfig: &config.ProviderConfig{
			Thinking: &config.ThinkingConfig{
				Enabled:      true,
				BudgetTokens: 32000,
			},
			Permission: config.DefaultPermissionConfig(),
		},
	}
	env := buildProviderEnv(def)
	raw, ok := env["OPENCODE_CONFIG_CONTENT"]
	if !ok {
		t.Fatal("expected OPENCODE_CONFIG_CONTENT to be set")
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Check config.model
	cfgBlock, _ := parsed["config"].(map[string]any)
	if cfgBlock["model"] != "anthropic/claude-sonnet-4-5" {
		t.Errorf("config.model = %v, want anthropic/claude-sonnet-4-5", cfgBlock["model"])
	}

	// Check provider block exists with thinking
	providerBlock, _ := parsed["provider"].(map[string]any)
	if providerBlock == nil {
		t.Fatal("expected provider block")
	}
	anthBlock, _ := providerBlock["anthropic"].(map[string]any)
	if anthBlock == nil {
		t.Fatal("expected provider.anthropic block")
	}
	models, _ := anthBlock["models"].(map[string]any)
	modelEntry, _ := models["claude-sonnet-4-5"].(map[string]any)
	opts, _ := modelEntry["options"].(map[string]any)
	thinking, _ := opts["thinking"].(map[string]any)
	if thinking["type"] != "enabled" {
		t.Errorf("thinking.type = %v, want enabled", thinking["type"])
	}
	if thinking["budgetTokens"] != float64(32000) {
		t.Errorf("thinking.budgetTokens = %v, want 32000", thinking["budgetTokens"])
	}

	// Check permission
	agentBlock, _ := parsed["agent"].(map[string]any)
	buildBlock, _ := agentBlock["build"].(map[string]any)
	permBlock, _ := buildBlock["permission"].(map[string]any)
	for _, key := range []string{"read", "edit", "write", "bash"} {
		if permBlock[key] != "allow" {
			t.Errorf("permission.%s = %v, want allow", key, permBlock[key])
		}
	}
}

func TestBuildProviderEnv_OpenCode_ModelOnly(t *testing.T) {
	def := config.AgentDef{
		Command: "opencode",
		Args:    []string{"acp"},
		Model:   "anthropic/claude-sonnet-4-5",
	}
	env := buildProviderEnv(def)
	raw, ok := env["OPENCODE_CONFIG_CONTENT"]
	if !ok {
		t.Fatal("expected OPENCODE_CONFIG_CONTENT to be set")
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Should have config.model but no provider block (no thinking)
	cfgBlock, _ := parsed["config"].(map[string]any)
	if cfgBlock["model"] != "anthropic/claude-sonnet-4-5" {
		t.Errorf("config.model = %v, want anthropic/claude-sonnet-4-5", cfgBlock["model"])
	}
	if parsed["provider"] != nil {
		t.Error("expected no provider block when thinking is not enabled")
	}
}

func TestBuildProviderEnv_OpenCode_CustomAPI(t *testing.T) {
	def := config.AgentDef{
		Command: "opencode",
		Args:    []string{"acp"},
		Model:   "custom/my-model",
		ProviderConfig: &config.ProviderConfig{
			APIURL: "https://api.example.com",
			APIKey: "sk-test-123",
		},
	}
	env := buildProviderEnv(def)
	raw := env["OPENCODE_CONFIG_CONTENT"]

	var parsed map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	providerBlock, _ := parsed["provider"].(map[string]any)
	customBlock, _ := providerBlock["custom"].(map[string]any)
	if customBlock["npm"] != "@ai-sdk/openai-compatible" {
		t.Errorf("npm = %v, want @ai-sdk/openai-compatible", customBlock["npm"])
	}
	opts, _ := customBlock["options"].(map[string]any)
	if opts["baseURL"] != "https://api.example.com" {
		t.Errorf("baseURL = %v, want https://api.example.com", opts["baseURL"])
	}
	if opts["apiKey"] != "sk-test-123" {
		t.Errorf("apiKey = %v, want sk-test-123", opts["apiKey"])
	}
}

func TestBuildProviderEnv_NonOpenCode(t *testing.T) {
	def := config.AgentDef{
		Command: "gemini",
		Args:    []string{"--experimental-acp"},
		Model:   "gemini-2.5-pro",
		Env:     map[string]string{"FOO": "bar"},
	}
	env := buildProviderEnv(def)
	if _, ok := env["OPENCODE_CONFIG_CONTENT"]; ok {
		t.Error("unexpected OPENCODE_CONFIG_CONTENT for non-opencode provider")
	}
	if env["FOO"] != "bar" {
		t.Errorf("existing env FOO = %v, want bar", env["FOO"])
	}
}

func TestBuildProviderEnv_PreservesExistingEnv(t *testing.T) {
	def := config.AgentDef{
		Command: "opencode",
		Args:    []string{"acp"},
		Model:   "anthropic/claude-sonnet-4-5",
		Env:     map[string]string{"CUSTOM_VAR": "custom_value"},
	}
	env := buildProviderEnv(def)
	if env["CUSTOM_VAR"] != "custom_value" {
		t.Errorf("CUSTOM_VAR = %v, want custom_value", env["CUSTOM_VAR"])
	}
	if _, ok := env["OPENCODE_CONFIG_CONTENT"]; !ok {
		t.Error("expected OPENCODE_CONFIG_CONTENT to be set")
	}
}

func TestInjectArgBefore(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		target string
		flag   string
		value  string
		want   []string
	}{
		{
			name:   "target found",
			args:   []string{"--experimental-acp"},
			target: "--experimental-acp",
			flag:   "-m",
			value:  "model",
			want:   []string{"-m", "model", "--experimental-acp"},
		},
		{
			name:   "target not found",
			args:   []string{"other"},
			target: "missing",
			flag:   "-m",
			value:  "model",
			want:   []string{"-m", "model", "other"},
		},
		{
			name:   "multiple args before target",
			args:   []string{"-y", "pkg", "acp"},
			target: "acp",
			flag:   "--model",
			value:  "test",
			want:   []string{"-y", "pkg", "--model", "test", "acp"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := injectArgBefore(tt.args, tt.target, tt.flag, tt.value)
			assertStrSlice(t, got, tt.want)
		})
	}
}

func TestSplitModelID(t *testing.T) {
	tests := []struct {
		model      string
		wantProv   string
		wantModel  string
	}{
		{"anthropic/claude-sonnet-4-5", "anthropic", "claude-sonnet-4-5"},
		{"openai/gpt-4o", "openai", "gpt-4o"},
		{"my-model", "custom", "my-model"},
		{"", "custom", ""},
	}
	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			prov, model := splitModelID(tt.model)
			if prov != tt.wantProv {
				t.Errorf("provider = %q, want %q", prov, tt.wantProv)
			}
			if model != tt.wantModel {
				t.Errorf("model = %q, want %q", model, tt.wantModel)
			}
		})
	}
}

func TestDefaultPermissionInJSON(t *testing.T) {
	raw := buildOpenCodeConfigJSON("test/model", nil)
	// With nil ProviderConfig, should still have all-allow permissions
	if raw == "{}" {
		t.Fatal("expected non-empty JSON")
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	agentBlock, _ := parsed["agent"].(map[string]any)
	buildBlock, _ := agentBlock["build"].(map[string]any)
	permBlock, _ := buildBlock["permission"].(map[string]any)
	for _, key := range []string{"read", "edit", "write", "bash"} {
		if permBlock[key] != "allow" {
			t.Errorf("permission.%s = %v, want allow", key, permBlock[key])
		}
	}
}

func assertStrSlice(t *testing.T, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
