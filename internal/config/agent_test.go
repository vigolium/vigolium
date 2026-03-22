package config

import "testing"

func TestDefaultAgentConfig(t *testing.T) {
	cfg := DefaultAgentConfig()

	if cfg.DefaultAgent != "claude-sdk" {
		t.Errorf("expected default_agent=claude-sdk, got %s", cfg.DefaultAgent)
	}
	if len(cfg.Backends) != 9 {
		t.Errorf("expected 9 agents, got %d", len(cfg.Backends))
	}

	// Check all expected agents exist
	for _, name := range []string{"claude-sdk", "claude", "claude-cli", "codex", "opencode", "opencode-cli", "gemini", "gemini-cli", "cursor"} {
		def, ok := cfg.Backends[name]
		if !ok {
			t.Errorf("expected agent %q to exist", name)
			continue
		}
		if def.Command == "" {
			t.Errorf("agent %q has empty command", name)
		}
	}
}

func TestAgentDef_EffectiveProtocol(t *testing.T) {
	tests := []struct {
		protocol string
		want     string
	}{
		{"", "pipe"},
		{"pipe", "pipe"},
		{"acp", "acp"},
	}
	for _, tt := range tests {
		def := AgentDef{Command: "test", Protocol: tt.protocol}
		if got := def.EffectiveProtocol(); got != tt.want {
			t.Errorf("EffectiveProtocol(%q) = %q, want %q", tt.protocol, got, tt.want)
		}
	}
}

func TestDefaultAgentConfig_Protocols(t *testing.T) {
	cfg := DefaultAgentConfig()

	acpAgents := []string{"claude", "codex", "opencode", "gemini", "cursor"}
	for _, name := range acpAgents {
		def := cfg.Backends[name]
		if def.EffectiveProtocol() != "acp" {
			t.Errorf("%s protocol = %q, want %q", name, def.EffectiveProtocol(), "acp")
		}
	}

	pipeAgents := []string{"claude-cli", "opencode-cli", "gemini-cli"}
	for _, name := range pipeAgents {
		def := cfg.Backends[name]
		if def.EffectiveProtocol() != "pipe" {
			t.Errorf("%s protocol = %q, want %q", name, def.EffectiveProtocol(), "pipe")
		}
	}
}

func TestAgentConfig_StreamEnabled(t *testing.T) {
	t.Run("nil defaults to true", func(t *testing.T) {
		cfg := &AgentConfig{}
		if !cfg.StreamEnabled() {
			t.Error("StreamEnabled() = false, want true when Stream is nil")
		}
	})

	t.Run("explicit true", func(t *testing.T) {
		v := true
		cfg := &AgentConfig{Stream: &v}
		if !cfg.StreamEnabled() {
			t.Error("StreamEnabled() = false, want true")
		}
	})

	t.Run("explicit false", func(t *testing.T) {
		v := false
		cfg := &AgentConfig{Stream: &v}
		if cfg.StreamEnabled() {
			t.Error("StreamEnabled() = true, want false")
		}
	})

	t.Run("default config has streaming enabled", func(t *testing.T) {
		cfg := DefaultAgentConfig()
		if !cfg.StreamEnabled() {
			t.Error("DefaultAgentConfig().StreamEnabled() = false, want true")
		}
	})
}

func TestAgentConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  AgentConfig
		wantErr bool
	}{
		{
			name:    "valid default config",
			config:  *DefaultAgentConfig(),
			wantErr: false,
		},
		{
			name: "empty default_agent",
			config: AgentConfig{
				DefaultAgent: "",
				Backends: map[string]AgentDef{
					"claude": {Command: "claude", Args: []string{"-p"}},
				},
			},
			wantErr: true,
		},
		{
			name: "default_agent not in map",
			config: AgentConfig{
				DefaultAgent: "missing",
				Backends: map[string]AgentDef{
					"claude": {Command: "claude", Args: []string{"-p"}},
				},
			},
			wantErr: true,
		},
		{
			name: "agent with empty command",
			config: AgentConfig{
				DefaultAgent: "bad",
				Backends: map[string]AgentDef{
					"bad": {Command: "", Args: nil},
				},
			},
			wantErr: true,
		},
		{
			name: "single valid agent",
			config: AgentConfig{
				DefaultAgent: "custom",
				Backends: map[string]AgentDef{
					"custom": {Command: "my-agent", Args: []string{"run"}},
				},
			},
			wantErr: false,
		},
		{
			name: "valid acp protocol",
			config: AgentConfig{
				DefaultAgent: "claude",
				Backends: map[string]AgentDef{
					"claude": {Command: "claude", Protocol: "acp"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid pipe protocol",
			config: AgentConfig{
				DefaultAgent: "claude",
				Backends: map[string]AgentDef{
					"claude": {Command: "claude", Protocol: "pipe"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid protocol",
			config: AgentConfig{
				DefaultAgent: "claude",
				Backends: map[string]AgentDef{
					"claude": {Command: "claude", Protocol: "grpc"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
