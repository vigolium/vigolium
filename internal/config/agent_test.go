package config

import (
	"strings"
	"testing"
)

func TestDefaultAgentConfig(t *testing.T) {
	cfg := DefaultAgentConfig()

	if cfg.DefaultAgent != "olium" {
		t.Errorf("expected default_agent=olium, got %s", cfg.DefaultAgent)
	}
	if cfg.Olium.Provider == "" {
		t.Error("expected agent.olium.provider to be set by default")
	}
	if cfg.TemplatesDir == "" {
		t.Error("expected agent.templates_dir to have a default")
	}
	if cfg.SessionsDir == "" {
		t.Error("expected agent.sessions_dir to have a default")
	}
}

func TestDefaultAgentConfig_Olium(t *testing.T) {
	cfg := DefaultAgentConfig()

	if cfg.Olium.Provider != "openai-compatible" {
		t.Errorf("expected agent.olium.provider=openai-compatible, got %q", cfg.Olium.Provider)
	}
	if cfg.Olium.MaxTurns != 32 {
		t.Errorf("expected agent.olium.max_turns=32, got %d", cfg.Olium.MaxTurns)
	}
	if cfg.Olium.MaxTokens != 1000000 {
		t.Errorf("expected agent.olium.max_tokens=1000000, got %d", cfg.Olium.MaxTokens)
	}
	if cfg.Olium.CacheSize != 1024 {
		t.Errorf("expected agent.olium.cache_size=1024, got %d", cfg.Olium.CacheSize)
	}
	if cfg.Olium.ReasoningEffort != "medium" {
		t.Errorf("expected agent.olium.reasoning_effort=medium, got %q", cfg.Olium.ReasoningEffort)
	}
	if cfg.Olium.Model != "gemma4:latest" {
		t.Errorf("expected agent.olium.model=gemma4:latest, got %q", cfg.Olium.Model)
	}
	if cfg.Olium.OAuthCredPath != "~/.codex/auth.json" {
		t.Errorf("expected agent.olium.oauth_cred_path=~/.codex/auth.json, got %q", cfg.Olium.OAuthCredPath)
	}

	// The olium block must flatten into agent.olium.* keys so
	// `vigolium config ls olium` surfaces them. Every documented field — even
	// the empty-by-default ones (llm_api_key, system_prompt) — must be
	// listed so users can discover what knobs exist without reading source.
	settings := &Settings{Agent: *cfg}
	entries := FlattenSettings(settings)
	oliumKeys := map[string]bool{}
	for _, e := range entries {
		if strings.HasPrefix(e.Key, "agent.olium.") {
			oliumKeys[strings.TrimPrefix(e.Key, "agent.olium.")] = true
		}
	}
	if len(oliumKeys) == 0 {
		t.Fatal("FlattenSettings produced no agent.olium.* keys; `vigolium config ls olium` will be empty")
	}
	for _, want := range []string{
		"provider", "model", "oauth_cred_path", "oauth_token", "llm_api_key",
		"google_cloud_project", "google_cloud_location",
		"reasoning_effort", "system_prompt", "max_tokens", "temperature",
		"max_turns", "cache_size",
	} {
		if !oliumKeys[want] {
			t.Errorf("expected agent.olium.%s to appear in flattened config (visible in `vigolium config ls olium`)", want)
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

func TestBrowserConfig_IsEnabled(t *testing.T) {
	t.Run("nil defaults to false", func(t *testing.T) {
		cfg := &BrowserConfig{}
		if cfg.IsEnabled() {
			t.Error("IsEnabled() = true, want false when Enable is nil")
		}
	})

	t.Run("explicit true", func(t *testing.T) {
		v := true
		cfg := &BrowserConfig{Enable: &v}
		if !cfg.IsEnabled() {
			t.Error("IsEnabled() = false, want true")
		}
	})

	t.Run("explicit false", func(t *testing.T) {
		v := false
		cfg := &BrowserConfig{Enable: &v}
		if cfg.IsEnabled() {
			t.Error("IsEnabled() = true, want false")
		}
	})
}

func TestBrowserConfig_EffectiveBinaryPath(t *testing.T) {
	t.Run("empty defaults to agent-browser", func(t *testing.T) {
		cfg := &BrowserConfig{}
		if got := cfg.EffectiveBinaryPath(); got != "agent-browser" {
			t.Errorf("EffectiveBinaryPath() = %q, want agent-browser", got)
		}
	})

	t.Run("custom path", func(t *testing.T) {
		cfg := &BrowserConfig{BinaryPath: "/usr/local/bin/agent-browser"}
		if got := cfg.EffectiveBinaryPath(); got != "/usr/local/bin/agent-browser" {
			t.Errorf("EffectiveBinaryPath() = %q, want /usr/local/bin/agent-browser", got)
		}
	})
}

func TestAgentConfig_BrowserDefault(t *testing.T) {
	cfg := DefaultAgentConfig()
	if !cfg.Browser.IsEnabled() {
		t.Error("DefaultAgentConfig browser should be enabled by default")
	}
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
			},
			wantErr: true,
		},
		{
			name: "custom default_agent name",
			config: AgentConfig{
				DefaultAgent: "olium",
			},
			wantErr: false,
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
