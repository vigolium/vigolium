package olium

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

// TestResolveProviderOpenAICompatibleModel guards the openai-compatible model
// resolution: an empty agent.olium.model must fall back to
// custom_provider.model_id, an explicit model must win over it, and both empty
// must error with an actionable message. This is the regression test for the
// default-collision bug where DefaultOliumConfig shipped Model="gemma4:latest",
// which shadowed custom_provider.model_id (model was neither "" nor the
// DefaultModel sentinel, so the fallback never fired).
func TestResolveProviderOpenAICompatibleModel(t *testing.T) {
	const baseURL = "http://localhost:11434/v1"

	cases := []struct {
		name        string
		model       string // opts.Model (agent.olium.model / --model)
		customModel string // opts.CustomModelID (custom_provider.model_id)
		wantModel   string
		wantErr     string // substring; empty = expect nil
	}{
		{
			name:        "empty model falls back to custom_provider.model_id",
			model:       "",
			customModel: "qwen3.6:latest",
			wantModel:   "qwen3.6:latest",
		},
		{
			name:        "DefaultModel sentinel falls back to custom_provider.model_id",
			model:       DefaultModel,
			customModel: "qwen3.6:latest",
			wantModel:   "qwen3.6:latest",
		},
		{
			name:        "explicit model wins over custom_provider.model_id",
			model:       "llama3.3:70b",
			customModel: "qwen3.6:latest",
			wantModel:   "llama3.3:70b",
		},
		{
			name:        "no model anywhere errors",
			model:       "",
			customModel: "",
			wantErr:     "model is required",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, providerName, gotModel, err := resolveProvider(Options{
				Provider:      "openai-compatible",
				Model:         c.model,
				CustomBaseURL: baseURL,
				CustomModelID: c.customModel,
			})
			if c.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (model=%q)", c.wantErr, gotModel)
				}
				if !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("error %q does not contain %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if providerName != "openai-compatible" {
				t.Errorf("provider name = %q, want openai-compatible", providerName)
			}
			if gotModel != c.wantModel {
				t.Errorf("resolved model = %q, want %q", gotModel, c.wantModel)
			}
		})
	}
}

// TestCanonicalProviderName covers alias normalization: the friendly
// anthropic-claude-cli synonym must collapse to the canonical anthropic-cli,
// input is trimmed and lowercased, empty passes through empty (so callers fall
// back to auto-detect), and unknown names pass through verbatim so
// resolveProvider can surface the exact typo.
func TestCanonicalProviderName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"anthropic-claude-cli", "anthropic-cli"},
		{"  Anthropic-Claude-CLI  ", "anthropic-cli"},
		{"anthropic-cli", "anthropic-cli"},
		{"openai-codex-oauth", "openai-codex-oauth"},
		{"", ""},
		{"anthropic-typo", "anthropic-typo"},
	}
	for _, c := range cases {
		if got := CanonicalProviderName(c.in); got != c.want {
			t.Errorf("CanonicalProviderName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestResolveProviderAnthropicCLIAlias asserts the anthropic-claude-cli alias
// routes into the anthropic-cli branch of resolveProvider. The claude binary
// may or may not be present in the test environment, so accept either outcome
// as long as it lands on the canonical provider: a successful build reports
// providerName=="anthropic-cli", while a missing binary errors with the
// canonical "anthropic-cli:" prefix (never a leaked alias or "unknown provider").
func TestResolveProviderAnthropicCLIAlias(t *testing.T) {
	_, providerName, _, err := resolveProvider(Options{Provider: "anthropic-claude-cli"})
	if err != nil {
		if !strings.HasPrefix(err.Error(), "anthropic-cli:") {
			t.Fatalf("alias resolution error = %q, want an \"anthropic-cli:\" error (alias should map to the anthropic-cli branch)", err)
		}
		return
	}
	if providerName != "anthropic-cli" {
		t.Errorf("alias resolved provider name = %q, want anthropic-cli", providerName)
	}
}

// TestResolveProviderClaudeSDKBridge asserts the anthropic-claude-sdk-bridge
// provider resolves through newClaudeSDKBridgeProvider. An explicit bridge
// binary that exists is used verbatim; the resolved provider name is stable and
// the model passes through (empty stays empty so the bridge picks its default).
func TestResolveProviderClaudeSDKBridge(t *testing.T) {
	// A guaranteed-present executable stands in for vigolium-audit so binary
	// resolution succeeds without the embedded blob or a PATH install.
	fakeBin := "/bin/sh"

	t.Run("explicit binary, empty model", func(t *testing.T) {
		prov, name, model, err := resolveProvider(Options{
			Provider:     "anthropic-claude-sdk-bridge",
			BridgeBinary: fakeBin,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "anthropic-claude-sdk-bridge" {
			t.Errorf("provider name = %q, want anthropic-claude-sdk-bridge", name)
		}
		if model != "" {
			t.Errorf("empty model should stay empty (bridge default), got %q", model)
		}
		if prov == nil || prov.Name() != "claude-sdk-bridge" {
			t.Errorf("resolved provider = %v, want claude-sdk-bridge", prov)
		}
	})

	t.Run("DefaultModel sentinel is cleared", func(t *testing.T) {
		_, _, model, err := resolveProvider(Options{
			Provider:     "anthropic-claude-sdk-bridge",
			BridgeBinary: fakeBin,
			Model:        DefaultModel,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if model != "" {
			t.Errorf("DefaultModel sentinel should resolve to empty, got %q", model)
		}
	})

	t.Run("explicit model passes through", func(t *testing.T) {
		_, _, model, err := resolveProvider(Options{
			Provider:     "anthropic-claude-sdk-bridge",
			BridgeBinary: fakeBin,
			Model:        "opus",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if model != "opus" {
			t.Errorf("model = %q, want opus", model)
		}
	})

	t.Run("bad explicit binary errors", func(t *testing.T) {
		_, _, _, err := resolveProvider(Options{
			Provider:     "anthropic-claude-sdk-bridge",
			BridgeBinary: "/nonexistent/vigolium-audit-xyz",
		})
		if err == nil {
			t.Fatal("expected an error for a missing bridge binary")
		}
		if !strings.Contains(err.Error(), "anthropic-claude-sdk-bridge") {
			t.Errorf("error %q should name the provider", err)
		}
	})
}

// TestDefaultConfigDoesNotShadowCustomModelID is the end-to-end guard for the
// original bug report: with the shipped default config, a user who changes ONLY
// custom_provider.model_id (and never touches agent.olium.model) must have that
// model honored. It starts from config.DefaultOliumConfig() — the real shipped
// default — and wires it into olium.Options exactly as pkg/cli/agent_olium.go
// does when no CLI flags are passed.
//
// This catches the root cause that TestResolveProviderOpenAICompatibleModel
// cannot: if someone re-introduces a non-empty Model default in
// DefaultOliumConfig() (e.g. Model: "gemma4:latest"), that value would shadow
// the distinct model_id here and the resolved model would come back wrong.
func TestDefaultConfigDoesNotShadowCustomModelID(t *testing.T) {
	// Shipped default config, then the user's scenario: change only model_id.
	cfg := config.DefaultOliumConfig()
	cfg.CustomProvider.ModelID = "qwen3.6:latest"

	// Sanity-check the precondition that makes the test meaningful: the default
	// model must NOT equal the model_id we set, otherwise the assertion below
	// would pass even if Model were shadowing model_id.
	if cfg.Model == cfg.CustomProvider.ModelID {
		t.Fatalf("test precondition broken: default Model %q must differ from the model_id under test", cfg.Model)
	}

	// Mirror pkg/cli/agent_olium.go Options wiring with no CLI flags set, i.e.
	// firstNonEmptyString("", cfg.X) collapses to cfg.X.
	opts := Options{
		Provider:      cfg.Provider,
		Model:         cfg.Model, // no --model flag
		CustomBaseURL: cfg.CustomProvider.BaseURL,
		CustomModelID: cfg.CustomProvider.ModelID,
		CustomAPIKey:  cfg.CustomProvider.APIKey,
	}

	_, providerName, gotModel, err := resolveProvider(opts)
	if err != nil {
		t.Fatalf("unexpected error resolving default openai-compatible config: %v", err)
	}
	if providerName != "openai-compatible" {
		t.Fatalf("default provider = %q, want openai-compatible", providerName)
	}
	if gotModel != "qwen3.6:latest" {
		t.Errorf("resolved model = %q, want %q — agent.olium.model is shadowing custom_provider.model_id (check DefaultOliumConfig().Model is empty)", gotModel, "qwen3.6:latest")
	}
}

// TestResolveProviderOpenAIResponses asserts the openai-responses provider
// resolves to the public Responses driver: it uses the same OpenAI key
// resolution as openai-api-key (explicit key or $OPENAI_API_KEY), defaults the
// model to gpt-5.5, and errors actionably when no key is available.
func TestResolveProviderOpenAIResponses(t *testing.T) {
	t.Run("explicit key resolves, default model", func(t *testing.T) {
		prov, name, model, err := resolveProvider(Options{
			Provider:  "openai-responses",
			LLMAPIKey: "sk-proj-test",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "openai-responses" {
			t.Errorf("provider name = %q, want openai-responses", name)
		}
		if model != "gpt-5.5" {
			t.Errorf("default model = %q, want gpt-5.5", model)
		}
		if prov == nil || prov.Name() != "openai-responses" {
			t.Errorf("resolved provider = %v, want openai-responses driver", prov)
		}
	})

	t.Run("no key anywhere errors", func(t *testing.T) {
		t.Setenv("OPENAI_API_KEY", "")
		_, _, _, err := resolveProvider(Options{Provider: "openai-responses"})
		if err == nil || !strings.Contains(err.Error(), "no key") {
			t.Fatalf("expected a \"no key\" error, got %v", err)
		}
	})
}

// TestResolveProviderAnthropicCompatible asserts the anthropic-compatible
// provider requires a base_url + model and otherwise resolves to the Messages
// driver reporting its own provider name.
func TestResolveProviderAnthropicCompatible(t *testing.T) {
	t.Run("base_url + model resolves", func(t *testing.T) {
		prov, name, model, err := resolveProvider(Options{
			Provider:      "anthropic-compatible",
			CustomBaseURL: "https://gw.example.com/v1",
			Model:         "claude-opus-4-7",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "anthropic-compatible" {
			t.Errorf("provider name = %q, want anthropic-compatible", name)
		}
		if model != "claude-opus-4-7" {
			t.Errorf("model = %q, want claude-opus-4-7", model)
		}
		if prov == nil || prov.Name() != "anthropic-compatible" {
			t.Errorf("resolved provider = %v, want anthropic-compatible driver", prov)
		}
	})

	t.Run("model falls back to custom_provider.model_id", func(t *testing.T) {
		_, _, model, err := resolveProvider(Options{
			Provider:      "anthropic-compatible",
			CustomBaseURL: "https://gw.example.com/v1",
			CustomModelID: "claude-3-7-sonnet",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if model != "claude-3-7-sonnet" {
			t.Errorf("model = %q, want claude-3-7-sonnet (custom_provider.model_id fallback)", model)
		}
	})

	t.Run("missing base_url errors", func(t *testing.T) {
		_, _, _, err := resolveProvider(Options{Provider: "anthropic-compatible", Model: "claude-opus-4-7"})
		if err == nil || !strings.Contains(err.Error(), "base_url is required") {
			t.Fatalf("expected a base_url error, got %v", err)
		}
	})

	t.Run("missing model errors", func(t *testing.T) {
		_, _, _, err := resolveProvider(Options{Provider: "anthropic-compatible", CustomBaseURL: "https://gw.example.com/v1"})
		if err == nil || !strings.Contains(err.Error(), "model is required") {
			t.Fatalf("expected a model error, got %v", err)
		}
	})
}
