package llm

import (
	"context"
	"fmt"
	"os"

	"github.com/vigolium/vigolium/internal/config"
)

// Client is the interface all LLM backends implement.
type Client interface {
	Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
}

// Error types for callers to inspect.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("LLM API error (status %d): %s", e.StatusCode, e.Body)
}

// NewClient creates a Client from cfg.
// Returns an error if the provider is unknown or the API key is missing.
func NewClient(cfg config.LLMConfig) (Client, error) {
	apiKey, err := resolveAPIKey(cfg)
	if err != nil {
		return nil, err
	}

	switch cfg.Provider {
	case "anthropic", "":
		model := cfg.Model
		if model == "" {
			model = "claude-sonnet-4-20250514"
		}
		return &AnthropicClient{
			apiKey:      apiKey,
			model:       model,
			maxTokens:   effectiveMaxTokens(cfg.MaxTokens),
			temperature: cfg.Temperature,
		}, nil

	case "openai":
		model := cfg.Model
		if model == "" {
			model = "gpt-4o"
		}
		baseURL := cfg.BaseURL
		if baseURL == "" {
			baseURL = "https://api.openai.com/v1"
		}
		return &OpenAIClient{
			apiKey:      apiKey,
			model:       model,
			baseURL:     baseURL,
			maxTokens:   effectiveMaxTokens(cfg.MaxTokens),
			temperature: cfg.Temperature,
		}, nil

	default:
		return nil, fmt.Errorf("unknown LLM provider %q (must be \"anthropic\" or \"openai\")", cfg.Provider)
	}
}

// NewCachedClient wraps a Client with LRU caching.
// If cfg.CacheSize is 0 caching is disabled and c is returned as-is.
func NewCachedClient(c Client, cfg config.LLMConfig) (Client, error) {
	if cfg.CacheSize == 0 {
		return c, nil
	}
	size := cfg.CacheSize
	ttl := cfg.CacheTTL
	if ttl == 0 {
		ttl = 300
	}
	return newCachedClient(c, size, ttl)
}

func resolveAPIKey(cfg config.LLMConfig) (string, error) {
	if cfg.APIKey != "" {
		return cfg.APIKey, nil
	}
	envVar := cfg.APIKeyEnv
	if envVar == "" {
		switch cfg.Provider {
		case "openai":
			envVar = "OPENAI_API_KEY"
		default:
			envVar = "ANTHROPIC_API_KEY"
		}
	}
	key := os.Getenv(envVar)
	if key == "" {
		return "", fmt.Errorf("LLM API key not set: set %s env var or configure api_key in llm config", envVar)
	}
	return key, nil
}

func effectiveMaxTokens(n int) int {
	if n <= 0 {
		return 4096
	}
	return n
}
