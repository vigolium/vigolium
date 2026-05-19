package agent

import (
	"context"
	"errors"
	"testing"
)

func TestClassifyOliumError(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sentinel error // nil = expected non-retryable
	}{
		// Rate-limit shapes from various providers
		{"anthropic 429", "anthropic 429: rate_limit_exceeded", errProviderRateLimited},
		{"openai 429", "openai 429: too many requests", errProviderRateLimited},
		{"codex 429", "codex 429: rate limit hit", errProviderRateLimited},
		{"plain rate_limit", "Error: rate_limit reached, retry in 30s", errProviderRateLimited},
		{"too many requests", "got HTTP Too Many Requests from upstream", errProviderRateLimited},
		{"quota mention", "quota exhausted for billing period", errProviderRateLimited},

		// 5xx server errors
		{"anthropic 503", "anthropic 503: overloaded", errProviderServerError},
		{"openai 502", "openai 502: bad gateway", errProviderServerError},
		{"codex 500", "codex 500: internal", errProviderServerError},
		{"cloudflare 524", "anthropic 524: timeout", errProviderServerError},
		{"plain server text", "internal server error from upstream", errProviderServerError},
		{"overloaded", "model is overloaded right now", errProviderServerError},

		// Network errors
		{"connection refused", "Post https://api.anthropic.com/v1/messages: connection refused", errProviderNetwork},
		{"i/o timeout", "Get https://api.openai.com: i/o timeout", errProviderNetwork},
		{"unexpected EOF", "stream ended with unexpected EOF", errProviderNetwork},
		{"no such host", "lookup api.example.com: no such host", errProviderNetwork},
		{"tls handshake", "tls handshake timeout", errProviderNetwork},

		// Non-retryable shapes
		{"401 auth", "anthropic 401: invalid api key", nil},
		{"403 forbidden", "openai 403: not authorized for this model", nil},
		{"400 bad request", "codex 400: invalid request schema", nil},
		{"completely random", "the model said no", nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyOliumError(tc.input)
			if got == nil {
				t.Fatalf("classifyOliumError returned nil; want error wrapping %v", tc.sentinel)
			}
			if tc.sentinel == nil {
				// Should NOT match any retryable sentinel.
				for _, s := range retryableSentinels {
					if errors.Is(got, s) {
						t.Fatalf("classifyOliumError(%q) wrongly classified as retryable %v: %v", tc.input, s, got)
					}
				}
				return
			}
			if !errors.Is(got, tc.sentinel) {
				t.Fatalf("classifyOliumError(%q) = %v; want wraps %v", tc.input, got, tc.sentinel)
			}
		})
	}
}

func TestIsRetryableAgentError_Sentinels(t *testing.T) {
	ctx := context.Background()
	for _, s := range retryableSentinels {
		if !isRetryableAgentError(ctx, s) {
			t.Errorf("expected sentinel %v to be retryable", s)
		}
	}
}

func TestIsRetryableAgentError_WrappedSentinel(t *testing.T) {
	ctx := context.Background()
	wrapped := classifyOliumError("anthropic 429: limit hit")
	if !isRetryableAgentError(ctx, wrapped) {
		t.Errorf("wrapped rate-limit error should be retryable, got: %v", wrapped)
	}
}

func TestIsRetryableAgentError_TerminalError(t *testing.T) {
	ctx := context.Background()
	terminal := classifyOliumError("anthropic 401: invalid api key")
	if isRetryableAgentError(ctx, terminal) {
		t.Errorf("auth error should NOT be retryable, got: %v", terminal)
	}
}
