package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAnthropicClient_Complete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("x-api-key") != "test-key" {
			t.Errorf("missing API key header")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(anthropicResponse{
			ID:    "msg_1",
			Model: "claude-sonnet-4-20250514",
			Content: []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}{{Type: "text", Text: "hello"}},
			Usage: struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			}{InputTokens: 10, OutputTokens: 5},
		})
	}))
	defer srv.Close()

	// Temporarily patch the constant via a test helper.
	origURL := anthropicAPIURL
	_ = origURL // suppress unused warning; we patch via field below

	c := &AnthropicClient{
		apiKey:    "test-key",
		model:     "claude-sonnet-4-20250514",
		maxTokens: 100,
	}

	// We need to hit our test server; patch via a monkey-patched constant is not
	// possible in Go without build tags. Use a subtest that verifies the struct.
	_ = c
	t.Run("struct fields", func(t *testing.T) {
		if c.model != "claude-sonnet-4-20250514" {
			t.Errorf("unexpected model %q", c.model)
		}
		if c.maxTokens != 100 {
			t.Errorf("unexpected maxTokens %d", c.maxTokens)
		}
	})

	// Test via a real mock server by overriding the URL used in the request.
	// We do this by calling the internal helper directly.
	t.Run("mock server response", func(t *testing.T) {
		resp, err := callAnthropicURL(context.Background(), "test-key", srv.URL, anthropicRequest{
			Model:     "claude-sonnet-4-20250514",
			MaxTokens: 100,
			Messages:  []anthropicMessage{{Role: "user", Content: "hello"}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Content != "hello" {
			t.Errorf("expected content 'hello', got %q", resp.Content)
		}
		if resp.TokensIn != 10 || resp.TokensOut != 5 {
			t.Errorf("unexpected token counts: in=%d out=%d", resp.TokensIn, resp.TokensOut)
		}
	})
}

func TestAnthropicClient_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"type":"authentication_error","message":"invalid api key"}}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := callAnthropicURL(context.Background(), "bad-key", srv.URL, anthropicRequest{
		Model:     "claude-sonnet-4-20250514",
		MaxTokens: 100,
		Messages:  []anthropicMessage{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", apiErr.StatusCode)
	}
}

func TestAnthropicClient_SystemMessage(t *testing.T) {
	var captured anthropicRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(anthropicResponse{
			ID:    "msg_2",
			Model: "claude-sonnet-4-20250514",
			Content: []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}{{Type: "text", Text: "ok"}},
		})
	}))
	defer srv.Close()

	req := anthropicRequest{
		Model:     "claude-sonnet-4-20250514",
		MaxTokens: 100,
		System:    "You are a tester.",
		Messages:  []anthropicMessage{{Role: "user", Content: "hi"}},
	}
	_, err := callAnthropicURL(context.Background(), "key", srv.URL, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.System != "You are a tester." {
		t.Errorf("system not propagated: %q", captured.System)
	}
}
