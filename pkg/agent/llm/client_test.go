package llm

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
)

// mockClient is a simple Client for testing.
type mockClient struct {
	calls int
	resp  *CompletionResponse
	err   error
}

func (m *mockClient) Complete(_ context.Context, _ CompletionRequest) (*CompletionResponse, error) {
	m.calls++
	return m.resp, m.err
}

func TestNewClient_Anthropic(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")

	c, err := NewClient(config.LLMConfig{Provider: "anthropic", Model: "claude-sonnet-4-20250514"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := c.(*AnthropicClient); !ok {
		t.Errorf("expected *AnthropicClient, got %T", c)
	}
}

func TestNewClient_OpenAI(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-openai-key")

	c, err := NewClient(config.LLMConfig{Provider: "openai", Model: "gpt-4o"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := c.(*OpenAIClient); !ok {
		t.Errorf("expected *OpenAIClient, got %T", c)
	}
}

func TestNewClient_UnknownProvider(t *testing.T) {
	_, err := NewClient(config.LLMConfig{Provider: "unknown", APIKey: "x"})
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestNewClient_MissingAPIKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	_, err := NewClient(config.LLMConfig{Provider: "anthropic"})
	if err == nil {
		t.Fatal("expected error for missing API key")
	}
}

func TestNewCachedClient_DisabledWhenSizeZero(t *testing.T) {
	inner := &mockClient{resp: &CompletionResponse{Content: "hi"}}
	c, err := NewCachedClient(inner, config.LLMConfig{CacheSize: 0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return the inner client directly.
	if c != inner {
		t.Errorf("expected inner client returned when CacheSize=0")
	}
}

func TestCachedClient_HitAndMiss(t *testing.T) {
	inner := &mockClient{resp: &CompletionResponse{Content: "cached"}}
	cc, err := newCachedClient(inner, 10, 60)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := CompletionRequest{Messages: []Message{{Role: "user", Content: "hello"}}}
	ctx := context.Background()

	resp1, _ := cc.Complete(ctx, req)
	resp2, _ := cc.Complete(ctx, req)

	if inner.calls != 1 {
		t.Errorf("expected 1 upstream call, got %d", inner.calls)
	}
	if resp1.Content != "cached" || resp2.Content != "cached" {
		t.Errorf("unexpected content: %q / %q", resp1.Content, resp2.Content)
	}
}

func TestCachedClient_TTLExpiry(t *testing.T) {
	inner := &mockClient{resp: &CompletionResponse{Content: "fresh"}}
	cc, err := newCachedClient(inner, 10, 0) // 0s TTL = instant expiry
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := CompletionRequest{Messages: []Message{{Role: "user", Content: "hello"}}}
	ctx := context.Background()

	cc.Complete(ctx, req)            //nolint:errcheck
	time.Sleep(1 * time.Millisecond) // ensure expiry
	cc.Complete(ctx, req)            //nolint:errcheck

	if inner.calls != 2 {
		t.Errorf("expected 2 upstream calls after TTL expiry, got %d", inner.calls)
	}
}

func TestCachedClient_Error(t *testing.T) {
	inner := &mockClient{err: fmt.Errorf("upstream error")}
	cc, err := newCachedClient(inner, 10, 60)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := CompletionRequest{Messages: []Message{{Role: "user", Content: "hello"}}}
	_, err = cc.Complete(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from upstream, got nil")
	}
	// Errors should NOT be cached.
	inner.err = nil
	inner.resp = &CompletionResponse{Content: "ok"}
	resp, err := cc.Complete(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error on retry: %v", err)
	}
	if resp.Content != "ok" {
		t.Errorf("expected 'ok', got %q", resp.Content)
	}
}
