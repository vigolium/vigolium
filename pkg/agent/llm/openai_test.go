package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func makeOpenAIResponse(content, model string, promptTok, compTok int) openaiResponse {
	return openaiResponse{
		ID:    "chatcmpl-1",
		Model: model,
		Choices: []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		}{{Message: struct {
			Content string `json:"content"`
		}{Content: content}}},
		Usage: struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		}{PromptTokens: promptTok, CompletionTokens: compTok},
	}
}

func TestOpenAIClient_Complete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("missing auth header")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(makeOpenAIResponse("world", "gpt-4o", 8, 3))
	}))
	defer srv.Close()

	resp, err := callOpenAIURL(context.Background(), "test-key", srv.URL+"/chat/completions", openaiRequest{
		Model:    "gpt-4o",
		Messages: []openaiMessage{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "world" {
		t.Errorf("expected content 'world', got %q", resp.Content)
	}
	if resp.TokensIn != 8 || resp.TokensOut != 3 {
		t.Errorf("unexpected tokens: in=%d out=%d", resp.TokensIn, resp.TokensOut)
	}
}

func TestOpenAIClient_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"type":"invalid_request_error","message":"bad request"}}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	_, err := callOpenAIURL(context.Background(), "key", srv.URL+"/chat/completions", openaiRequest{
		Model:    "gpt-4o",
		Messages: []openaiMessage{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", apiErr.StatusCode)
	}
}

func TestOpenAIClient_EmptyChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(openaiResponse{ID: "x", Model: "gpt-4o"})
	}))
	defer srv.Close()

	_, err := callOpenAIURL(context.Background(), "key", srv.URL+"/chat/completions", openaiRequest{
		Model:    "gpt-4o",
		Messages: []openaiMessage{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error for empty choices, got nil")
	}
}
