package http

import (
	"context"
	"io"
	"testing"
)

func TestRequestBuilder(t *testing.T) {
	t.Run("creates GET request by default", func(t *testing.T) {
		req, err := NewRequest("https://example.com").Build()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if req.Method != "GET" {
			t.Errorf("expected GET, got %s", req.Method)
		}
		if req.URL.String() != "https://example.com" {
			t.Errorf("unexpected URL: %s", req.URL.String())
		}
	})

	t.Run("sets HTTP method", func(t *testing.T) {
		req, err := NewRequest("https://example.com").Method("POST").Build()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if req.Method != "POST" {
			t.Errorf("expected POST, got %s", req.Method)
		}
	})

	t.Run("sets single header", func(t *testing.T) {
		req, err := NewRequest("https://example.com").
			Header("X-Custom", "value").
			Build()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if req.Header.Get("X-Custom") != "value" {
			t.Errorf("expected X-Custom header, got %v", req.Header)
		}
	})

	t.Run("sets multiple headers", func(t *testing.T) {
		headers := map[string]string{
			"X-Custom-1": "value1",
			"X-Custom-2": "value2",
		}

		req, err := NewRequest("https://example.com").
			Headers(headers).
			Build()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if req.Header.Get("X-Custom-1") != "value1" {
			t.Error("expected X-Custom-1 header")
		}
		if req.Header.Get("X-Custom-2") != "value2" {
			t.Error("expected X-Custom-2 header")
		}
	})

	t.Run("sets default User-Agent if not provided", func(t *testing.T) {
		req, err := NewRequest("https://example.com").Build()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		ua := req.Header.Get("User-Agent")
		// Expect Chrome-like UA for WAF bypass
		if ua == "" || ua == "Go-http-client/1.1" {
			t.Errorf("expected Chrome-like User-Agent, got: %s", ua)
		}
	})

	t.Run("sets body from bytes", func(t *testing.T) {
		body := []byte("test body")
		req, err := NewRequest("https://example.com").
			Method("POST").
			Body(body).
			Build()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		actualBody, _ := io.ReadAll(req.Body)
		if string(actualBody) != string(body) {
			t.Errorf("expected body %s, got %s", body, actualBody)
		}
	})

	t.Run("sets body from string", func(t *testing.T) {
		body := "test body"
		req, err := NewRequest("https://example.com").
			Method("POST").
			BodyString(body).
			Build()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		actualBody, _ := io.ReadAll(req.Body)
		if string(actualBody) != body {
			t.Errorf("expected body %s, got %s", body, actualBody)
		}
	})

	t.Run("sets context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		req, err := NewRequest("https://example.com").
			Context(ctx).
			Build()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if req.Context() != ctx {
			t.Error("expected custom context")
		}
	})

	t.Run("validates invalid URL", func(t *testing.T) {
		_, err := NewRequest("://invalid").Build()
		if err == nil {
			t.Fatal("expected error for invalid URL")
		}
	})

	t.Run("chains multiple operations", func(t *testing.T) {
		req, err := NewRequest("https://example.com/api").
			Method("POST").
			Header("X-Custom", "value").
			Header("Content-Type", "application/json").
			Header("User-Agent", "test/1.0").
			BodyString(`{"key":"value"}`).
			Build()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if req.Method != "POST" {
			t.Errorf("expected POST, got %s", req.Method)
		}
		if req.Header.Get("X-Custom") != "value" {
			t.Error("expected X-Custom header")
		}
		if req.Header.Get("Content-Type") != "application/json" {
			t.Error("expected Content-Type header")
		}
		if req.Header.Get("User-Agent") != "test/1.0" {
			t.Error("expected custom User-Agent")
		}

		body, _ := io.ReadAll(req.Body)
		if string(body) != `{"key":"value"}` {
			t.Errorf("unexpected body: %s", body)
		}
	})
}
