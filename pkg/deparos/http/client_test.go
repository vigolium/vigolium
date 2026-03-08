package http

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	t.Run("creates client with default config", func(t *testing.T) {
		client := NewClient(nil)
		if client == nil {
			t.Fatal("expected non-nil client")
		}
		if client.client == nil {
			t.Fatal("expected non-nil underlying http.Client")
		}
	})

	t.Run("creates client with custom config", func(t *testing.T) {
		config := &ClientConfig{
			PoolConfig: &PoolConfig{
				MaxIdleConns:           50,
				MaxIdleConnsPerHost:    5,
				DisableTLSVerification: true,
			},
			MaxRedirects: 5,
		}
		client := NewClient(config)
		if client == nil {
			t.Fatal("expected non-nil client")
		}
	})

	t.Run("applies middleware in correct order", func(t *testing.T) {
		var order []string

		middleware1 := func(rt http.RoundTripper) http.RoundTripper {
			return &testRoundTripper{
				name:  "middleware1",
				next:  rt,
				order: &order,
			}
		}

		middleware2 := func(rt http.RoundTripper) http.RoundTripper {
			return &testRoundTripper{
				name:  "middleware2",
				next:  rt,
				order: &order,
			}
		}

		config := &ClientConfig{
			Middleware: []Middleware{middleware1, middleware2},
		}
		client := NewClient(config)

		// Create test server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		// Send request
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		rc, err := client.Send(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		rc.Close()

		// Verify middleware order
		expected := []string{"middleware1", "middleware2"}
		if len(order) != len(expected) {
			t.Fatalf("expected %d middleware calls, got %d", len(expected), len(order))
		}
		for i, name := range expected {
			if order[i] != name {
				t.Errorf("expected middleware[%d]=%s, got %s", i, name, order[i])
			}
		}
	})
}

func TestClientSend(t *testing.T) {
	t.Run("sends GET request successfully", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				t.Errorf("expected GET, got %s", r.Method)
			}
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>test</html>"))
		}))
		defer server.Close()

		client := NewClient(nil)
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		rc, err := client.Send(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer rc.Close()

		resp := rc.Response()
		body := rc.BodyBytes()

		if resp.StatusCode != 200 {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
		if string(body) != "<html>test</html>" {
			t.Errorf("unexpected body: %s", body)
		}
		if resp.Header.Get("Content-Type") != "text/html" {
			t.Errorf("expected Content-Type header text/html, got %v", resp.Header.Get("Content-Type"))
		}
	})

	t.Run("sends POST request with body", func(t *testing.T) {
		expectedBody := "test=data"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("expected POST, got %s", r.Method)
			}
			body, _ := io.ReadAll(r.Body)
			if string(body) != expectedBody {
				t.Errorf("expected body %s, got %s", expectedBody, string(body))
			}
			w.WriteHeader(http.StatusCreated)
		}))
		defer server.Close()

		client := NewClient(nil)
		req, err := http.NewRequestWithContext(context.Background(), "POST", server.URL, bytes.NewBufferString(expectedBody))
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		rc, err := client.Send(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer rc.Close()

		if rc.Response().StatusCode != 201 {
			t.Errorf("expected status 201, got %d", rc.Response().StatusCode)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Never respond
			select {}
		}))
		defer server.Close()

		client := NewClient(nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		req, err := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		_, err = client.Send(ctx, req)
		if err == nil {
			t.Fatal("expected error from cancelled context")
		}
		if !strings.Contains(err.Error(), "context canceled") {
			t.Errorf("expected context canceled error, got: %v", err)
		}
	})

	t.Run("handles 404 response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("Not Found"))
		}))
		defer server.Close()

		client := NewClient(nil)
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/notfound", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		rc, err := client.Send(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer rc.Close()

		if rc.Response().StatusCode != 404 {
			t.Errorf("expected status 404, got %d", rc.Response().StatusCode)
		}
	})

	t.Run("handles redirects", func(t *testing.T) {
		redirectCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/redirect" {
				redirectCount++
				if redirectCount < 3 {
					http.Redirect(w, r, "/redirect", http.StatusFound)
					return
				}
				http.Redirect(w, r, "/final", http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("final"))
		}))
		defer server.Close()

		client := NewClient(nil)
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/redirect", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		rc, err := client.Send(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer rc.Close()

		if rc.Response().StatusCode != 200 {
			t.Errorf("expected status 200, got %d", rc.Response().StatusCode)
		}
		if redirectCount != 3 {
			t.Errorf("expected 3 redirects, got %d", redirectCount)
		}
	})

	t.Run("limits redirects", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/redirect", http.StatusFound)
		}))
		defer server.Close()

		config := &ClientConfig{
			MaxRedirects: 2, // Limit to 2 redirects
		}
		client := NewClient(config)

		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/redirect", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		_, err = client.Send(context.Background(), req)
		if err == nil {
			t.Fatal("expected error from too many redirects")
		}
	})

	t.Run("sets default User-Agent", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ua := r.Header.Get("User-Agent")
			// Expect Chrome-like UA for WAF bypass
			if ua == "" || ua == "Go-http-client/1.1" {
				t.Errorf("expected Chrome-like User-Agent, got '%s'", ua)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := NewClient(nil)
		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		rc, err := client.Send(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		rc.Close()
	})
}

func TestClientTimeout(t *testing.T) {
	t.Run("request times out when server slower than client timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			RequestTimeout: 50 * time.Millisecond,
		})

		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		_, err = client.Send(context.Background(), req)
		if err == nil {
			t.Fatal("expected timeout error")
		}

		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("expected context deadline exceeded error, got %v", err)
		}
	})

	t.Run("request completes when server responds before timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(10 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := NewClient(&ClientConfig{
			RequestTimeout: 200 * time.Millisecond,
		})

		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		rc, err := client.Send(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer rc.Close()

		if rc.Response().StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", rc.Response().StatusCode)
		}
	})
}

func TestClientTLSVerification(t *testing.T) {
	t.Run("disables TLS verification by default", func(t *testing.T) {
		client := NewClient(nil)
		transport, ok := client.client.Transport.(*http.Transport)
		if !ok {
			t.Fatal("expected *http.Transport")
		}

		if transport.TLSClientConfig == nil {
			t.Fatal("expected TLS config")
		}
		if !transport.TLSClientConfig.InsecureSkipVerify {
			t.Error("expected InsecureSkipVerify to be true")
		}
	})
}

// testRoundTripper is a test middleware that records execution order.
type testRoundTripper struct {
	name  string
	next  http.RoundTripper
	order *[]string
}

func (t *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	*t.order = append(*t.order, t.name)
	return t.next.RoundTrip(req)
}
