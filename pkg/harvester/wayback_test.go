package harvester

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaybackClient_Fetch_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "url=*.example.com/*") {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}

		_, _ = fmt.Fprintln(w, "http://example.com/page1")
		_, _ = fmt.Fprintln(w, "http://example.com/page2")
		_, _ = fmt.Fprintln(w, "http://sub.example.com/api/v1")
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 100 * time.Millisecond,
		maxBackoff: 400 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got []string
	for r := range results {
		got = append(got, r.URL)
	}

	expected := []string{
		"http://example.com/page1",
		"http://example.com/page2",
		"http://sub.example.com/api/v1",
	}

	if len(got) != len(expected) {
		t.Errorf("got %d URLs, want %d", len(got), len(expected))
	}

	for i, want := range expected {
		if i >= len(got) {
			break
		}
		if got[i] != want {
			t.Errorf("URL[%d] = %q, want %q", i, got[i], want)
		}
	}
}

func TestWaybackClient_Fetch_StreamsLineByLine(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 1000; i++ {
			_, _ = fmt.Fprintf(w, "http://example.com/page%d\n", i)
		}
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 100 * time.Millisecond,
		maxBackoff: 400 * time.Millisecond,
	}

	results := make(chan Result, 1100)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lineCount := 0
	for range results {
		lineCount++
	}

	if lineCount != 1000 {
		t.Errorf("got %d lines, want 1000", lineCount)
	}
}

func TestWaybackClient_Fetch_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 10000; i++ {
			_, _ = fmt.Fprintf(w, "http://example.com/page%d\n", i)
		}
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 100 * time.Millisecond,
		maxBackoff: 400 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())

	results := make(chan Result, 200)
	go func() {
		count := 0
		for range results {
			count++
			if count >= 100 {
				cancel()
				return
			}
		}
	}()

	err := client.fetch(ctx, "example.com", results, "wayback")
	close(results)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestWaybackClient_Fetch_RateLimit_Retry(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = fmt.Fprintln(w, "http://example.com/success")
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 50 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got []string
	for r := range results {
		got = append(got, r.URL)
	}

	if len(got) != 1 || got[0] != "http://example.com/success" {
		t.Errorf("unexpected result: %v", got)
	}

	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestWaybackClient_Fetch_MaxRetriesExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 2,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 50 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "max retries exceeded") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWaybackClient_Fetch_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 50 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var apiErr *waybackAPIError
	if !errors.As(err, &apiErr) {
		t.Errorf("expected waybackAPIError, got: %T", err)
	}

	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", apiErr.StatusCode)
	}
}

func TestWaybackClient_Fetch_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 50 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := 0
	for range results {
		count++
	}

	if count != 0 {
		t.Errorf("expected 0 URLs, got %d", count)
	}
}

func TestWaybackClient_Fetch_EmptyLines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "http://example.com/page1")
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, "http://example.com/page2")
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, "")
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 3,
		retryDelay: 10 * time.Millisecond,
		maxBackoff: 50 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got []string
	for r := range results {
		got = append(got, r.URL)
	}

	if len(got) != 2 {
		t.Errorf("expected 2 URLs, got %d: %v", len(got), got)
	}
}

func TestWaybackClient_Fetch_EmptyDomain(t *testing.T) {
	client := newWaybackClient()

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "", results, "wayback")
	close(results)

	if err == nil {
		t.Fatal("expected error for empty domain")
	}

	if !strings.Contains(err.Error(), "domain cannot be empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWaybackClient_BackoffCapped(t *testing.T) {
	var attempts int32
	var timestamps []time.Time

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timestamps = append(timestamps, time.Now())
		count := atomic.AddInt32(&attempts, 1)
		if count < 4 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = fmt.Fprintln(w, "http://example.com/success")
	}))
	defer server.Close()

	client := &waybackClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		userAgent:  "test-agent",
		maxRetries: 5,
		retryDelay: 50 * time.Millisecond,
		maxBackoff: 100 * time.Millisecond,
	}

	results := make(chan Result, 10)
	err := client.fetch(context.Background(), "example.com", results, "wayback")
	close(results)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(timestamps) < 3 {
		t.Fatalf("expected at least 3 attempts, got %d", len(timestamps))
	}

	delay2 := timestamps[2].Sub(timestamps[1])
	delay3 := timestamps[3].Sub(timestamps[2])

	if delay3 > delay2*2 {
		t.Errorf("backoff should be capped: delay2=%v, delay3=%v", delay2, delay3)
	}
}

func TestWaybackSource_Run(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "http://example.com/page1")
		_, _ = fmt.Fprintln(w, "http://example.com/page2")
	}))
	defer server.Close()

	src := &WaybackSource{
		client: &waybackClient{
			httpClient: server.Client(),
			baseURL:    server.URL,
			userAgent:  "test-agent",
			maxRetries: 3,
			retryDelay: 10 * time.Millisecond,
			maxBackoff: 50 * time.Millisecond,
		},
	}

	results := src.Run(context.Background(), "example.com")

	var urls []string
	for r := range results {
		if r.Error != nil {
			t.Fatalf("unexpected error: %v", r.Error)
		}
		urls = append(urls, r.URL)
	}

	if len(urls) != 2 {
		t.Errorf("expected 2 URLs, got %d", len(urls))
	}
}

func TestNewWaybackClient_Defaults(t *testing.T) {
	client := newWaybackClient()

	if client.maxRetries != 3 {
		t.Errorf("expected max retries 3, got %d", client.maxRetries)
	}

	if client.maxBackoff != 4*time.Second {
		t.Errorf("expected max backoff 4s, got %v", client.maxBackoff)
	}

	if client.retryDelay != 1*time.Second {
		t.Errorf("expected retry delay 1s, got %v", client.retryDelay)
	}
}
