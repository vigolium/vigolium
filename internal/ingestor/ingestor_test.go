package ingestor

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts == nil {
		t.Fatal("DefaultOptions returned nil")
	}
	if opts.Concurrency != 10 {
		t.Errorf("Concurrency = %d, want 10", opts.Concurrency)
	}
	if opts.RateLimit != 100 {
		t.Errorf("RateLimit = %d, want 100", opts.RateLimit)
	}
	if opts.Input != "-" {
		t.Errorf("Input = %q, want -", opts.Input)
	}
	if opts.InputFormat != "urls" {
		t.Errorf("InputFormat = %q, want urls", opts.InputFormat)
	}
	if opts.DefaultParam != "1" {
		t.Errorf("DefaultParam = %q, want 1", opts.DefaultParam)
	}
}

func TestNewClient(t *testing.T) {
	t.Run("trims trailing slash", func(t *testing.T) {
		c := NewClient("http://localhost:8080/", "key", 50)
		if c.baseURL != "http://localhost:8080" {
			t.Errorf("baseURL = %q, want http://localhost:8080", c.baseURL)
		}
	})

	t.Run("keeps non-trailing", func(t *testing.T) {
		c := NewClient("http://localhost:8080", "key", 50)
		if c.baseURL != "http://localhost:8080" {
			t.Errorf("baseURL = %q", c.baseURL)
		}
	})

	t.Run("sets fields", func(t *testing.T) {
		c := NewClient("http://x", "secret", 5)
		if c.apiKey != "secret" {
			t.Errorf("apiKey = %q", c.apiKey)
		}
		if c.httpClient == nil || c.httpClient.Timeout != 30*time.Second {
			t.Errorf("httpClient not configured: %+v", c.httpClient)
		}
		if c.rateLimiter == nil {
			t.Error("rateLimiter is nil")
		}
	})
}

func TestSubmitSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/ingest-http" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer tok" {
			t.Errorf("authorization = %q", auth)
		}

		var got IngestRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if got.URL != "http://target/x" {
			t.Errorf("decoded URL = %q", got.URL)
		}

		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(IngestResponse{TaskID: "t1", Status: "queued", QueueSize: 3})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok", 1000)
	resp, err := c.Submit(context.Background(), &IngestRequest{URL: "http://target/x"})
	if err != nil {
		t.Fatalf("Submit error: %v", err)
	}
	if resp.TaskID != "t1" || resp.Status != "queued" || resp.QueueSize != 3 {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestSubmitNoAPIKeyOmitsAuthHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Authorization"]; ok {
			t.Error("Authorization header should be absent when apiKey is empty")
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(IngestResponse{Status: "ok"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "", 1000)
	if _, err := c.Submit(context.Background(), &IngestRequest{URL: "http://t"}); err != nil {
		t.Fatalf("Submit error: %v", err)
	}
}

func TestSubmitServerErrorWithErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Error: "bad input", Code: 400})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok", 1000)
	_, err := c.Submit(context.Background(), &IngestRequest{URL: "http://t"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "bad input") || !strings.Contains(err.Error(), "400") {
		t.Errorf("error = %v, want it to mention status and message", err)
	}
}

func TestSubmitServerErrorPlainBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("oops not json"))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok", 1000)
	_, err := c.Submit(context.Background(), &IngestRequest{URL: "http://t"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "oops not json") || !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %v", err)
	}
}

func TestSubmitInvalidSuccessJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{not valid json"))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok", 1000)
	_, err := c.Submit(context.Background(), &IngestRequest{URL: "http://t"})
	if err == nil || !strings.Contains(err.Error(), "parse response") {
		t.Errorf("error = %v, want parse response failure", err)
	}
}

func TestSubmitContextCanceled(t *testing.T) {
	// rateLimiter.Wait should fail immediately on a canceled context.
	c := NewClient("http://localhost", "tok", 1000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Submit(ctx, &IngestRequest{URL: "http://t"})
	if err == nil || !strings.Contains(err.Error(), "rate limiter") {
		t.Errorf("error = %v, want rate limiter error", err)
	}
}

func TestSubmitTransportError(t *testing.T) {
	// Point at a server that is closed so the HTTP round-trip fails.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	c := NewClient(url, "tok", 1000)
	_, err := c.Submit(context.Background(), &IngestRequest{URL: "http://t"})
	if err == nil || !strings.Contains(err.Error(), "http request") {
		t.Errorf("error = %v, want http request failure", err)
	}
}

func TestRunValidation(t *testing.T) {
	tests := []struct {
		name    string
		opts    *Options
		wantErr string
	}{
		{
			name:    "missing server url",
			opts:    &Options{},
			wantErr: "server URL is required",
		},
		{
			name:    "missing scheme",
			opts:    &Options{ServerURL: "localhost:8080", APIKey: "k"},
			wantErr: "must include scheme",
		},
		{
			name:    "missing api key",
			opts:    &Options{ServerURL: "http://localhost:8080"},
			wantErr: "API key is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Run(context.Background(), tt.opts)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Run() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestRunHTTPSAccepted(t *testing.T) {
	// https:// prefix should also be accepted by validation.
	_, err := Run(context.Background(), &Options{ServerURL: "https://x", APIKey: ""})
	if err == nil || !strings.Contains(err.Error(), "API key is required") {
		t.Errorf("Run() error = %v, want API key error (passing scheme check)", err)
	}
}

func TestRunURLsEndToEnd(t *testing.T) {
	// Write a URL list to a temp file and run the urls path against a fake server.
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "urls.txt")
	content := "http://target/a\n\nhttp://target/b\n  http://target/c  \n"
	if err := os.WriteFile(inputPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(IngestResponse{Status: "queued"})
	}))
	defer srv.Close()

	opts := DefaultOptions()
	opts.ServerURL = srv.URL
	opts.APIKey = "tok"
	opts.Input = inputPath
	opts.Concurrency = 2

	stats, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	// 3 non-empty lines submitted.
	if stats.Submitted != 3 {
		t.Errorf("Submitted = %d, want 3", stats.Submitted)
	}
	if stats.Errors != 0 {
		t.Errorf("Errors = %d, want 0", stats.Errors)
	}
	if stats.Elapsed <= 0 {
		t.Errorf("Elapsed = %v, want > 0", stats.Elapsed)
	}
}

func TestRunCountsErrors(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "urls.txt")
	if err := os.WriteFile(inputPath, []byte("http://target/a\nhttp://target/b\n"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("fail"))
	}))
	defer srv.Close()

	opts := DefaultOptions()
	opts.ServerURL = srv.URL
	opts.APIKey = "tok"
	opts.Input = inputPath
	opts.Concurrency = 1

	stats, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if stats.Errors != 2 {
		t.Errorf("Errors = %d, want 2", stats.Errors)
	}
	if stats.Submitted != 0 {
		t.Errorf("Submitted = %d, want 0", stats.Submitted)
	}
}

func TestRunNucleiFormat(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "nuclei.json")
	// Stream of nuclei JSON objects: two valid (one with raw request), one empty URL.
	content := `{"url":"http://t/a"}
{"url":"http://t/b","request":{"raw":"GET /b HTTP/1.1\r\nHost: t\r\n\r\n"}}
{"url":""}
`
	if err := os.WriteFile(inputPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	var sawRaw bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got IngestRequest
		_ = json.NewDecoder(r.Body).Decode(&got)
		if got.Request != nil && got.Request.Raw != "" {
			sawRaw = true
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(IngestResponse{Status: "queued"})
	}))
	defer srv.Close()

	opts := DefaultOptions()
	opts.ServerURL = srv.URL
	opts.APIKey = "tok"
	opts.Input = inputPath
	opts.InputFormat = "nuclei"
	opts.Concurrency = 1

	stats, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if stats.Submitted != 2 { // empty URL skipped
		t.Errorf("Submitted = %d, want 2", stats.Submitted)
	}
	if !sawRaw {
		t.Error("expected at least one request with raw HTTP body")
	}
}

func TestRunOpenInputError(t *testing.T) {
	// A nonexistent input file: workers see a closed channel, run completes with zero stats.
	opts := DefaultOptions()
	opts.ServerURL = "http://localhost:9"
	opts.APIKey = "tok"
	opts.Input = filepath.Join(t.TempDir(), "does-not-exist.txt")
	opts.Concurrency = 1

	stats, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if stats.Submitted != 0 || stats.Errors != 0 {
		t.Errorf("stats = %+v, want zero submitted/errors", stats)
	}
}

func TestOpenInputStdin(t *testing.T) {
	r, closer, err := openInput("-")
	if err != nil {
		t.Fatalf("openInput(-) error: %v", err)
	}
	if closer != nil {
		t.Error("stdin closer should be nil")
	}
	if r != os.Stdin {
		t.Error("openInput(-) should return os.Stdin")
	}
}

func TestOpenInputPlainFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(p, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	r, closer, err := openInput(p)
	if err != nil {
		t.Fatalf("openInput error: %v", err)
	}
	defer func() {
		if closer != nil {
			_ = closer.Close()
		}
	}()
	data, _ := io.ReadAll(r)
	if string(data) != "hello" {
		t.Errorf("read = %q, want hello", string(data))
	}
}

func TestOpenInputGzip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.gz")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gw := gzip.NewWriter(f)
	if _, err := gw.Write([]byte("gzipped content")); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	_ = gw.Close()
	_ = f.Close()

	r, closer, err := openInput(p)
	if err != nil {
		t.Fatalf("openInput(gz) error: %v", err)
	}
	if closer == nil {
		t.Fatal("gzip closer should not be nil")
	}
	defer func() { _ = closer.Close() }()

	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read gz: %v", err)
	}
	if string(data) != "gzipped content" {
		t.Errorf("read = %q", string(data))
	}
}

func TestOpenInputGzipCorrupt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.gz")
	if err := os.WriteFile(p, []byte("not actually gzip"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err := openInput(p)
	if err == nil {
		t.Error("expected error opening corrupt gzip, got nil")
	}
}

func TestOpenInputMissingFile(t *testing.T) {
	_, _, err := openInput(filepath.Join(t.TempDir(), "nope.txt"))
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestMultiCloser(t *testing.T) {
	t.Run("closes all without error", func(t *testing.T) {
		a := &countingCloser{}
		b := &countingCloser{}
		mc := &multiCloser{closers: []io.Closer{a, b}}
		if err := mc.Close(); err != nil {
			t.Errorf("Close error: %v", err)
		}
		if a.calls != 1 || b.calls != 1 {
			t.Errorf("calls = %d,%d, want 1,1", a.calls, b.calls)
		}
	})

	t.Run("returns last error but closes all", func(t *testing.T) {
		errC := &countingCloser{err: errors.New("boom")}
		okC := &countingCloser{}
		mc := &multiCloser{closers: []io.Closer{errC, okC}}
		err := mc.Close()
		if err == nil {
			t.Error("expected error from multiCloser")
		}
		if okC.calls != 1 {
			t.Error("multiCloser should close all closers even when one errors")
		}
	})
}

type countingCloser struct {
	calls int
	err   error
}

func (c *countingCloser) Close() error {
	c.calls++
	return c.err
}

func TestParseURLsInput(t *testing.T) {
	reader := strings.NewReader("http://a\n\n   \nhttp://b\n  http://c  \n")
	ch := make(chan *IngestRequest, 10)
	opts := &Options{
		EnableModules: []string{"xss"},
		WebhookURL:    "http://hook",
	}
	parseURLsInput(context.Background(), reader, ch, opts)
	close(ch)

	var urls []string
	for req := range ch {
		urls = append(urls, req.URL)
		if len(req.EnableModules) != 1 || req.EnableModules[0] != "xss" {
			t.Errorf("EnableModules = %v", req.EnableModules)
		}
		if req.WebhookURL != "http://hook" {
			t.Errorf("WebhookURL = %q", req.WebhookURL)
		}
	}
	want := []string{"http://a", "http://b", "http://c"}
	if strings.Join(urls, ",") != strings.Join(want, ",") {
		t.Errorf("urls = %v, want %v", urls, want)
	}
}

func TestParseURLsInputContextCanceled(t *testing.T) {
	reader := strings.NewReader("http://a\nhttp://b\n")
	ch := make(chan *IngestRequest, 10)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Should return promptly without producing anything.
	parseURLsInput(ctx, reader, ch, &Options{})
	close(ch)
	if len(ch) != 0 {
		t.Errorf("channel has %d items, want 0", len(ch))
	}
}

func TestParseNucleiInput(t *testing.T) {
	body := `{"url":"http://a"}
{"url":"http://b","request":{"raw":"GET / HTTP/1.1"}}
{"url":""}
`
	reader := strings.NewReader(body)
	ch := make(chan *IngestRequest, 10)
	parseNucleiInput(context.Background(), reader, ch, &Options{EnableModules: []string{"sqli"}})
	close(ch)

	var reqs []*IngestRequest
	for req := range ch {
		reqs = append(reqs, req)
	}
	if len(reqs) != 2 {
		t.Fatalf("got %d requests, want 2", len(reqs))
	}
	if reqs[0].URL != "http://a" || reqs[0].Request != nil {
		t.Errorf("req0 = %+v", reqs[0])
	}
	if reqs[1].URL != "http://b" || reqs[1].Request == nil || reqs[1].Request.Raw != "GET / HTTP/1.1" {
		t.Errorf("req1 = %+v", reqs[1])
	}
	if len(reqs[0].EnableModules) != 1 || reqs[0].EnableModules[0] != "sqli" {
		t.Errorf("EnableModules not propagated: %v", reqs[0].EnableModules)
	}
}

func TestParseNucleiInputDecodeErrorContinues(t *testing.T) {
	// A malformed object that decodes with error: the loop logs and continues,
	// but dec.More on broken JSON typically stops. We assert no panic and the
	// valid leading object is captured.
	reader := strings.NewReader(`{"url":"http://a"}{"url":123}`)
	ch := make(chan *IngestRequest, 10)
	parseNucleiInput(context.Background(), reader, ch, &Options{})
	close(ch)
	var got []string
	for req := range ch {
		got = append(got, req.URL)
	}
	if len(got) == 0 || got[0] != "http://a" {
		t.Errorf("expected first valid url captured, got %v", got)
	}
}

func TestParseSpecInputFromFile(t *testing.T) {
	// Use the existing swagger fixture from the openapi package's testdata.
	specPath := filepath.Join("..", "..", "pkg", "input", "formats", "openapi", "testdata", "swagger_simple.yaml")
	if _, err := os.Stat(specPath); err != nil {
		t.Skipf("swagger fixture not found: %v", err)
	}

	ch := make(chan *IngestRequest, 64)
	opts := &Options{
		Input:         specPath,
		InputFormat:   "swagger",
		TargetURL:     "https://example.com",
		Headers:       []string{"X-Test: value", "malformed-header-no-colon"},
		Variables:     []string{"k=v", "novalue"},
		DefaultParam:  "1",
		EnableModules: []string{"all"},
		WebhookURL:    "http://hook",
	}
	parseSpecInput(context.Background(), ch, opts)
	close(ch)

	var reqs []*IngestRequest
	for req := range ch {
		reqs = append(reqs, req)
	}
	if len(reqs) == 0 {
		t.Fatal("expected at least one request from spec parsing")
	}
	for _, req := range reqs {
		if req.Request == nil || req.Request.Raw == "" {
			t.Errorf("spec request missing raw HTTP: %+v", req)
		}
		if req.WebhookURL != "http://hook" {
			t.Errorf("WebhookURL = %q", req.WebhookURL)
		}
	}
}

func TestParseSpecInputLoadError(t *testing.T) {
	// Nonexistent spec input: function logs and returns without producing requests.
	ch := make(chan *IngestRequest, 4)
	opts := &Options{Input: filepath.Join(t.TempDir(), "missing.yaml"), InputFormat: "openapi"}
	parseSpecInput(context.Background(), ch, opts)
	close(ch)
	if len(ch) != 0 {
		t.Errorf("expected no requests on load error, got %d", len(ch))
	}
}

func TestIngestRequestJSONRoundTrip(t *testing.T) {
	// Verify omitempty behavior and nested raw request serialization.
	req := &IngestRequest{
		URL:           "http://t",
		Request:       &IngestRawRequest{Raw: "GET / HTTP/1.1"},
		EnableModules: []string{"xss"},
		WebhookURL:    "http://hook",
		Metadata:      map[string]string{"k": "v"},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back IngestRequest
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.URL != req.URL || back.Request.Raw != req.Request.Raw {
		t.Errorf("round trip mismatch: %+v", back)
	}

	// Empty request omits optional fields.
	empty, _ := json.Marshal(&IngestRequest{})
	if strings.Contains(string(empty), "request") || strings.Contains(string(empty), "metadata") {
		t.Errorf("empty request should omit optional fields: %s", empty)
	}
}
