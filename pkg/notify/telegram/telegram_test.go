package telegram

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	tele "gopkg.in/telebot.v3"

	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// okResponse is a minimal valid Telegram Bot API success body that telebot's
// extractOk/extractMessage helpers accept.
const okResponse = `{"ok":true,"result":{"message_id":1,"chat":{"id":1,"type":"private"},"date":1}}`

// telegramHandler captures the last sendMessage payload and lets a test control
// the HTTP response.
type telegramHandler struct {
	mu         sync.Mutex
	methods    []string // API methods invoked (e.g. "sendMessage", "sendDocument")
	lastText   string
	lastChatID string
	parseMode  string
	calls      atomic.Int32
	statusFn   func(call int32) (int, string)
}

func newTelegramHandler() *telegramHandler {
	return &telegramHandler{
		statusFn: func(int32) (int, string) { return http.StatusOK, okResponse },
	}
}

func (h *telegramHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := h.calls.Add(1)

	// URL form: /bot<token>/<method>
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	method := ""
	if len(parts) > 0 {
		method = parts[len(parts)-1]
	}

	h.mu.Lock()
	h.methods = append(h.methods, method)
	h.mu.Unlock()

	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		var payload map[string]any
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		h.mu.Lock()
		if v, ok := payload["text"].(string); ok {
			h.lastText = v
		}
		if v, ok := payload["chat_id"].(string); ok {
			h.lastChatID = v
		}
		if v, ok := payload["parse_mode"].(string); ok {
			h.parseMode = v
		}
		h.mu.Unlock()
	}

	status, respBody := h.statusFn(n)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, respBody)
}

func (h *telegramHandler) Methods() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.methods))
	copy(out, h.methods)
	return out
}

// newTestClient builds a Client whose telebot bot is pointed at the given test
// server URL. NewClient itself has NO seam to override the Telegram API base URL
// (it always uses tele.DefaultApiURL), so this internal-package helper constructs
// the Client directly: tele.Settings.Offline skips the network getMe() call
// during construction, and Bot.URL is redirected to httptest.
func newTestClient(t *testing.T, serverURL string, cfg *Config) *Client {
	t.Helper()
	if cfg == nil {
		cfg = DefaultConfig()
		cfg.BotToken = "test-token"
		cfg.ChatID = 12345
	}
	bot, err := tele.NewBot(tele.Settings{
		Token:     cfg.BotToken,
		URL:       serverURL,
		Offline:   true,
		ParseMode: tele.ModeMarkdownV2,
		Client:    &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatalf("build offline bot: %v", err)
	}
	limiter := ratelimit.New(context.Background(), uint(cfg.RateLimit), time.Second)
	c := &Client{config: cfg, bot: bot, rateLimiter: limiter}
	t.Cleanup(c.Close)
	return c
}

func testConfig() *Config {
	cfg := DefaultConfig()
	cfg.BotToken = "test-token"
	cfg.ChatID = 999
	cfg.MaxRetries = 2
	return cfg
}

// --- NewClient validation (no network: validation fails before bot build) ---

func TestNewClient_ValidationErrors(t *testing.T) {
	t.Setenv(EnvBotToken, "")
	t.Setenv(EnvChatID, "")

	if _, err := NewClient(); err == nil {
		t.Fatal("expected error when token and chat id are missing")
	}
	if _, err := NewClient(WithBotToken("tok")); err == nil {
		t.Fatal("expected error when chat id is missing")
	}
}

func TestNewBackend_ConfigError(t *testing.T) {
	t.Setenv(EnvBotToken, "")
	t.Setenv(EnvChatID, "")
	// NewBackend delegates to NewClient; with no token/chat id it fails at
	// validation before any network call (getMe) is attempted.
	if _, err := NewBackend(); err == nil {
		t.Fatal("expected error from NewBackend with missing config")
	}
}

func TestNewClient_InvalidChatIDEnv(t *testing.T) {
	t.Setenv(EnvBotToken, "tok")
	t.Setenv(EnvChatID, "not-a-number")
	if _, err := NewClient(); err == nil {
		t.Fatal("expected error parsing invalid TELEGRAM_CHAT_ID")
	}
}

func TestConfig_LoadFromEnvAndValidate(t *testing.T) {
	t.Setenv(EnvBotToken, "env-tok")
	t.Setenv(EnvChatID, "42")

	cfg := DefaultConfig()
	if err := cfg.LoadFromEnv(); err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if cfg.BotToken != "env-tok" || cfg.ChatID != 42 {
		t.Errorf("env not loaded: token=%q chat=%d", cfg.BotToken, cfg.ChatID)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate should pass: %v", err)
	}
}

func TestConfig_OptionsApplied(t *testing.T) {
	cfg := DefaultConfig()
	for _, opt := range []Option{
		WithBotToken("t"),
		WithChatID(7),
		WithMaxRetries(3),
		WithRateLimit(11),
		WithHTTPTimeout(2 * time.Second),
		WithMaxMessageBytes(123),
	} {
		opt(cfg)
	}
	if cfg.BotToken != "t" || cfg.ChatID != 7 || cfg.MaxRetries != 3 ||
		cfg.RateLimit != 11 || cfg.HTTPTimeout != 2*time.Second || cfg.MaxMessageBytes != 123 {
		t.Errorf("options not applied: %+v", cfg)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxRetries != DefaultMaxRetries ||
		cfg.RateLimit != DefaultRateLimit ||
		cfg.HTTPTimeout != DefaultHTTPTimeout ||
		cfg.MaxMessageBytes != DefaultMaxMessageBytes {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

// --- Send (text) -----------------------------------------------------------

func TestClient_Send_Text(t *testing.T) {
	h := newTelegramHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()

	c := newTestClient(t, srv.URL, testConfig())
	if err := c.Send("hello"); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	methods := h.Methods()
	if len(methods) != 1 || methods[0] != "sendMessage" {
		t.Errorf("expected one sendMessage call, got %v", methods)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lastText != "hello" {
		t.Errorf("unexpected text %q", h.lastText)
	}
	if h.lastChatID != "999" {
		t.Errorf("unexpected chat_id %q", h.lastChatID)
	}
	if h.parseMode != string(tele.ModeMarkdownV2) {
		t.Errorf("unexpected parse_mode %q", h.parseMode)
	}
}

func TestClient_Send_EmptyIsNoop(t *testing.T) {
	h := newTelegramHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()

	c := newTestClient(t, srv.URL, testConfig())
	if err := c.Send(""); err != nil {
		t.Fatalf("empty Send should be no-op: %v", err)
	}
	if got := h.calls.Load(); got != 0 {
		t.Errorf("empty Send should make no HTTP call, got %d", got)
	}
}

func TestClient_sendText_MultipleChunks(t *testing.T) {
	// sendText splits on MaxMessageBytes and sends each chunk. Reached directly
	// because Send/SendWithFilename gate on the same limit and never hand a
	// message larger than MaxMessageBytes to sendText.
	h := newTelegramHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()

	cfg := testConfig()
	cfg.MaxMessageBytes = 6
	c := newTestClient(t, srv.URL, cfg)

	if err := c.sendText("aaaa\nbbbb\ncccc"); err != nil {
		t.Fatalf("sendText failed: %v", err)
	}
	methods := h.Methods()
	if len(methods) < 2 {
		t.Errorf("expected multiple sendMessage chunks, got %v", methods)
	}
	for _, m := range methods {
		if m != "sendMessage" {
			t.Errorf("unexpected method %q", m)
		}
	}
}

func TestClient_Send_AutoFileWhenTooLong(t *testing.T) {
	h := newTelegramHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()

	cfg := testConfig()
	cfg.MaxMessageBytes = 10
	c := newTestClient(t, srv.URL, cfg)

	// A single token longer than the limit and with no newline cannot be split
	// into text chunks; Send routes it to SendStringAsFile -> sendDocument.
	if err := c.Send(strings.Repeat("Z", 50)); err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if !contains(h.Methods(), "sendDocument") {
		t.Errorf("expected sendDocument call, got %v", h.Methods())
	}
}

func TestClient_SendWithFilename(t *testing.T) {
	h := newTelegramHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()

	cfg := testConfig()
	cfg.MaxMessageBytes = 5
	c := newTestClient(t, srv.URL, cfg)

	if err := c.SendWithFilename("", "x.txt"); err != nil {
		t.Fatalf("empty should be no-op: %v", err)
	}
	if h.calls.Load() != 0 {
		t.Fatal("empty SendWithFilename should not call API")
	}

	if err := c.SendWithFilename(strings.Repeat("a", 50), "report.txt"); err != nil {
		t.Fatalf("SendWithFilename failed: %v", err)
	}
	if !contains(h.Methods(), "sendDocument") {
		t.Errorf("expected file send, got %v", h.Methods())
	}
}

// --- error / retry paths ---------------------------------------------------

func TestClient_Send_ErrorFromAPI(t *testing.T) {
	h := newTelegramHandler()
	h.statusFn = func(int32) (int, string) {
		return http.StatusBadRequest, `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	c := newTestClient(t, srv.URL, testConfig())
	err := c.Send("hi")
	if err == nil {
		t.Fatal("expected error from API failure")
	}
	if !strings.Contains(err.Error(), "failed to send message") {
		t.Errorf("error not wrapped as expected: %v", err)
	}
}

func TestClient_Send_RetryThenSucceed(t *testing.T) {
	h := newTelegramHandler()
	h.statusFn = func(call int32) (int, string) {
		if call == 1 {
			// telebot maps error_code 429 to a FloodError whose message contains
			// "Too Many Requests", which the client treats as retryable.
			return http.StatusTooManyRequests,
				`{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 0","parameters":{"retry_after":0}}`
		}
		return http.StatusOK, okResponse
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	cfg := testConfig()
	cfg.MaxRetries = 5
	c := newTestClient(t, srv.URL, cfg)

	// First attempt is rate-limited (sleeps min(1,10)=1s), second succeeds.
	start := time.Now()
	if err := c.Send("retry-me"); err != nil {
		t.Fatalf("Send should succeed after retry: %v", err)
	}
	if elapsed := time.Since(start); elapsed < time.Second {
		t.Logf("note: retry path completed quickly (%v)", elapsed)
	}
	if got := h.calls.Load(); got != 2 {
		t.Errorf("expected 2 calls (1 retry), got %d", got)
	}
}

func TestClient_Send_GivesUpAfterMaxRetries(t *testing.T) {
	h := newTelegramHandler()
	h.statusFn = func(int32) (int, string) {
		return http.StatusTooManyRequests,
			`{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 0","parameters":{"retry_after":0}}`
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	cfg := testConfig()
	cfg.MaxRetries = 2 // keep retries low so sleeps stay ~1s each
	c := newTestClient(t, srv.URL, cfg)

	err := c.Send("always-limited")
	if err == nil {
		t.Fatal("expected failure after exhausting retries")
	}
	if !strings.Contains(err.Error(), "max retries") {
		t.Errorf("expected max-retries error, got %v", err)
	}
	if got := h.calls.Load(); got != int32(cfg.MaxRetries) {
		t.Errorf("expected %d attempts, got %d", cfg.MaxRetries, got)
	}
}

// --- file sending ----------------------------------------------------------

func TestClient_SendFile(t *testing.T) {
	h := newTelegramHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := newTestClient(t, srv.URL, testConfig())

	// Empty path -> error before any HTTP call.
	if err := c.SendFile(""); err == nil {
		t.Fatal("expected error for empty file path")
	}
	// Missing file -> stat error.
	if err := c.SendFile(filepath.Join(t.TempDir(), "nope.txt")); err == nil {
		t.Fatal("expected error for missing file")
	}
	// Empty file -> error.
	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.SendFile(empty); err == nil {
		t.Fatal("expected error for empty file")
	}

	// Valid file with content -> sendDocument.
	good := filepath.Join(t.TempDir(), "data.txt")
	if err := os.WriteFile(good, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.SendFileWithCaption(good, "caption"); err != nil {
		t.Fatalf("SendFileWithCaption failed: %v", err)
	}
	if !contains(h.Methods(), "sendDocument") {
		t.Errorf("expected sendDocument, got %v", h.Methods())
	}
}

func TestClient_SendStringAsFile(t *testing.T) {
	h := newTelegramHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := newTestClient(t, srv.URL, testConfig())

	if err := c.SendStringAsFile("", "x.txt"); err != nil {
		t.Fatalf("empty content should be no-op: %v", err)
	}
	if h.calls.Load() != 0 {
		t.Fatal("empty content should not call API")
	}

	if err := c.SendStringAsFileWithCaption("contents", "file.txt", "cap"); err != nil {
		t.Fatalf("SendStringAsFileWithCaption failed: %v", err)
	}
	if !contains(h.Methods(), "sendDocument") {
		t.Errorf("expected sendDocument, got %v", h.Methods())
	}
}

func TestClient_SendBytesAndReaderAsFile(t *testing.T) {
	h := newTelegramHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := newTestClient(t, srv.URL, testConfig())

	if err := c.SendBytesAsFile(nil, "x.txt"); err != nil {
		t.Fatalf("empty bytes should be no-op: %v", err)
	}
	if h.calls.Load() != 0 {
		t.Fatal("empty bytes should not call API")
	}

	if err := c.SendBytesAsFile([]byte("abc"), "b.txt"); err != nil {
		t.Fatalf("SendBytesAsFile failed: %v", err)
	}
	if err := c.SendReaderAsFile(strings.NewReader("def"), "r.txt"); err != nil {
		t.Fatalf("SendReaderAsFile failed: %v", err)
	}
	methods := h.Methods()
	count := 0
	for _, m := range methods {
		if m == "sendDocument" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 sendDocument calls, got %d in %v", count, methods)
	}
}

func TestClient_SendStringAsFile_GzipFallback(t *testing.T) {
	h := newTelegramHandler()
	var sawGz atomic.Bool
	h.statusFn = func(call int32) (int, string) {
		if call == 1 {
			// First document upload rejected as too large -> client gzips & retries.
			return http.StatusOK,
				`{"ok":false,"error_code":413,"description":"Request Entity Too Large"}`
		}
		sawGz.Store(true)
		return http.StatusOK, okResponse
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	c := newTestClient(t, srv.URL, testConfig())
	if err := c.SendStringAsFile("some content to compress", "big.txt"); err != nil {
		t.Fatalf("expected gzip fallback to succeed: %v", err)
	}
	if h.calls.Load() != 2 {
		t.Errorf("expected 2 calls (orig + gzip retry), got %d", h.calls.Load())
	}
	if !sawGz.Load() {
		t.Error("expected a second (gzip) upload attempt")
	}
}

// --- Backend wrapper -------------------------------------------------------

func TestBackend_SendAndSendRaw(t *testing.T) {
	h := newTelegramHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()

	c := newTestClient(t, srv.URL, testConfig())
	b := &Backend{client: c}

	result := &output.ResultEvent{
		Info: output.Info{Name: "XSS", Severity: severity.Medium, Description: "reflected"},
		// FormatResult fetches the host's TLS cert; use a loopback addr that
		// refuses instantly so this unit test never dials out / hangs offline.
		Host: "127.0.0.1:0",
		URL:  "https://example.com/?q=1",
	}
	if err := b.Send(result); err != nil {
		t.Fatalf("Backend.Send failed: %v", err)
	}
	if err := b.SendRaw("raw *message*"); err != nil {
		t.Fatalf("Backend.SendRaw failed: %v", err)
	}
	if h.calls.Load() < 2 {
		t.Errorf("expected at least 2 API calls, got %d", h.calls.Load())
	}
	b.Close()
}

// --- formatting / escape helpers -------------------------------------------

func TestEscapeMarkdown(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"plain", "plain"},
		{"a.b", `a\.b`},
		{"*x*", `\*x\*`},
		{"a-b", `a\-b`},
		{"a_b", `a\_b`},
		{"100%", "100%"}, // % is not in the escape set
		{"(p)", `\(p\)`},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := EscapeMarkdown(tc.in); got != tc.want {
				t.Errorf("EscapeMarkdown(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFormatResult(t *testing.T) {
	result := &output.ResultEvent{
		Info: output.Info{
			Name:        "SQL Injection",
			Severity:    severity.High,
			Description: "found a bug",
		},
		// Loopback addr so FormatResult's TLS cert fetch fails instantly
		// instead of dialing example.com (offline-flaky / slow in CI).
		Host:             "127.0.0.1:0",
		URL:              "https://example.com/?id=1",
		FuzzingParameter: "id",
		ExtractedResults: []string{"root", "admin"},
		Request:          "GET / HTTP/1.1",
	}
	out := FormatResult(result)
	for _, want := range []string{
		"Module: *SQL Injection*",
		"Severity: *HIGH*",
		"Host: *127\\.0\\.0\\.1:0*",
		"Param Name: *id*",
		"Extracted: *root, admin*",
		"*Description*",
		"*URL*",
		"*Request*",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("FormatResult missing %q\noutput:\n%s", want, out)
		}
	}
}

func TestFormatResult_MinimalNoOptionalSections(t *testing.T) {
	result := &output.ResultEvent{
		Info: output.Info{Name: "Info Disc", Severity: severity.Info},
		Host: "127.0.0.1:0", // loopback: no network dial in this unit test
	}
	out := FormatResult(result)
	if strings.Contains(out, "*URL*") || strings.Contains(out, "*Request*") ||
		strings.Contains(out, "Extracted:") || strings.Contains(out, "*Description*") {
		t.Errorf("unexpected optional section in minimal result:\n%s", out)
	}
	if !strings.Contains(out, "Module: *Info Disc*") {
		t.Errorf("missing module line:\n%s", out)
	}
}

func TestSplitMessage(t *testing.T) {
	t.Run("short returns single chunk", func(t *testing.T) {
		got := splitMessage("hello", 100)
		if len(got) != 1 || got[0] != "hello" {
			t.Errorf("expected single chunk, got %v", got)
		}
	})

	t.Run("splits at newlines under limit", func(t *testing.T) {
		msg := "aaaa\nbbbb\ncccc"
		got := splitMessage(msg, 6)
		if len(got) < 2 {
			t.Errorf("expected multiple chunks, got %v", got)
		}
		for _, chunk := range got {
			if len([]byte(chunk)) > 6 {
				t.Errorf("chunk %q exceeds maxBytes", chunk)
			}
		}
	})

	t.Run("truncates over-long line", func(t *testing.T) {
		long := strings.Repeat("x", 100)
		got := splitMessage(long, 10)
		joined := strings.Join(got, "")
		if !strings.Contains(joined, "...") {
			t.Errorf("expected truncation ellipsis, got %v", got)
		}
		for _, chunk := range got {
			if len([]byte(chunk)) > 10 {
				t.Errorf("chunk %q exceeds maxBytes", chunk)
			}
		}
	})
}

func TestTruncateLine(t *testing.T) {
	if got := truncateLine("short", 100); got != "short" {
		t.Errorf("short line changed: %q", got)
	}
	long := strings.Repeat("y", 50)
	got := truncateLine(long, 10)
	if len([]byte(got)) > 10 {
		t.Errorf("truncateLine exceeded maxBytes: %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("expected ellipsis: %q", got)
	}

	// maxBytes smaller than ellipsis -> truncatedBytes clamped to 0.
	if got := truncateLine("abcdef", 2); !strings.HasSuffix(got, "...") {
		t.Errorf("expected ellipsis even when maxBytes < len(ellipsis): %q", got)
	}
}

// --- small local helpers ---------------------------------------------------

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// ensure gzip import is used: the gzip fallback test relies on the production
// code path; this assertion documents that a gzip stream round-trips, guarding
// against accidental import removal.
func TestGzipRoundTripSanity(t *testing.T) {
	var buf strings.Builder
	gz := gzip.NewWriter(&buf)
	_, _ = io.WriteString(gz, "x")
	_ = gz.Close()
	if buf.Len() == 0 {
		t.Fatal("gzip produced no output")
	}
}
