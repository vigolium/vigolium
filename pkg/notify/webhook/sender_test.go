package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
)

func newServer(handler http.HandlerFunc) (*httptest.Server, config.WebhookConfig) {
	srv := httptest.NewServer(handler)
	return srv, config.WebhookConfig{
		URL:        srv.URL,
		TimeoutSec: 5,
	}
}

func TestNewSender_NilWhenURLEmpty(t *testing.T) {
	if NewSender(config.WebhookConfig{}) != nil {
		t.Fatal("expected nil sender for empty config")
	}
	if NewSender(config.WebhookConfig{URL: "   "}) != nil {
		t.Fatal("expected nil sender for whitespace-only URL")
	}
}

func TestSender_Post_Success200(t *testing.T) {
	srv, cfg := newServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", got)
		}
		var body ScanCompletedPayload
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if body.Event != "scan.completed" {
			t.Errorf("unexpected event %q", body.Event)
		}
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	s := NewSender(cfg)
	if s == nil {
		t.Fatal("sender should not be nil")
	}
	err := s.Post(context.Background(), ScanCompletedPayload{
		Event:       "scan.completed",
		ProjectUUID: "p",
		ScanUUID:    "s",
		ScanType:    "native",
		Status:      "completed",
	})
	if err != nil {
		t.Fatalf("Post failed: %v", err)
	}
}

func TestSender_Post_AuthorizationHeader(t *testing.T) {
	want := "Bearer my-token"
	srv, cfg := newServer(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != want {
			t.Errorf("expected Authorization %q, got %q", want, got)
		}
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()
	cfg.Authorization = want

	s := NewSender(cfg)
	if err := s.Post(context.Background(), ScanCompletedPayload{}); err != nil {
		t.Fatalf("Post failed: %v", err)
	}
}

// shrinkBackoff lowers the exponential retry backoff so retry tests exercise the
// full attempt loop without spending real seconds sleeping. The original value is
// restored when the test finishes.
func shrinkBackoff(t *testing.T) {
	t.Helper()
	orig := initialBackoff
	initialBackoff = time.Millisecond
	t.Cleanup(func() { initialBackoff = orig })
}

func TestSender_Post_RetryOn5xx(t *testing.T) {
	shrinkBackoff(t)
	var attempts atomic.Int32
	srv, cfg := newServer(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	s := NewSender(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Post(ctx, ScanCompletedPayload{}); err != nil {
		t.Fatalf("Post failed after retries: %v", err)
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("expected 3 attempts, got %d", got)
	}
}

func TestSender_Post_GivesUpAfterMaxRetries(t *testing.T) {
	shrinkBackoff(t)
	var attempts atomic.Int32
	srv, cfg := newServer(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	})
	defer srv.Close()

	s := NewSender(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	err := s.Post(ctx, ScanCompletedPayload{})
	if err == nil {
		t.Fatal("expected error after maxRetries 5xx")
	}
	if got := attempts.Load(); got != int32(maxRetries) {
		t.Errorf("expected %d attempts, got %d", maxRetries, got)
	}
}

func TestSender_Post_NoRetryOn4xx(t *testing.T) {
	var attempts atomic.Int32
	srv, cfg := newServer(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	})
	defer srv.Close()

	s := NewSender(cfg)
	err := s.Post(context.Background(), ScanCompletedPayload{})
	if err == nil {
		t.Fatal("expected error on 400")
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("expected 1 attempt, got %d", got)
	}
}

func TestSender_Post_PayloadShape(t *testing.T) {
	var got string
	srv, cfg := newServer(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	s := NewSender(cfg)
	payload := ScanCompletedPayload{
		Event:       "scan.completed",
		ProjectUUID: "proj",
		ScanUUID:    "scan",
		ScanType:    "autopilot",
		Target:      "https://x.example",
		Status:      "completed",
		StartedAt:   time.Date(2026, 5, 10, 10, 0, 0, 0, time.UTC),
		FinishedAt:  time.Date(2026, 5, 10, 10, 5, 0, 0, time.UTC),
		Findings: FindingCounts{
			Total: 3,
			BySeverity: map[string]int{
				"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0,
			},
		},
		ResultURL: "gs://proj/agentic-scans/scan/results.tar.gz",
	}
	if err := s.Post(context.Background(), payload); err != nil {
		t.Fatalf("Post failed: %v", err)
	}
	for _, want := range []string{
		`"event":"scan.completed"`,
		`"project_uuid":"proj"`,
		`"scan_uuid":"scan"`,
		`"scan_type":"autopilot"`,
		`"target":"https://x.example"`,
		`"status":"completed"`,
		`"result_url":"gs://proj/agentic-scans/scan/results.tar.gz"`,
		`"by_severity"`,
		`"critical":1`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("payload missing %q\nbody: %s", want, got)
		}
	}
}

func TestWebhookConfig_EffectiveTimeout(t *testing.T) {
	if (&config.WebhookConfig{}).EffectiveTimeout() != 10 {
		t.Error("expected default 10s")
	}
	if (&config.WebhookConfig{TimeoutSec: 3}).EffectiveTimeout() != 3 {
		t.Error("expected configured value")
	}
	if (&config.WebhookConfig{TimeoutSec: -5}).EffectiveTimeout() != 10 {
		t.Error("expected default for non-positive")
	}
}

func TestWebhookConfig_IsConfigured(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.WebhookConfig
		want bool
	}{
		{"empty", config.WebhookConfig{}, false},
		{"whitespace-url", config.WebhookConfig{URL: "  \t"}, false},
		{"with-url", config.WebhookConfig{URL: "https://x"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.IsConfigured(); got != tc.want {
				t.Errorf("IsConfigured = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNotifyConfig_ProviderRouting(t *testing.T) {
	url := "https://x.example"
	cases := []struct {
		name        string
		cfg         config.NotifyConfig
		wantWebhook bool
		wantTele    bool
		wantDisc    bool
	}{
		{
			name:        "master-off-blocks-all",
			cfg:         config.NotifyConfig{Webhook: config.WebhookConfig{URL: url}},
			wantWebhook: false,
			wantTele:    false,
			wantDisc:    false,
		},
		{
			name: "no-provider-allows-all",
			cfg: config.NotifyConfig{
				Enabled: true,
				Webhook: config.WebhookConfig{URL: url},
			},
			wantWebhook: true,
			wantTele:    true,
			wantDisc:    true,
		},
		{
			name: "provider-webhook-blocks-others",
			cfg: config.NotifyConfig{
				Enabled:  true,
				Provider: "webhook",
				Webhook:  config.WebhookConfig{URL: url},
			},
			wantWebhook: true,
			wantTele:    false,
			wantDisc:    false,
		},
		{
			name: "provider-telegram-blocks-others",
			cfg: config.NotifyConfig{
				Enabled:  true,
				Provider: "telegram",
				Webhook:  config.WebhookConfig{URL: url},
			},
			wantWebhook: false,
			wantTele:    true,
			wantDisc:    false,
		},
		{
			name: "provider-case-insensitive",
			cfg: config.NotifyConfig{
				Enabled:  true,
				Provider: "WebHook",
				Webhook:  config.WebhookConfig{URL: url},
			},
			wantWebhook: true,
			wantTele:    false,
			wantDisc:    false,
		},
		{
			name: "provider-webhook-no-url-blocks",
			cfg: config.NotifyConfig{
				Enabled:  true,
				Provider: "webhook",
			},
			wantWebhook: false,
			wantTele:    false,
			wantDisc:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.IsWebhookActive(); got != tc.wantWebhook {
				t.Errorf("IsWebhookActive = %v, want %v", got, tc.wantWebhook)
			}
			if got := tc.cfg.IsProviderActive(config.NotifyProviderTelegram); got != tc.wantTele {
				t.Errorf("IsProviderActive(telegram) = %v, want %v", got, tc.wantTele)
			}
			if got := tc.cfg.IsProviderActive(config.NotifyProviderDiscord); got != tc.wantDisc {
				t.Errorf("IsProviderActive(discord) = %v, want %v", got, tc.wantDisc)
			}
		})
	}
}
