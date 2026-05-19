//go:build integration

package spitolas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestProbeURLCapturesAlert serves a page that calls alert() and asserts
// the probe records the dialog event.
func TestProbeURLCapturesAlert(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head><title>probe-target</title></head>
<body><script>alert("vig-probe-canary-123")</script></body></html>`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := ProbeURL(ctx, ProbeConfig{
		URL:        srv.URL,
		WaitExtra:  500 * time.Millisecond,
		NavTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("ProbeURL: %v", err)
	}
	if len(res.Dialogs) == 0 {
		t.Fatalf("expected at least one dialog, got none")
	}
	found := false
	for _, d := range res.Dialogs {
		if d.Type == "alert" && strings.Contains(d.Message, "vig-probe-canary-123") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("dialog with canary not captured; got %+v", res.Dialogs)
	}
}

// TestProbeURLNoAlert ensures a benign page reports zero dialogs.
func TestProbeURLNoAlert(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><p>nothing happens here</p></body></html>`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := ProbeURL(ctx, ProbeConfig{URL: srv.URL, WaitExtra: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("ProbeURL: %v", err)
	}
	if len(res.Dialogs) != 0 {
		t.Fatalf("expected no dialogs, got %+v", res.Dialogs)
	}
}
