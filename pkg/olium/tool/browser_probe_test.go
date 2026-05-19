package tool

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas"
)

func TestBrowserProbeSchemaShape(t *testing.T) {
	tool := NewBrowserProbe()
	schema := tool.Schema()

	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema missing properties")
	}
	for _, p := range []string{"url", "wait_ms", "wait_selector", "nav_timeout_ms"} {
		if _, ok := props[p]; !ok {
			t.Errorf("schema missing property %q", p)
		}
	}
	required, _ := schema["required"].([]string)
	if len(required) == 0 || required[0] != "url" {
		t.Errorf("schema required = %v, want [url]", required)
	}

	if tool.IsReadOnly() {
		t.Errorf("browser_probe must report IsReadOnly=false (executes attacker JS)")
	}
}

func TestBrowserProbeRequiresURL(t *testing.T) {
	tool := NewBrowserProbe()
	res, err := tool.Execute(context.Background(), map[string]any{}, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.IsError {
		t.Errorf("expected IsError when url missing")
	}
}

func TestBrowserProbeReportsDialog(t *testing.T) {
	called := false
	probe := func(ctx context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		called = true
		if cfg.URL != "https://example.com/?p=x" {
			t.Errorf("probe got URL %q", cfg.URL)
		}
		return &spitolas.ProbeResult{
			FinalURL: cfg.URL,
			Title:    "Example",
			Dialogs: []spitolas.DialogEvent{
				{Type: "alert", Message: "vig-x-12345", URL: cfg.URL, At: time.Now()},
			},
		}, nil
	}

	tool := &browserProbeTool{probe: probe}
	res, err := tool.Execute(context.Background(), map[string]any{
		"url": "https://example.com/?p=x",
	}, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !called {
		t.Fatalf("probe not invoked")
	}
	if res.IsError {
		t.Fatalf("unexpected IsError; content=%s", res.Content)
	}
	if !strings.Contains(res.Content, "vig-x-12345") {
		t.Errorf("content missing dialog message: %s", res.Content)
	}
	if got, _ := res.Details["dialog_fired"].(bool); !got {
		t.Errorf("Details.dialog_fired = false, want true")
	}
}

func TestBrowserProbeNoDialog(t *testing.T) {
	probe := func(ctx context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		return &spitolas.ProbeResult{FinalURL: cfg.URL, Title: "OK"}, nil
	}
	tool := &browserProbeTool{probe: probe}
	res, err := tool.Execute(context.Background(), map[string]any{"url": "https://example.com"}, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected IsError")
	}
	if got, _ := res.Details["dialog_fired"].(bool); got {
		t.Errorf("Details.dialog_fired = true, want false")
	}
	if !strings.Contains(res.Content, "No JavaScript dialogs") {
		t.Errorf("content missing no-dialogs note: %s", res.Content)
	}
}

func TestBrowserProbeNavErrorWithDialogStillSucceeds(t *testing.T) {
	// javascript: URLs and similar can return a navigation error even though
	// the page already executed JS and fired a dialog. The tool should still
	// report success when dialogs are present.
	probe := func(ctx context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		return &spitolas.ProbeResult{
			Dialogs: []spitolas.DialogEvent{{Type: "alert", Message: "fired"}},
		}, errors.New("navigation aborted")
	}
	tool := &browserProbeTool{probe: probe}
	res, err := tool.Execute(context.Background(), map[string]any{"url": "x"}, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected success despite nav error; content=%s", res.Content)
	}
}

func TestBrowserProbeNavErrorNoDialogFails(t *testing.T) {
	probe := func(ctx context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		return nil, errors.New("connection refused")
	}
	tool := &browserProbeTool{probe: probe}
	res, err := tool.Execute(context.Background(), map[string]any{"url": "x"}, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.IsError {
		t.Errorf("expected IsError on nav failure with no result")
	}
}
