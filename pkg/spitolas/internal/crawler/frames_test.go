package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

func TestIframeDiscoverScriptShape(t *testing.T) {
	// The discover script is a plain sync IIFE returning a JSON array; it must
	// stay same-origin only and never brute-force frame names.
	if !strings.HasPrefix(iframeDiscoverScript, "(() => {") {
		t.Errorf("discover script should be a self-invoking function")
	}
	for _, want := range []string{
		"querySelectorAll('iframe, frame')", // reads frames from the live DOM
		"abs.origin !== origin",             // same-origin gate
		"contentDocument",                   // recurse into nested same-origin frames
		"shadowRoot",                        // pierce web-component shadow DOM
		"JSON.stringify(out)",               // returns a JSON array
	} {
		if !strings.Contains(iframeDiscoverScript, want) {
			t.Errorf("discover script missing expected token %q", want)
		}
	}
}

func TestIframeFetchScriptFormat(t *testing.T) {
	// The fetch script carries exactly one %s (the URL list) and must embed a
	// real JSON array without producing a formatting artifact.
	urls := []string{
		"https://example.com/apex/Captcha?source=a",
		"https://example.com/embed?x=1&y=2",
	}
	payload, err := json.Marshal(urls)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	script := fmt.Sprintf(iframeFetchScript, string(payload))

	if strings.Contains(script, "%!") {
		t.Fatalf("script formatting produced an error artifact:\n%s", script)
	}
	if !strings.HasPrefix(script, "(async () => {") {
		t.Errorf("fetch script should be a self-invoking async function")
	}
	if !strings.Contains(script, "/apex/Captcha?source=a") {
		t.Errorf("fetch script missing injected URL; got:\n%s", script)
	}
	// The embedded array must be valid JSON that round-trips to the same URLs.
	start := strings.Index(script, "[")
	end := strings.Index(script, "]")
	if start < 0 || end < 0 || end < start {
		t.Fatalf("could not locate embedded array in script")
	}
	var got []string
	if err := json.Unmarshal([]byte(script[start:end+1]), &got); err != nil {
		t.Fatalf("embedded array is not valid JSON: %v", err)
	}
	if len(got) != len(urls) || got[0] != urls[0] || got[1] != urls[1] {
		t.Errorf("embedded array round-trip mismatch: got %v want %v", got, urls)
	}
}

func TestSelectUnprimedFramesDedupAndCap(t *testing.T) {
	c := &Crawler{}

	// First pass: all new, but capped at 2.
	first := c.selectUnprimedFrames([]string{
		"https://h/a", "https://h/b", "https://h/c",
	}, 2)
	if len(first) != 2 || first[0] != "https://h/a" || first[1] != "https://h/b" {
		t.Fatalf("expected first two URLs under cap, got %v", first)
	}

	// Second pass: a and b are already primed; only the genuinely new URLs return.
	// (c was never selected above because of the cap, so it is still unprimed.)
	second := c.selectUnprimedFrames([]string{
		"https://h/a", "https://h/b", "https://h/c", "https://h/d",
	}, 0)
	want := map[string]bool{"https://h/c": true, "https://h/d": true}
	if len(second) != len(want) {
		t.Fatalf("expected only unprimed URLs, got %v", second)
	}
	for _, u := range second {
		if !want[u] {
			t.Errorf("unexpected URL returned: %q", u)
		}
	}

	// Third pass over the same set yields nothing new.
	if third := c.selectUnprimedFrames([]string{"https://h/c", "https://h/d"}, 0); len(third) != 0 {
		t.Errorf("expected no new URLs on repeat, got %v", third)
	}
}

func TestPrimeIframeAssetsGuards(t *testing.T) {
	// nil page must be a safe no-op regardless of config.
	cfgOn, err := config.New("https://example.com/")
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	cOn := &Crawler{config: cfgOn}
	cOn.primeIframeAssets(context.Background(), nil) // must not panic

	// Disabled priming is a no-op.
	cfgOff, _ := config.New("https://example.com/")
	cfgOff.IframePriming = false
	(&Crawler{config: cfgOff}).primeIframeAssets(context.Background(), nil)

	// Frame crawling disabled also disables iframe priming.
	cfgNoFrames, _ := config.New("https://example.com/")
	cfgNoFrames.CrawlFrames = false
	(&Crawler{config: cfgNoFrames}).primeIframeAssets(context.Background(), nil)
}

func TestIframeConfigDefaults(t *testing.T) {
	cfg, err := config.New("https://example.com/")
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	if !cfg.IframePriming {
		t.Error("IframePriming should default to true")
	}
	if cfg.IframeMaxAssets <= 0 {
		t.Errorf("IframeMaxAssets should default > 0, got %d", cfg.IframeMaxAssets)
	}
	if cfg.NetworkIdleTimeout <= 0 {
		t.Errorf("NetworkIdleTimeout should default > 0, got %s", cfg.NetworkIdleTimeout)
	}
}
