package crawler

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

func TestServiceWorkerPrimeScriptFormats(t *testing.T) {
	// The template carries exactly one %d (the asset cap) and no stray verbs, so
	// formatting must not produce a %!(error) artifact.
	script := fmt.Sprintf(serviceWorkerPrimeScript, 123)

	if strings.Contains(script, "%!") {
		t.Fatalf("script formatting produced an error artifact:\n%s", script)
	}
	if !strings.Contains(script, "const MAX = 123;") {
		t.Errorf("script missing injected cap; got:\n%s", script)
	}
	if !strings.HasPrefix(script, "(async () => {") {
		t.Errorf("script should be a self-invoking async function")
	}
	// The follow-only sources (read what the live app registers/declares, then
	// parse the manifests it points at) must all be present.
	for _, want := range []string{
		"getRegistrations",        // installed worker (browser-native)
		"location.origin",         //
		"querySelectorAll",        // declared <link rel=manifest>
		"serviceWorker",           // inline register('...') extraction
		"reRegister",              //
		"assetGroups", "hashTable", // Angular ngsw.json parsing
		"entrypoints", "data.files", // React CRA asset-manifest parsing
		"prerendered",     // Nuxt route parsing
		"revision",        // Workbox precache parsing
		"isJsonManifest",  // manifest reader
		"isSW",            // service-worker reader
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing expected token %q", want)
		}
	}

	// Spidering must NOT brute-force well-known filenames — that is the discovery
	// phase's job. No PWA-signal gate and no hand-written guess array may remain;
	// every fetched URL must come from what the app registers or declares.
	for _, forbidden := range []string{
		"pwaSignal",
		"if (pwaSignal)",
		"'safety-worker.js'",
		"'combined-sw.js'",
		"'worker-basic.min.js'",
		"'asset-manifest.json'",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("script must not brute-force paths, but contains %q", forbidden)
		}
	}
}

func TestPrimeServiceWorkerAssetsGuards(t *testing.T) {
	// nil page must be a safe no-op regardless of config.
	cfgOn, err := config.New("https://example.com/")
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	cOn := &Crawler{config: cfgOn}
	cOn.primeServiceWorkerAssets(context.Background(), nil) // must not panic

	// Disabled config is also a no-op (and reaching the nil-page check is fine).
	cfgOff, _ := config.New("https://example.com/")
	cfgOff.ServiceWorkerPriming = false
	cOff := &Crawler{config: cfgOff}
	cOff.primeServiceWorkerAssets(context.Background(), nil) // must not panic
}

func TestServiceWorkerConfigDefaults(t *testing.T) {
	cfg, err := config.New("https://example.com/")
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	if !cfg.ServiceWorkerPriming {
		t.Error("ServiceWorkerPriming should default to true")
	}
	if cfg.ServiceWorkerMaxAssets <= 0 {
		t.Errorf("ServiceWorkerMaxAssets should default > 0, got %d", cfg.ServiceWorkerMaxAssets)
	}
}
