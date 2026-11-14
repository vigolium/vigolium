package dependency_confusion

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

// recordingRegistry is an httptest server that reports the given names as claimed
// (200) and everything else as unclaimed (404), while recording every name it was
// queried for so tests can assert we don't over-query the registry.
type recordingRegistry struct {
	srv     *httptest.Server
	mu      sync.Mutex
	queried []string
}

func newRecordingRegistry(t *testing.T, claimed ...string) *recordingRegistry {
	t.Helper()
	set := make(map[string]struct{}, len(claimed))
	for _, c := range claimed {
		set[c] = struct{}{}
	}
	rr := &recordingRegistry{}
	rr.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The client percent-encodes the scope "/" as %2f; Go decodes it back into
		// r.URL.Path, so the name is the path minus the leading slash.
		name := strings.TrimPrefix(r.URL.Path, "/")
		rr.mu.Lock()
		rr.queried = append(rr.queried, name)
		rr.mu.Unlock()
		if _, ok := set[name]; ok {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name":"` + name + `"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(rr.srv.Close)
	return rr
}

func (rr *recordingRegistry) queriedNames() []string {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	out := make([]string, len(rr.queried))
	copy(out, rr.queried)
	return out
}

func (rr *recordingRegistry) module() *Module {
	m := New()
	m.registry = newRegistryClient(rr.srv.URL, 5*time.Second)
	return m
}

// scanJS buffers one JavaScript response and returns the flush findings.
func scanJS(t *testing.T, m *Module, path, body string) []*output.ResultEvent {
	t.Helper()
	return scanCT(t, m, path, "application/javascript", body)
}

func scanCT(t *testing.T, m *Module, path, ct, body string) []*output.ResultEvent {
	t.Helper()
	resp := modtest.Response(modtest.Request(t, "http://app.example.com"+path), ct, body)
	if _, err := m.ScanPerRequest(resp, &modkit.ScanContext{}); err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	res, err := m.FlushFindings(&modkit.ScanContext{ExternalFetcher: http.DefaultClient})
	if err != nil {
		t.Fatalf("FlushFindings: %v", err)
	}
	return res
}

func findingNames(res []*output.ResultEvent) []string {
	out := make([]string, 0, len(res))
	for _, r := range res {
		out = append(out, r.ExtractedResults...)
	}
	return out
}

func TestScan_JSBundle_UnclaimedScopedFlagged(t *testing.T) {
	reg := newRecordingRegistry(t) // nothing claimed
	m := reg.module()

	body := `import a from "@acme/secret-ui"; import "left-pad"; require("lodash");`
	res := scanJS(t, m, "/static/main.abc123.js", body)

	sortedEq(t, findingNames(res), []string{"@acme/secret-ui"})
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
	f := res[0]
	if f.Info.Severity != ModuleSeverity || f.Info.Confidence != ModuleConfidence {
		t.Errorf("severity/confidence = %v/%v, want %v/%v",
			f.Info.Severity, f.Info.Confidence, ModuleSeverity, ModuleConfidence)
	}
	if f.Metadata["package"] != "@acme/secret-ui" || f.Metadata["scoped"] != true {
		t.Errorf("unexpected metadata: %+v", f.Metadata)
	}

	// Over-query guard: only the one scoped, non-public name is ever queried.
	sortedEq(t, reg.queriedNames(), []string{"@acme/secret-ui"})
}

func TestScan_Claimed_NoFinding(t *testing.T) {
	reg := newRecordingRegistry(t, "@acme/real")
	m := reg.module()
	res := scanJS(t, m, "/app.js", `import a from "@acme/real";`)
	if len(res) != 0 {
		t.Fatalf("expected no finding for claimed name, got %v", findingNames(res))
	}
	sortedEq(t, reg.queriedNames(), []string{"@acme/real"})
}

// TestScan_DoesNotOverQuery is the core "avoid checking non-existing packages too
// much" guard: bare imports, relative imports, node builtins, known-public
// scopes, and non-import string literals must never reach the registry.
func TestScan_DoesNotOverQuery(t *testing.T) {
	reg := newRecordingRegistry(t)
	m := reg.module()
	body := `
		import "left-pad";                    // bare  -> skip
		import "lodash";                      // bare  -> skip
		require("fs");                        // builtin-> skip
		import x from "./local";              // rel   -> skip
		import y from "@angular/core";        // public-> skip
		import z from "@babel/runtime";       // public-> skip
		import w from "@aws-sdk/client-s3";   // public-> skip
		const s = "@fake/not-an-import";      // string-> skip
		import ok from "@acme/internal";      // the only candidate
	`
	res := scanJS(t, m, "/bundle.js", body)
	sortedEq(t, findingNames(res), []string{"@acme/internal"})

	// Exactly one registry call — no wasted lookups on names that don't qualify.
	if q := reg.queriedNames(); len(q) != 1 || q[0] != "@acme/internal" {
		t.Fatalf("expected exactly one query for @acme/internal, got %v", q)
	}
}

func TestScan_NonJSResponse_Ignored(t *testing.T) {
	reg := newRecordingRegistry(t)
	m := reg.module()

	// A package.json served as JSON must be ignored — extraction is JS-only.
	res := scanCT(t, m, "/package.json", "application/json",
		`{"dependencies":{"@acme/internal":"1.0.0"}}`)
	if len(res) != 0 {
		t.Fatalf("expected JSON response ignored, got %v", findingNames(res))
	}
	if q := reg.queriedNames(); len(q) != 0 {
		t.Fatalf("expected no registry queries for non-JS response, got %v", q)
	}
}

func TestScan_IndeterminateRegistry_NoFinding(t *testing.T) {
	// Registry returns 503 for everything: indeterminate, must not accuse.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	m := New()
	m.registry = newRegistryClient(srv.URL, 5*time.Second)
	res := scanJS(t, m, "/app.js", `import a from "@acme/internal";`)
	if len(res) != 0 {
		t.Fatalf("expected no findings on indeterminate registry, got %v", findingNames(res))
	}
}

func TestScan_DedupAcrossResponses(t *testing.T) {
	reg := newRecordingRegistry(t) // nothing claimed
	m := reg.module()

	// Same name in two bundles -> one finding, two observed URLs, one query.
	rr1 := modtest.Response(modtest.Request(t, "http://app.example.com/a.js"), "application/javascript",
		`import x from "@acme/dup";`)
	rr2 := modtest.Response(modtest.Request(t, "http://app.example.com/b.js"), "application/javascript",
		`const y = require("@acme/dup");`)
	if _, err := m.ScanPerRequest(rr1, &modkit.ScanContext{}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ScanPerRequest(rr2, &modkit.ScanContext{}); err != nil {
		t.Fatal(err)
	}
	res, err := m.FlushFindings(&modkit.ScanContext{ExternalFetcher: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 deduped finding, got %d", len(res))
	}
	urls, _ := res[0].Metadata["observed_urls"].([]string)
	if len(urls) != 2 {
		t.Errorf("expected 2 observed URLs, got %v", urls)
	}
	if q := reg.queriedNames(); len(q) != 1 {
		t.Errorf("expected 1 registry query for deduped name, got %v", q)
	}
}

func TestCanProcess(t *testing.T) {
	m := New()
	cases := []struct {
		path, ct, body string
		want           bool
	}{
		{"/app.js", "application/javascript", "x", true},
		{"/app.mjs", "text/plain", "x", true}, // .js-family by URL
		{"/chunk.cjs", "", "x", true},         // .cjs by URL, no CT
		{"/inline", "text/javascript;charset=utf-8", "x", true},
		{"/package.json", "application/json", "{}", false}, // JSON: not JS
		{"/main.js.map", "application/json", "{}", false},  // source map: not JS
		{"/index.html", "text/html", "<html>", false},
		{"/app.js", "application/javascript", "", false}, // empty body
	}
	for _, c := range cases {
		rr := modtest.Response(modtest.Request(t, "http://app.example.com"+c.path), c.ct, c.body)
		if got := m.CanProcess(rr); got != c.want {
			t.Errorf("CanProcess(%s,%q) = %v, want %v", c.path, c.ct, got, c.want)
		}
	}
}

// With external lookups disabled (no ExternalFetcher — the default,
// and always under --offline) the registry receives nothing.
func TestFlushFindings_ExternalLookupsDisabledSendsNothing(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	m := New()
	m.registry = newRegistryClient(srv.URL, 5*time.Second)
	resp := modtest.Response(modtest.Request(t, "http://app.example.com/app.js"), "application/javascript",
		`import x from "@acme-internal/secret-lib";`)
	if _, err := m.ScanPerRequest(resp, &modkit.ScanContext{}); err != nil {
		t.Fatal(err)
	}
	res, err := m.FlushFindings(&modkit.ScanContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 0 || hits.Load() != 0 {
		t.Errorf("findings=%d registry hits=%d, want 0/0 with external lookups off", len(res), hits.Load())
	}
}
