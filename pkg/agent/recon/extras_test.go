package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunJSFingerprint_DetectsNextAndReact(t *testing.T) {
	resp := &probeResponse{
		Body: `<html><head>
			<script id="__NEXT_DATA__">{"props":{}}</script>
			<script src="/_next/static/chunks/main-abc.js"></script>
			<div data-reactroot></div>
			<script>window.react-dom.render(...)</script>
		</head></html>`,
	}
	signals := runJSFingerprint(resp)
	if len(signals) == 0 {
		t.Fatal("expected at least one JS signal")
	}
	got := map[string]string{}
	for _, s := range signals {
		got[s.Name] = s.Tag
	}
	if got["next"] != "nextjs" {
		t.Errorf("expected next/nextjs signal, got: %+v", got)
	}
	// React isn't required (case-fold is on `react-dom`), but if matched
	// it should carry the right tag.
	if v, ok := got["react"]; ok && v != "react" {
		t.Errorf("react signal carried unexpected tag %q", v)
	}
}

func TestRunJSFingerprint_EmptyResponse(t *testing.T) {
	if got := runJSFingerprint(nil); got != nil {
		t.Errorf("expected nil for nil response, got: %+v", got)
	}
	if got := runJSFingerprint(&probeResponse{}); got != nil {
		t.Errorf("expected nil for empty body, got: %+v", got)
	}
}

func TestExtractScriptSrcs(t *testing.T) {
	html := `<head>
		<script src="/_next/static/a.js"></script>
		<script src='/vendor/b.js'></script>
		<script>inline.foo()</script>
		<script src="https://cdn.example.com/c.js" defer></script>
	</head>`
	got := extractScriptSrcs(html)
	want := []string{"/_next/static/a.js", "/vendor/b.js", "https://cdn.example.com/c.js"}
	if len(got) != len(want) {
		t.Fatalf("expected %d srcs, got %d: %+v", len(want), len(got), got)
	}
	for i, src := range want {
		if got[i] != src {
			t.Errorf("src %d: want %q, got %q", i, src, got[i])
		}
	}
}

func TestRunLoginFormScrape_FindsPasswordForms(t *testing.T) {
	resp := &probeResponse{
		Body: `<html><body>
			<form action="/login" method="post">
				<input type="email" name="username">
				<input type="password" name="pw">
				<button type="submit">Log in</button>
			</form>
			<form action="/search"><input type="text" name="q"></form>
		</body></html>`,
	}
	candidates := runLoginFormScrape(resp, "https://example.com/")
	if len(candidates) != 1 {
		t.Fatalf("expected exactly 1 login candidate, got %d", len(candidates))
	}
	c := candidates[0]
	if c.UsernameName != "username" {
		t.Errorf("expected username field 'username', got %q", c.UsernameName)
	}
	if c.PasswordName != "pw" {
		t.Errorf("expected password field 'pw', got %q", c.PasswordName)
	}
	if c.Action != "/login" {
		t.Errorf("expected action '/login', got %q", c.Action)
	}
}

func TestRunLoginFormScrape_NoFormsReturnsNil(t *testing.T) {
	resp := &probeResponse{Body: `<html><body>no forms here</body></html>`}
	if got := runLoginFormScrape(resp, "https://example.com/"); got != nil {
		t.Errorf("expected nil when no login forms present, got: %+v", got)
	}
}

func TestRunMethodMatrix_RecordsNon405(t *testing.T) {
	// Test server: /open accepts PUT (returns 200), DELETE (returns 401),
	// and rejects PATCH with 405. /closed rejects everything with 405.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open":
			switch r.Method {
			case http.MethodPut:
				w.WriteHeader(http.StatusOK)
			case http.MethodDelete:
				w.WriteHeader(http.StatusUnauthorized)
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		case "/closed":
			w.WriteHeader(http.StatusMethodNotAllowed)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := Config{}.effective()
	client := newProbeClient(cfg)
	defer client.CloseIdleConnections()

	out := runMethodMatrix(context.Background(), client, srv.URL, []string{"/open", "/closed"}, cfg)
	if got := out["/open"]; len(got) != 2 || got[0] != http.MethodDelete || got[1] != http.MethodPut {
		t.Errorf("expected /open: [DELETE PUT] (alphabetical), got %+v", got)
	}
	if _, ok := out["/closed"]; ok {
		t.Errorf("/closed should not appear in matrix when only 405s are returned, got %+v", out)
	}
}

func TestVHostVariants(t *testing.T) {
	got := vhostVariants("example.com:8080")
	found := map[string]bool{}
	for _, v := range got {
		found[v] = true
	}
	if !found["localhost"] {
		t.Errorf("expected localhost in vhost variants, got: %+v", got)
	}
	if !found["admin.example.com"] {
		t.Errorf("expected admin.example.com in vhost variants, got: %+v", got)
	}
}

func TestVHostVariants_NoDotHostSkipsAdmin(t *testing.T) {
	got := vhostVariants("localhost")
	for _, v := range got {
		if strings.HasPrefix(v, "admin.") {
			t.Errorf("admin.* variant should not be generated for bare hostname, got: %+v", got)
		}
	}
}

func TestExtractReachablePaths_DedupesAndCaps(t *testing.T) {
	r := &TechStackReport{
		WellKnown: []WellKnownEntry{
			{Path: "/robots.txt", StatusCode: 200},
			{Path: "/sitemap.xml", StatusCode: 200},
		},
		SensitivePaths: []SensitivePathEntry{
			{Path: "/.env", StatusCode: 200},
			{Path: "/robots.txt", StatusCode: 200}, // duplicate — should not double-add
		},
		APISpecs: []APISpecDetection{
			{URL: "https://x/openapi.json", Kind: "openapi"},
		},
	}
	paths := extractReachablePaths(r, 8)
	// / is always seeded.
	wantMin := map[string]bool{"/": true, "/robots.txt": true, "/sitemap.xml": true, "/.env": true, "/openapi.json": true}
	for p := range wantMin {
		found := false
		for _, gotP := range paths {
			if gotP == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected path %q in result, got: %+v", p, paths)
		}
	}
	// No duplicates.
	seen := map[string]int{}
	for _, p := range paths {
		seen[p]++
	}
	for p, n := range seen {
		if n > 1 {
			t.Errorf("path %q appears %d times in result (should be deduped)", p, n)
		}
	}
}

func TestComputeFaviconHash_ReturnsHexOnReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			_, _ = w.Write([]byte("FAVICONBYTES"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := Config{}.effective()
	client := newProbeClient(cfg)
	defer client.CloseIdleConnections()

	got := computeFaviconHash(context.Background(), client, srv.URL, cfg)
	if got == "" {
		t.Fatal("expected non-empty favicon hash")
	}
	if len(got) != 32 {
		t.Errorf("expected 32-char md5 hex, got %d chars: %q", len(got), got)
	}
}
