package runner

import (
	"net/url"
	"testing"
)

func TestEvaluateReSpiderCandidate(t *testing.T) {
	const nextShell = `<html><head>` +
		`<script src="/_next/static/chunks/main-abc123.js"></script>` +
		`</head><body><div id="__next"></div>` +
		`<script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>` +
		`</body></html>`

	const emptyReactShell = `<html><body><div id="root"></div>` +
		`<script src="/static/js/runtime.1234ab.js"></script>` +
		`<script src="/static/js/main.5678cd.js"></script></body></html>`

	const interactivePage = `<html><body><h1>Account</h1>` +
		`<form action="/save"><input type="text" name="name"><button>Save</button></form>` +
		`</body></html>`

	const staticPage = `<html><body><h1>About us</h1><p>` +
		`We are a company that does many things and writes a lot of prose here.</p></body></html>`

	const loginPage = `<html><body><form method="post">` +
		`<input type="text" name="user"><input type="password" name="pass"></form></body></html>`

	tests := []struct {
		name     string
		in       respiderInput
		wantKeep bool
		wantWhy  string // checked when not kept (or as the keep reason)
	}{
		{"spa next shell", respiderInput{URL: "https://app.x.com/console/", StatusCode: 200, ContentType: "text/html", Body: []byte(nextShell)}, true, "spa"},
		{"empty react shell", respiderInput{URL: "https://app.x.com/dashboard/", StatusCode: 200, ContentType: "text/html", Body: []byte(emptyReactShell)}, true, "spa-shell"},
		{"interactive form", respiderInput{URL: "https://app.x.com/account/", StatusCode: 200, ContentType: "text/html", Body: []byte(interactivePage)}, true, "interactive"},
		{"static prose page", respiderInput{URL: "https://app.x.com/about/", StatusCode: 200, ContentType: "text/html", Body: []byte(staticPage)}, false, "static"},
		{"login body password field", respiderInput{URL: "https://app.x.com/portal/", StatusCode: 200, ContentType: "text/html", Body: []byte(loginPage)}, false, "login"},
		{"login url path", respiderInput{URL: "https://app.x.com/login", StatusCode: 200, ContentType: "text/html", Body: []byte(nextShell)}, false, "login"},
		{"3xx to idp", respiderInput{URL: "https://app.x.com/console/", StatusCode: 302, ContentType: "text/html", Location: "https://login.microsoftonline.com/abc/oauth2/authorize", Body: nil}, false, "login"},
		{"static asset ct", respiderInput{URL: "https://app.x.com/styles/", StatusCode: 200, ContentType: "text/css", Body: []byte("body{}")}, false, "asset"},
		{"file extension path", respiderInput{URL: "https://app.x.com/app.js", StatusCode: 200, ContentType: "text/html", Body: []byte(nextShell)}, false, "bad-path"},
		{"non-200", respiderInput{URL: "https://app.x.com/admin/", StatusCode: 404, ContentType: "text/html", Body: []byte(nextShell)}, false, "non-200"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := evaluateReSpiderCandidate(tt.in)
			if v.Keep != tt.wantKeep {
				t.Fatalf("Keep = %v, want %v (reason=%q)", v.Keep, tt.wantKeep, v.Reason)
			}
			if v.Reason != tt.wantWhy {
				t.Fatalf("Reason = %q, want %q", v.Reason, tt.wantWhy)
			}
			if v.Keep && v.ShellHash == "" {
				t.Fatalf("kept candidate has empty ShellHash")
			}
		})
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestShellFingerprintDedup(t *testing.T) {
	// Two SPA routes that serve the same bundle (same <script src> set, only the
	// volatile chunk hashes differ) must collapse to one shell key.
	routeA := []byte(`<div id="root"></div><script src="/static/js/main.aaaa11.js"></script>`)
	routeB := []byte(`<div id="root"></div><script src="/static/js/main.bbbb22.js"></script>`)
	routeC := []byte(`<div id="root"></div><script src="/assets/other.cccc33.js"></script>`)

	a := shellFingerprint(mustParseURL(t, "https://app.x.com/console/"), routeA)
	b := shellFingerprint(mustParseURL(t, "https://app.x.com/dashboard/"), routeB)
	c := shellFingerprint(mustParseURL(t, "https://app.x.com/admin/"), routeC)

	if a != b {
		t.Errorf("same-bundle routes should dedup: %s != %s", a, b)
	}
	if a == c {
		t.Errorf("different-bundle routes should not dedup")
	}
}

func TestShellFingerprintHostScoped(t *testing.T) {
	// Identical shells on different hosts must NOT collapse (per-host dedup).
	body := []byte(`<div id="root"></div><script src="/static/js/main.aaaa11.js"></script>`)
	a := shellFingerprint(mustParseURL(t, "https://a.example.com/ui/"), body)
	b := shellFingerprint(mustParseURL(t, "https://b.example.com/ui/"), body)
	if a == b {
		t.Errorf("shells on different hosts should not share a key")
	}
}
