package http_method_tampering

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

// TestScanPerRequest_CatchAllEndpoint reproduces the reported false positive:
// an endpoint (à la DataDome /js/) that returns a 2xx, non-shell, per-request
// changing body for ANY method — so the wildcard/baseline shell checks are
// defeated and a dangerous method or honored override looks "enabled". The
// catch-all guard sends an unsupported sentinel method, sees it accepted just
// the same, and reports nothing.
func TestScanPerRequest_CatchAllEndpoint(t *testing.T) {
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// 2xx + meaningful, per-request-varying body for ANY method (incl. the sentinel).
		c := atomic.AddInt64(&n, 1)
		_, _ = fmt.Fprintf(w, "<html><body>request %020d accepted and processed ok by the service</body></html>", c)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/js/"),
		"text/html",
		"<html><body>request 00000000000000000000 accepted and processed ok by the service</body></html>",
	)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("a catch-all endpoint (2xx for any method) must not be reported, got %d: %+v", len(res), res)
	}
}

// TestScanPerRequest_DangerousMethodEnabled is the positive counterpart: a real
// endpoint that serves write methods but rejects unknown methods with 405. The
// sentinel probe is rejected, so the catch-all guard does NOT fire and the
// genuine finding survives.
func TestScanPerRequest_DangerousMethodEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			_, _ = io.WriteString(w, "<html><body>resource listing: alpha beta gamma delta epsilon zeta</body></html>")
		case "OPTIONS":
			w.Header().Set("Allow", "GET, PUT, DELETE, PATCH")
			w.WriteHeader(http.StatusNoContent)
		case "PUT", "DELETE", "PATCH", "MKCOL", "MOVE", "COPY":
			t.Fatal("safe capability audit must never send a state-changing method: " + r.Method)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = io.WriteString(w, "method not allowed")
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/item/42"),
		"text/html",
		"<html><body>resource listing: alpha beta gamma delta epsilon zeta</body></html>",
	)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) == 0 {
		t.Fatal("expected an observation for methods declared by OPTIONS")
	}
	if res[0].RecordKind != output.RecordKindObservation {
		t.Fatalf("declared capability must be an observation, got %q", res[0].RecordKind)
	}
}

// TestScanPerRequest_OverrideIgnored_EmptyBody reproduces the reported false
// positive: an SSO/auth endpoint (à la PingFederate /idp/.../SSO.ping) that
// answers POST — with or without a method-override header — with a body-less
// 200 wrapped in large headers (CSP, etc.). The old code passed the FULL raw
// response (headers + body) to the body-meaningfulness check, so the kilobytes
// of headers defeated the "empty 200" guard and the ignored override was
// reported. Body-meaningfulness is now judged on the BODY alone, so an empty
// 200 is not "successful" and nothing is reported.
func TestScanPerRequest_OverrideIgnored_EmptyBody(t *testing.T) {
	const csp = "default-src 'self' *.example.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' cdn.example.com analytics.example.com; style-src * 'self' 'unsafe-inline'; img-src * data:; connect-src *; frame-ancestors 'self'"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Large headers, no body — identical for every method and every header.
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("Set-Cookie", "PF=abc123; Path=/; Secure; HttpOnly; SameSite=None")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/idp/x/resumeSAML20/idp/SSO.ping"), "text/html", "")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("a body-less 200 (override ignored) must not be reported, got %d: %+v", len(res), res)
	}
}

// TestScanPerRequest_OverrideIgnored_SameBody isolates the differential gate:
// the server returns a meaningful, non-shell body for POST but IGNORES the
// override header (same body with or without it), rejects direct write methods
// with 405, and rejects the unsupported sentinel with 405 (so the catch-all
// guard does not fire). The override candidate is meaningful and non-shell, yet
// because the plain-POST control returns the same page the header had no
// observable effect — so nothing is reported.
func TestScanPerRequest_OverrideIgnored_SameBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			_, _ = io.WriteString(w, "<html><body>account overview: name email phone address billing</body></html>")
		case "POST":
			// Ignores the override header entirely: same response either way.
			_, _ = io.WriteString(w, "<html><body>your request was received and is being processed by us</body></html>")
		default: // direct PUT/DELETE/PATCH/... and the VIGOLIUMX sentinel
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = io.WriteString(w, "method not allowed")
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/account"), "text/html",
		"<html><body>account overview: name email phone address billing</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("an ignored override (response unchanged vs plain POST) must not be reported, got %d: %+v", len(res), res)
	}
}

// TestScanPerRequest_OverrideRespected is the positive counterpart: the server
// genuinely honors X-HTTP-Method-Override, returning a DELETE-specific response
// that differs from a plain POST. Direct write methods and the sentinel are
// rejected with 405 (so neither the dangerous-method phase nor the catch-all
// guard fires), leaving the override differential as the sole, confirmed signal.
func TestScanPerRequest_OverrideRespected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.Header.Get("X-HTTP-Method-Override") == "OPTIONS" {
			w.Header().Set("Allow", "GET, PUT")
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "GET, PUT")
			return
		}
		switch r.Method {
		case "GET":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<html><body>resource 42 listing: created updated owner tags status</body></html>")
		case "OPTIONS":
			w.Header().Set("Allow", "GET, PUT")
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "GET, PUT")
		default:
			t.Fatal("safe override audit sent an unexpected method: " + r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/api/item/42"), "text/html",
		"<html><body>resource 42 listing: created updated owner tags status</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) == 0 {
		t.Fatal("expected observations for declared methods and a reproducible safe override")
	}
	foundOverride := false
	for _, result := range res {
		if result.Info.Name == "HTTP Method Override Mechanism Observed" {
			foundOverride = true
			if result.RecordKind != output.RecordKindObservation {
				t.Fatalf("override capability must be an observation, got %q", result.RecordKind)
			}
		}
	}
	if !foundOverride {
		t.Fatal("expected safe OPTIONS override observation")
	}
}

// TestScanPerRequest_OverrideNonDeterministicToken reproduces the dominant
// reported false positive: an analytics/attestation endpoint (à la
// /web-analytics/web/init_client or BootstrapAttestationSession) that mints a
// FRESH random token on every POST and ignores the method-override header. The
// override response differs from a single plain-POST control only because of the
// per-request token, so the old single-sample differential concluded the override
// was "respected". The determinism gate takes a SECOND no-override control, sees
// the two controls differ from each other by the same random amount, and reports
// nothing. The direct write methods and the sentinel are rejected with 405 so the
// override differential is the sole candidate signal.
func TestScanPerRequest_OverrideNonDeterministicToken(t *testing.T) {
	// freshToken mimics a base64 attestation token: ~120 non-hex letters (so the
	// similarity normalizer, which collapses long hex/digit runs, does NOT erase
	// it) that changes completely from one request to the next.
	freshToken := func(c int64) string {
		const alpha = "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ+/" // all non-hex
		b := make([]byte, 120)
		for i := range b {
			b[i] = alpha[(int(c)*31+i*7)%len(alpha)]
		}
		return string(b)
	}
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET", "POST":
			// Fresh high-entropy token on every request, verb/override ignored.
			c := atomic.AddInt64(&n, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"cid":"c%d","token":"%s"}`, c, freshToken(c))
		default: // direct PUT/DELETE/... and the VIGOLIUMX sentinel
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = io.WriteString(w, "method not allowed")
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/web-analytics/web/init_client"),
		"application/json", `{"cid":"c0","token":"`+freshToken(0)+`"}`)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("a non-deterministic per-request-token endpoint (override ignored) must not be reported, got %d: %+v", len(res), res)
	}
}

// TestScanPerRequest_AuraSoftError reproduces the Salesforce Aura false positive:
// the framework endpoint answers a DELETE with an HTTP 200 aura:invalidSession
// event (the CSRF/session token was rejected, so nothing was performed). Such a
// soft-error 200 must not count as an enabled write method.
func TestScanPerRequest_AuraSoftError(t *testing.T) {
	const auraErr = `{"event":{"descriptor":"markup://aura:invalidSession","attributes":{"values":{"newToken":"x"}}},"exceptionEvent":true}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			_, _ = io.WriteString(w, `{"actions":[{"state":"SUCCESS","returnValue":{"listing":"alpha beta"}}]}`)
			return
		}
		// Any other verb (incl. DELETE and the sentinel) → 200 invalidSession event.
		_, _ = io.WriteString(w, auraErr)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/s/sfsites/aura?r=4&aura.ApexAction.execute=1"),
		"application/json", `{"actions":[{"state":"SUCCESS","returnValue":{"listing":"alpha beta"}}]}`)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("an Aura invalidSession 200 (action not performed) must not be reported, got %d: %+v", len(res), res)
	}
}

// TestScanPerRequest_VerbAgnosticRead reproduces the geo/beacon false positive
// (à la /cookies/api/user_location answering any verb with the same location
// JSON): a MOVE/PUT returns exactly what a benign GET returns because the server
// routed it to the same read handler. The GET control is similar to the
// dangerous-method response, so the verb was ignored and nothing is reported. The
// sentinel is accepted too, but the verb-agnostic gate fires first regardless.
func TestScanPerRequest_VerbAgnosticRead(t *testing.T) {
	const loc = `{"country":"AU","region":"nsw","regionSubdivision":"AUNSW","city":"sydney"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Same read response for EVERY method (GET, PUT, DELETE, MOVE, sentinel).
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, loc)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/cookies/api/user_location"), "application/json", loc)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("a verb-agnostic read endpoint (MOVE returns same as GET) must not be reported, got %d: %+v", len(res), res)
	}
}

// TestScanPerRequest_ContentTypeFlipSPA reproduces the static-asset-on-a-SPA
// false positive (à la /site.webmanifest): a GET serves the real asset
// (non-HTML), but a PUT is swallowed by the catch-all SPA renderer and returns an
// HTML document. The content-type flip (non-HTML GET → HTML write) marks the SPA
// render, so the "PUT enabled" candidate is dropped. Direct write methods 2xx
// (SPA render) but the sentinel is rejected so the catch-all guard does not fire.
func TestScanPerRequest_ContentTypeFlipSPA(t *testing.T) {
	const manifest = `{"name":"Easy Lens","short_name":"EasyLens","icons":[],"start_url":"/","display":"standalone"}`
	const shell = `<!doctype html><html><head><title>Easy Lens</title></head><body><div id="root">loading the app now</div></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			w.Header().Set("Content-Type", "application/manifest+json")
			_, _ = io.WriteString(w, manifest)
		case "PUT", "DELETE", "PATCH", "MKCOL", "MOVE", "COPY":
			// Catch-all SPA renderer: HTML shell for any write verb.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, shell)
		default: // VIGOLIUMX sentinel rejected → catch-all guard does not fire
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = io.WriteString(w, "method not allowed")
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/site.webmanifest"), "application/manifest+json", manifest)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("a content-type flip to an HTML SPA shell (verb swallowed by the renderer) must not be reported, got %d: %+v", len(res), res)
	}
}

func TestIsSuccessfulMethod(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		want       bool
	}{
		{
			name:       "200 with meaningful body is successful",
			statusCode: 200,
			body:       "<html><body>Welcome to the admin panel, you have full access</body></html>",
			want:       true,
		},
		{
			name:       "405 is not successful",
			statusCode: 405,
			body:       "Method Not Allowed",
			want:       false,
		},
		{
			name:       "403 is not successful",
			statusCode: 403,
			body:       "Forbidden",
			want:       false,
		},
		{
			name:       "200 with method not allowed in body is not successful",
			statusCode: 200,
			body:       "<html>Method Not Allowed for this resource</html>",
			want:       false,
		},
		{
			name:       "200 with not supported in body is not successful",
			statusCode: 200,
			body:       "<html>This HTTP method is not supported on this endpoint</html>",
			want:       false,
		},
		{
			name:       "200 with login redirect is not successful",
			statusCode: 200,
			body:       "<html>Redirecting to /login please authenticate first</html>",
			want:       false,
		},
		{
			name:       "200 aura:invalidSession soft-error is not successful",
			statusCode: 200,
			body:       `{"event":{"descriptor":"markup://aura:invalidSession"},"exceptionEvent":true}`,
			want:       false,
		},
		{
			name:       "200 with empty body is not successful",
			statusCode: 200,
			body:       "",
			want:       false,
		},
		{
			name:       "200 with very short body is not successful",
			statusCode: 200,
			body:       "OK",
			want:       false,
		},
		{
			name:       "500 is not successful",
			statusCode: 500,
			body:       "Internal Server Error",
			want:       false,
		},
		{
			name:       "302 is not successful",
			statusCode: 302,
			body:       "",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSuccessfulMethod(tt.statusCode, tt.body)
			if got != tt.want {
				t.Errorf("isSuccessfulMethod(%d, ...) = %v, want %v", tt.statusCode, got, tt.want)
			}
		})
	}
}
