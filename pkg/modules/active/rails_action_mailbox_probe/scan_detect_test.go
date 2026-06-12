package rails_action_mailbox_probe

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// TestScanPerRequest_DetectsMailboxIngress simulates a Rails app whose Action
// Mailbox relay ingress endpoint advertises POST via an Allow header on OPTIONS,
// with a distinct body from the random 404 path.
func TestScanPerRequest_DetectsMailboxIngress(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rails/action_mailbox/relay/inbound_emails" {
			w.Header().Set("Allow", "POST, OPTIONS")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("action_mailbox ingress endpoint present and accepting submissions"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("distinct not found body contents here"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when an Action Mailbox ingress advertises POST")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every probe path
// yields no findings.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host without Action Mailbox endpoints must not yield findings")
}

// TestScanPerRequest_RateLimitedNoFalsePositive reproduces the production false
// positive and isolates the throttle/block status gate. The 429 body carries the
// "ActionMailbox" and "Inbound Emails" markers *literally* (not as a reflected
// path), so the echo guard cannot strip them — only rejecting the throttled
// status prevents the finding. A blocked response never reached the Rails route.
func TestScanPerRequest_RateLimitedNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		if r.Method == http.MethodOptions {
			// Probe replies: a WAF block page that literally names the feature,
			// distinct from the GET fingerprint body so the 404 fingerprint
			// cannot reject it — only the status gate can.
			_, _ = w.Write([]byte("WAF block: ActionMailbox / Inbound Emails ingress is rate limited"))
			return
		}
		_, _ = w.Write([]byte("rate limited"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 429 rate-limit page that echoes the path must not yield a finding")
}

// TestScanPerRequest_SendGridRateLimitedNoFalsePositive covers the SendGrid
// ingress probe specifically: a 429 on /rails/action_mailbox/sendgrid/inbound_emails
// whose body echoes the path (which contains "action_mailbox") must not be
// reported. The SendGrid path lacks "conductor", so before the fix it tripped
// the single "ActionMailbox reference" marker. Mirrors the production scan where
// the edge throttled the OPTIONS probe mid-run while other paths returned 404s.
func TestScanPerRequest_SendGridRateLimitedNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rails/action_mailbox/sendgrid/inbound_emails" {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("Too Many Requests for " + r.URL.Path))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 429 on the SendGrid ingress path must not yield a finding")
}

// TestScanPerRequest_ReflectedPathNoFalsePositive ensures that a response which
// merely echoes the requested path is not mistaken for rendered page content.
// OPTIONS probes get a 405 whose body reflects the path (so the body markers
// would trip without the echo guard), while the GET 404 fingerprint differs —
// isolating the reflection guard as the only thing preventing a finding.
func TestScanPerRequest_ReflectedPathNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte("Method Not Allowed: " + r.URL.Path))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an echoed path must not be mistaken for Action Mailbox page content")
}

// TestScanPerRequest_CORSPreflightNoFalsePositive reproduces the production
// false positive where an API gateway (AWS API Gateway behind Cloudflare)
// answers OPTIONS for the conductor path with a generic 204 CORS preflight:
// Access-Control-Allow-* headers, no body, and no standard Allow header. To
// mirror the real edge, the guaranteed-nonexistent blanket-OPTIONS probe path
// gets API Gateway's 403 "Missing Authentication Token" instead of the preflight
// — so the host-level blanket detector cannot see it, isolating the per-response
// CORS-preflight guard as the only thing preventing the finding. A CORS
// responder proves CORS is enabled, not that the Action Mailbox route exists.
func TestScanPerRequest_CORSPreflightNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			if strings.Contains(r.URL.Path, "vigolium-not-rails") {
				// AWS API Gateway default for unmatched routes.
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"message":"Missing Authentication Token"}`))
				return
			}
			// Generic CORS preflight: all methods advertised, no Allow header.
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "OPTIONS,GET,PUT,POST,DELETE,PATCH,HEAD")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a generic 204 CORS preflight must not be reported as an exposed Action Mailbox endpoint")
}

// TestScanPerRequest_BlanketCORSPreflightNoFalsePositive covers the simpler edge
// where the gateway answers OPTIONS with the same 204 CORS preflight on *every*
// path including the random blanket-probe path. Here the host-level
// detectBlanketOptions short-circuits the scan before any probe runs.
func TestScanPerRequest_BlanketCORSPreflightNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "OPTIONS,GET,PUT,POST,DELETE,PATCH,HEAD")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a blanket CORS-preflight OPTIONS responder must not yield findings")
}

// TestScanPerRequest_DetectsConductorUIByBody confirms the high-severity
// conductor finding is driven by actual rendered page content. The conductor
// path returns a 200 whose body carries the real Action Mailbox conductor
// markers ("Inbound Emails", "Deliver new inbound email"); the GET 404
// fingerprint differs, so only the body content can confirm it.
func TestScanPerRequest_DetectsConductorUIByBody(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rails/conductor/action_mailbox/inbound_emails" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body><h1>Inbound Emails</h1>` +
				`<table><thead><tr><th>id</th><th>status</th></tr></thead></table>` +
				`<a href="/rails/conductor/action_mailbox/inbound_emails/new">Deliver new inbound email</a>` +
				`</body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("distinct not found body contents here"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when the conductor UI renders its real content")

	var conductor *output.ResultEvent
	for _, r := range res {
		if strings.Contains(r.Info.Name, "Conductor UI") {
			conductor = r
		}
	}
	require.NotNil(t, conductor, "expected the Conductor UI finding")
	assert.Equal(t, severity.High, conductor.Info.Severity)
	require.NotEmpty(t, conductor.ExtractedResults)
	joined := strings.Join(conductor.ExtractedResults, " ")
	assert.Contains(t, joined, "Body:", "evidence must cite the rendered body content, not just a status code")
}

// TestScanPerRequest_ConductorBare200NoFalsePositive proves a bare 200 with no
// genuine conductor content is not reported. A blank/landing page on the
// conductor path returns 200 but lacks the rendered Action Mailbox markers, so
// confirming on body content (not status) prevents the finding.
func TestScanPerRequest_ConductorBare200NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rails/conductor/action_mailbox/inbound_emails" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>Welcome to our API</body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a bare 200 without rendered conductor content must not yield a finding")
}

// TestScanPerRequest_Nginx405AllowHeaderNoFalsePositive reproduces the exact
// production false positive: an nginx front-end answers the OPTIONS probe with
// "405 Method Not Allowed", an `Allow: GET, POST` header, and its stock HTML
// status page. The Allow header lists POST (satisfying the route-signal check),
// but the 405 status — the server *rejecting* OPTIONS — plus the GET in the
// Allow list and the nginx status-page body all prove this is a front-end
// rejection for a static/proxied location, not a mounted Rails ingress route.
// Distinct from TestScanPerRequest_ReflectedPathNoFalsePositive, whose 405 mock
// omits the Allow header (caught by the empty-Allow check); the real nginx 405
// includes it and slipped past the guard.
func TestScanPerRequest_Nginx405AllowHeaderNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, POST")
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte("<html>\n<head><title>405 Not Allowed</title></head>\n" +
				"<body>\n<center><h1>405 Not Allowed</h1></center>\n<hr><center></center>\n</body>\n</html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("distinct not found body contents here"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an nginx 405 page advertising `Allow: GET, POST` must not be reported as an exposed Action Mailbox ingress")
}

// TestScanPerRequest_StaticLocation200GetAllowNoFalsePositive isolates the
// POST-only route guard. A front-end static location answers OPTIONS with a
// 200 and an empty body advertising `Allow: GET, POST, HEAD` (the web-server
// methods for a file location). The 2xx status and empty body clear the status
// and status-page guards, so only rejecting an Allow header that includes GET —
// which a Rails POST-only ingress route never advertises — prevents the finding.
// The blanket-OPTIONS probe path is 404'd so detectBlanketOptions does not
// short-circuit the scan first.
func TestScanPerRequest_StaticLocation200GetAllowNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			if strings.Contains(r.URL.Path, "vigolium-not-rails") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Allow", "GET, POST, HEAD")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("distinct not found body contents here"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a static location advertising GET in its Allow header must not be reported as a Rails ingress")
}

// TestCanProcess validates the host-liveness gate.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, New().CanProcess(rr))
	assert.True(t, New().CanProcess(modtest.Response(rr, "text/html", "ok")))
}
