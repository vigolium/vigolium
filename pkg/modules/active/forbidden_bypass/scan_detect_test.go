package forbidden_bypass

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// seed403 builds a request to rawURL with a synthetic 403 baseline response
// attached — the module only attempts a bypass when the original status is
// 401/403.
func seed403(t *testing.T, rawURL string) *httpmsg.HttpRequestResponse {
	t.Helper()
	base := modtest.Request(t, rawURL)
	rawResp := "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: 9\r\n\r\nForbidden"
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(base.Request(), resp)
}

// TestScanPerRequest_DetectsPathBypass drives the real scan method against a
// server that 403s nothing of its own (the 403 baseline is seeded) but serves
// the protected resource for any path mutation, while answering an unrelated
// random path with 404. The mutated 200 is distinguishable from the host's
// wildcard response, so it is reported as a genuine bypass.
func TestScanPerRequest_DetectsPathBypass(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Any path that still references the protected resource serves it; an
		// unrelated path (the wildcard probe) is a genuine 404.
		if strings.Contains(r.URL.Path, "admin") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>SECRET ADMIN PANEL</body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := seed403(t, srv.URL+"/admin")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a path-bypass finding when a mutation reaches the protected resource")
}

// TestScanPerRequest_NoFalsePositive_Catchall reproduces the catch-all false
// positive: the host answers EVERY path — the seeded resource is 403, but every
// mutated payload AND the random wildcard probe return the same 200 SPA shell.
// A status-only check would report every mutation as a bypass; the wildcard
// guard must reject them all.
func TestScanPerRequest_NoFalsePositive_Catchall(t *testing.T) {
	t.Parallel()
	const shell = "<!doctype html><html><head><title>App</title></head><body><div id=root></div></body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusOK) // same 200 shell for every path
		_, _ = w.Write([]byte(shell))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := seed403(t, srv.URL+"/admin")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 200 catch-all shell must not be reported as a 403 bypass")
}

// TestScanPerRequest_NoFalsePositive_EmptyBodyCatchall reproduces the
// bsr.netflix.net false positive: a Google-fronted edge that answers EVERY path
// (the seeded resource, every mutated payload, and a clean random probe) with a
// blank 200 (Content-Length: 0). The wildcard guard (ConfirmNotSoft404)
// misses this because WildcardEntry.IsWildcard requires a non-empty body, and the
// reproducibility gate passes because a blank 200 reproduces perfectly. The
// random-path catch-all guard, which treats two empty bodies as identical, must
// reject it.
func TestScanPerRequest_NoFalsePositive_EmptyBodyCatchall(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Blank 200 for every path — no body written.
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := seed403(t, srv.URL+"/logout")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an empty-body 200 catch-all must not be reported as a 403 bypass")
}

// TestScanPerRequest_NoFalsePositive_WhitespacePayloadRootCollapse reproduces the
// login-uat.example.com false positive. The protected resource
// (/ui-sfdc-javascript-impl/) is 403 and a random path 404s — NOT a catch-all — so
// the wildcard/catch-all guards all pass. The trap is the legacy whitespace payload
// "/ <path> /": its request line "GET / /ui-sfdc-javascript-impl/ / HTTP/1.1" is
// parsed (by our own builder AND the origin) only up to the first interior space,
// collapsing the wire request to "GET /". The server's legitimate homepage 200 was
// then misreported as a path bypass. With the whitespace payloads removed and the
// collapse guard in place, no probe fetches the root, so nothing is reported.
func TestScanPerRequest_NoFalsePositive_WhitespacePayloadRootCollapse(t *testing.T) {
	t.Parallel()
	const homepage = "<!doctype html><html><head><title>Example Portal</title></head>" +
		"<body><h1>Welcome</h1><script>var OneTrust={};</script></body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/" || r.URL.Path == "":
			// Site root: a real, substantial homepage (not a soft-404).
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(homepage))
		case strings.Contains(r.URL.Path, "sfdc"):
			// The genuinely protected resource stays forbidden for every mutation.
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Forbidden"))
		default:
			// Unrelated/random paths are a clean 404 — proving this host is NOT a
			// catch-all, so the existing catch-all guards cannot save us here.
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := seed403(t, srv.URL+"/ui-sfdc-javascript-impl/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a whitespace payload that collapses to the homepage must not be reported as a 403 bypass")
}

// TestScanPerRequest_DetectsTrustedHeaderBypass drives the scan against a backend
// that 403s the protected resource unless the request carries a spoofed
// reverse-proxy identity header (X-Forwarded-User: admin), in which case it serves
// the resource. The bare request stays 403 (causality holds) and an unrelated path
// 404s (not a catch-all), so the per-header trusted-identity probe is reported.
func TestScanPerRequest_DetectsTrustedHeaderBypass(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "admin") {
			if r.Header.Get("X-Forwarded-User") == "admin" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<html><body>SECRET ADMIN PANEL — welcome admin</body></html>"))
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Forbidden"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := seed403(t, srv.URL+"/admin")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a trusted identity-header bypass finding")
	assert.Equal(t, "x-forwarded-user", res[0].FuzzingParameter, "the trusted-identity phase should attribute the single header")
	assert.Equal(t, "Trusted Identity Header Authentication Bypass", res[0].Info.Name)
}

// TestScanPerRequest_DetectsCombinedTrustedHeaderBypass covers a gateway that
// authorizes only when the FULL proxy identity set is present together (user +
// email + groups), as oauth2-proxy does. No single header unlocks the resource, so
// the per-header phase finds nothing and the combined all-headers-at-once probe is
// what trips the bypass.
func TestScanPerRequest_DetectsCombinedTrustedHeaderBypass(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "admin") {
			if r.Header.Get("X-Forwarded-User") == "admin" &&
				r.Header.Get("X-Forwarded-Email") == "admin" &&
				r.Header.Get("X-Forwarded-Groups") == "admin" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<html><body>SECRET ADMIN PANEL — full identity</body></html>"))
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Forbidden"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := seed403(t, srv.URL+"/admin")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a combined trusted identity-header bypass finding")
	assert.Equal(t, "trusted-identity-headers", res[0].FuzzingParameter, "no single header unlocks it; the combined probe should be credited")
}

// TestStillForbiddenWithoutHeaders exercises the causality layer in isolation (the
// generic IP-header phase has no such check, so it cannot be exercised cleanly
// through ScanPerRequest): a bare request that is STILL access-controlled keeps the
// finding, while one that is 200 even without the header — a resource that simply
// went public — drops it.
func TestStillForbiddenWithoutHeaders(t *testing.T) {
	t.Parallel()

	t.Run("still forbidden keeps the finding", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Forbidden"))
		}))
		defer srv.Close()
		client := modtest.Requester(t)
		rr := modtest.Request(t, srv.URL+"/admin")
		assert.True(t, stillForbiddenWithoutHeaders(client, rr.Service(), rr.Request().Raw()),
			"a bare request that is still 403 must not suppress the bypass")
	})

	t.Run("public resource drops the finding", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("public content"))
		}))
		defer srv.Close()
		client := modtest.Requester(t)
		rr := modtest.Request(t, srv.URL+"/admin")
		assert.False(t, stillForbiddenWithoutHeaders(client, rr.Service(), rr.Request().Raw()),
			"a resource that is 200 even without the header is not header-attributable")
	})
}

// TestScanPerRequest_NoFalsePositive_TransientBypass reproduces a transient 200:
// the very first admin request succeeds (a flap / race / caching edge), but the
// reproducibility re-fetch returns 404. The bypass does not reproduce, so the
// strict reproducibility gate must drop it.
func TestScanPerRequest_NoFalsePositive_TransientBypass(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	servedAdmin := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "admin") {
			mu.Lock()
			first := !servedAdmin
			servedAdmin = true
			mu.Unlock()
			if first {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<html><body>SECRET ADMIN PANEL</body></html>"))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := seed403(t, srv.URL+"/admin")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a one-shot transient 200 that does not reproduce must not be reported")
}
