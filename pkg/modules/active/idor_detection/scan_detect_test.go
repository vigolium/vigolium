package idor_detection

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// objectBody renders a fixed-width object body for the given id so that the
// baseline and neighbor responses are structurally identical (same status, near
// identical length) yet have different content — exactly the IDOR signal the
// module looks for. The "email" field guarantees the body is well over the
// module's 50-byte floor.
func objectBody(id string) string {
	return fmt.Sprintf("{\"user_id\":\"%5s\",\"email\":\"user%5s@example.com\",\"pad\":%q}",
		id, id, strings.Repeat("x", 200))
}

// TestScanPerInsertionPoint_DetectsIDOR drives the real scan method against a
// backend that serves a valid object for any neighbor user_id. The module
// classifies user_id=12345 as a predictable object id, probes 12344/12346/...,
// and reports because the neighbor returns a structurally similar 200 with
// different content.
func TestScanPerInsertionPoint_DetectsIDOR(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("user_id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(objectBody(id)))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/profile?user_id=12345"),
		"application/json",
		objectBody("12345"),
	)
	ip := modtest.InsertionPoint(t, rr, "user_id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an IDOR finding when neighbor user_ids return distinct, structurally similar objects")
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a backend that enforces
// authorization (403 for any id but the owner's) yields no finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("user_id") != "12345" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(objectBody("12345")))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/profile?user_id=12345"),
		"application/json",
		objectBody("12345"),
	)
	ip := modtest.InsertionPoint(t, rr, "user_id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "403 for neighbor user_ids means authorization is enforced — no finding")
}

// listingBody renders a paginated public listing for the given page that links
// to its previous and next siblings — the shape of a blog/catalog index
// (e.g. /list?page=3 with href="/list?page=2" and href="/list?page=4"). The
// repeated filler keeps each page comfortably over the module's 50-byte floor
// while every page differs in content, exactly like the Grab engineering blog
// pagination that produced the false positive.
func listingBody(page string) string {
	n, _ := strconv.Atoi(page)
	return fmt.Sprintf(
		`<html><body><h1>Listing page %s</h1><div class="posts">%s</div>`+
			`<a href="/list?page=%d" class="prev">Prev</a>`+
			`<a href="/list?page=%d" class="next">Next</a></body></html>`,
		page, strings.Repeat("post ", 60), n-1, n+1)
}

// TestScanPerInsertionPoint_LinkedNeighborSkipped is the regression for the
// reported blog-pagination false positive: GET /list?page=3 serves a listing
// whose body already links page 2 (Prev) and page 4 (Next). Those neighbors are
// intended public navigation, not a broken authorization boundary, so the module
// must skip them before sending any probe.
func TestScanPerInsertionPoint_LinkedNeighborSkipped(t *testing.T) {
	t.Parallel()
	var page2Hits, page4Hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("page")
		switch p {
		case "2":
			atomic.AddInt64(&page2Hits, 1)
		case "4":
			atomic.AddInt64(&page4Hits, 1)
		}
		// Only pages 1-4 exist; the +10 neighbor (page 13) is a 404, so it yields
		// no finding and the test isolates the linked-neighbor behavior.
		if p != "1" && p != "2" && p != "3" && p != "4" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, listingBody(p))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/list?page=3"),
		"text/html",
		listingBody("3"),
	)
	ip := modtest.InsertionPoint(t, rr, "page")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "neighbors the page already links to are intended navigation, not IDOR")
	assert.Zero(t, atomic.LoadInt64(&page2Hits), "the linked Prev neighbor must be skipped before any probe")
	assert.Zero(t, atomic.LoadInt64(&page4Hits), "the linked Next neighbor must be skipped before any probe")
}

// TestScanPerInsertionPoint_NoCredentialDowngrade verifies the
// authorization-boundary gate: an unauthenticated request (no Authorization,
// Cookie or token) that reaches a distinct neighbor object crosses no per-user
// boundary, so the finding is reported as a Medium/Tentative lead — not a
// High/Firm authorization bypass.
func TestScanPerInsertionPoint_NoCredentialDowngrade(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(objectBody(r.URL.Query().Get("user_id"))))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/profile?user_id=12345"),
		"application/json",
		objectBody("12345"),
	)
	ip := modtest.InsertionPoint(t, rr, "user_id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a distinct neighbor object is still a lead, just a weaker one without credentials")
	assert.Equal(t, severity.Medium, res[0].Info.Severity, "no credential crosses no authorization boundary — downgrade to Medium")
	assert.Equal(t, severity.Tentative, res[0].Info.Confidence)
}

// TestScanPerInsertionPoint_CredentialedStaysHigh verifies the converse: when the
// original request carries a session Cookie, a neighbor object reachable past
// that credential is a genuine authorization bypass and stays High.
func TestScanPerInsertionPoint_CredentialedStaysHigh(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(objectBody(r.URL.Query().Get("user_id"))))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := authedResponse(t, srv.URL+"/api/profile?user_id=12345", "session=valid-session-token",
		"application/json", objectBody("12345"))
	ip := modtest.InsertionPoint(t, rr, "user_id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res)
	assert.Equal(t, severity.High, res[0].Info.Severity, "a credentialed request crossing into another object is a real authorization bypass")
}

// authedResponse builds an HttpRequestResponse for rawURL carrying a Cookie
// header (so the request represents an authenticated session) with a synthetic
// 200 response attached, mirroring modtest.Response.
func authedResponse(t *testing.T, rawURL, cookie, contentType, body string) *httpmsg.HttpRequestResponse {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	port, err := strconv.Atoi(u.Port())
	require.NoError(t, err)
	svc, err := httpmsg.NewService(u.Hostname(), port, u.Scheme)
	require.NoError(t, err)

	target := u.RequestURI()
	if target == "" {
		target = "/"
	}
	raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\n\r\n", target, u.Host, cookie)
	req := httpmsg.NewHttpRequestWithService(svc, []byte(raw))

	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s",
		contentType, len(body), body)
	return httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte(rawResp)))
}

// noiseBody renders a fixed-length body whose only variable part is a 20-digit
// counter token. Two such bodies are always structurally identical (same status,
// identical length) yet byte-different — the shape of an analytics/tracking
// endpoint that returns different content on every request regardless of the id.
func noiseBody(n int64) string {
	return fmt.Sprintf("{\"data\":\"%020d\",\"pad\":%q}", n, strings.Repeat("x", 200))
}

// TestScanPerInsertionPoint_NonDeterministicEndpoint is the regression for the
// classic IDOR false positive: the backend returns different content on every
// request regardless of user_id (a tracking beacon / randomized JS bundle), so a
// neighbor id looks "structurally similar but different" exactly like a real
// BOLA. The determinism gate re-issues the ORIGINAL id, sees the same-id response
// vary just as much, and suppresses the finding.
func TestScanPerInsertionPoint_NonDeterministicEndpoint(t *testing.T) {
	t.Parallel()
	var counter int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ignore user_id entirely: every request — same id or not — gets fresh content.
		n := atomic.AddInt64(&counter, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(noiseBody(n)))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/profile?user_id=12345"),
		"application/json",
		noiseBody(0),
	)
	ip := modtest.InsertionPoint(t, rr, "user_id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-deterministic endpoint (same id → different content) must not be reported as IDOR")
}

// SAFE-8: under a read-only traffic policy, idor_detection on a DELETE record
// sends nothing (the requester refuses every neighbour-ID DELETE).
func TestScanPerInsertionPoint_ReadOnlyPolicySendsNoDelete(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(objectBody(r.URL.Query().Get("user_id"))))
	}))
	defer srv.Close()

	opts := types.DefaultOptions()
	opts.Timeout = 5 * time.Second
	opts.TrafficPolicy = types.NewTrafficPolicy([]string{"GET", "HEAD"})
	require.NoError(t, network.Init(opts))
	svc := &services.Services{Options: opts}
	client, err := vighttp.NewRequester(opts, svc)
	require.NoError(t, err)

	rr := modtest.Response(
		modtest.RequestMethod(t, http.MethodDelete, srv.URL+"/api/profile?user_id=12345", ""),
		"application/json",
		objectBody("12345"),
	)
	ip := modtest.InsertionPoint(t, rr, "user_id")
	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
	assert.Equal(t, int64(0), hits.Load(), "no DELETE may reach the server under a read-only policy")
}
