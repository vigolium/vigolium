package fingerprint

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

const hitPage = `<html><head><title>Admin</title></head><body><h1>Admin console</h1><form><input name="q"></form></body></html>`

// compareHit serves /admin with hitPage and every other path with sibling,
// runs the comparator against /admin with an EMPTY signature cache (so every
// sibling shape is uncached), and returns the verdict.
func compareHit(t *testing.T, sibling http.HandlerFunc) MatchResult {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, hitPage)
			return
		}
		sibling(w, r)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	l := NewLearner(client, nil)
	l.SetDelay(0)
	c := NewComparator(NewCache(l), l)

	req := createTestHTTPRequest(t, http.MethodGet, srv.URL+"/admin", nil)
	resp, err := client.Get(srv.URL + "/admin")
	require.NoError(t, err)
	rc := responsechain.NewResponseChain(resp, 0)
	require.NoError(t, rc.Fill())
	t.Cleanup(rc.Close)

	got, err := c.Compare(context.Background(), req, rc)
	require.NoError(t, err)
	return got
}

// A sibling answering a genuine 404 whose shape is not cached is a
// miss, not "content" — it must not drop the hit.
func TestSiblingHardMissKeepsHit(t *testing.T) {
	got := compareHit(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "no such page: "+r.URL.Path)
	})
	assert.Equal(t, TruePositive, got)
}

// A throttled sibling (429 burst) says nothing about the directory: Unknown,
// which keeps the hit.
func TestSiblingThrottledIsUnknown(t *testing.T) {
	got := compareHit(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	assert.Equal(t, Unknown, got)
}

// A breaking sibling with content that does NOT resemble the hit (a JSON 403
// next to an HTML 200) is not evidence the hit is a catch-all.
func TestSiblingDifferentPageKeepsHit(t *testing.T) {
	got := compareHit(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"denied"}`)
	})
	assert.Equal(t, TruePositive, got)
}

// A catch-all answering every sibling with the hit's own page is still a
// wildcard and drops the hit.
func TestSiblingSamePageDropsHit(t *testing.T) {
	got := compareHit(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, hitPage)
	})
	assert.Equal(t, FalsePositive, got)
}

func TestIsThrottledResponse(t *testing.T) {
	assert.True(t, IsThrottledResponse(429, nil, nil))
	assert.True(t, IsThrottledResponse(503, nil, nil))
	assert.False(t, IsThrottledResponse(404, nil, nil))
	assert.False(t, IsThrottledResponse(403, http.Header{}, []byte("forbidden")))
	cf := http.Header{"Server": {"cloudflare"}, "Cf-Ray": {"abc"}}
	assert.True(t, IsThrottledResponse(403, cf, []byte("Attention Required! | Cloudflare")))
	assert.False(t, IsThrottledResponse(403, http.Header{}, []byte("Access Denied")), "a body phrase alone is not an edge block")
}
