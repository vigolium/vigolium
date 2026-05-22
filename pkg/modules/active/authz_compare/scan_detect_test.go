package authz_compare

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	httpRequester "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// primaryBody and compareBody are the two structurally identical (same status,
// near-equal length) but content-different responses two sessions see at the
// same endpoint. primaryBody is seeded as the authenticated baseline; the live
// server returns compareBody to the replaying compare session.
var (
	primaryBody = "{\"owner\":\"alice\",\"email\":\"alice@example.com\",\"pad\":\"" + strings.Repeat("x", 300) + "\"}"
	compareBody = "{\"owner\":\"bobxx\",\"email\":\"bobxx@example.com\",\"pad\":\"" + strings.Repeat("y", 300) + "\"}"
)

// TestScanPerRequest_DetectsCrossSessionIDOR drives the real scan method with a
// configured compare session against a backend that serves a different user's
// (structurally similar) object to the compare session — i.e. it never enforces
// per-session object ownership. The primary baseline is alice's record; the
// replay returns bob's record with a 200, so the module flags missing
// authorization.
func TestScanPerRequest_DetectsCrossSessionIDOR(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Always 200 with a different-but-similar body than the seeded baseline.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(compareBody))
	}))
	defer srv.Close()

	compareClient := modtest.Requester(t)
	mod := New()
	mod.SetCompareClients([]*httpRequester.Requester{compareClient}, []string{"session-b"})
	require.True(t, mod.HasCompareClients())

	primaryClient := modtest.Requester(t)
	// Seed the primary session's authenticated baseline (alice's object).
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/account"),
		"application/json",
		primaryBody,
	)
	require.True(t, mod.CanProcess(rr))

	res, err := mod.ScanPerRequest(rr, primaryClient, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a cross-session IDOR finding when the compare session sees a different object")
}

// TestScanPerRequest_NoFalsePositive ensures a backend that enforces
// authorization for the compare session (403) yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	compareClient := modtest.Requester(t)
	mod := New()
	mod.SetCompareClients([]*httpRequester.Requester{compareClient}, []string{"session-b"})

	primaryClient := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/account"),
		"application/json",
		primaryBody,
	)

	res, err := mod.ScanPerRequest(rr, primaryClient, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 403 for the compare session means authorization is enforced — no finding")
}

// TestCanProcess_SkipsWithoutCompareClients verifies the module is inert until
// at least one compare session is configured.
func TestCanProcess_SkipsWithoutCompareClients(t *testing.T) {
	t.Parallel()
	mod := New()
	assert.False(t, mod.HasCompareClients())
	rr := modtest.Response(modtest.Request(t, "http://example.com/api/account"), "application/json", primaryBody)
	assert.False(t, mod.CanProcess(rr), "CanProcess must be false without compare sessions")
}
