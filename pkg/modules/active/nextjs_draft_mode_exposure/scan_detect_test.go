package nextjs_draft_mode_exposure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

// nextDataBody is a minimal Next.js page body so LooksLikeNextJS fingerprints
// the seed request as a Next.js host.
const nextDataBody = `<html><body><script id="__NEXT_DATA__" type="application/json">{"buildId":"abc"}</script></body></html>`

// draftHandler sets a Next.js draft-mode bypass cookie on the App Router draft
// endpoint, simulating draft mode being enabled without a valid secret.
func draftHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/draft" {
			w.Header().Set("Set-Cookie", "__prerender_bypass=deadbeef; Path=/; HttpOnly")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

// TestScanPerHost_LiveCookieWithoutContentProofIsCandidate ensures cookie
// issuance alone no longer becomes a confirmed High finding.
func TestScanPerHost_LiveCookieWithoutContentProofIsCandidate(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(draftHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", nextDataBody)

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a candidate when a live draft bypass cookie is set")
	assert.Equal(t, ModuleID, res[0].ModuleID)
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind)
}

func TestScanPerHost_DraftContentDifferentialConfirmsExposure(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/draft":
			http.SetCookie(w, &http.Cookie{Name: "__prerender_bypass", Value: "live-preview", Path: "/", HttpOnly: true})
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusTemporaryRedirect)
		case "/":
			w.Header().Set("Content-Type", "text/html")
			if c, err := r.Cookie("__prerender_bypass"); err == nil && c.Value == "live-preview" {
				_, _ = w.Write([]byte("<html><body>UNPUBLISHED DRAFT ARTICLE " + strings.Repeat("draft ", 40) + "</body></html>"))
				return
			}
			_, _ = w.Write([]byte("<html><body>PUBLIC ARTICLE " + strings.Repeat("public ", 40) + "</body></html>"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", nextDataBody)
	res, err := New().ScanPerHost(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, output.RecordKindFinding, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeBypass, res[0].EvidenceGrade)
}

func TestScanPerHost_DeletionCookieIsIgnored(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/draft" {
			http.SetCookie(w, &http.Cookie{Name: "__prerender_bypass", Value: "", Path: "/", MaxAge: -1})
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", nextDataBody)
	res, err := New().ScanPerHost(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an expired/deletion cookie does not activate draft mode")
}

func TestScanPerHost_ExitPreviewEndpointIsNotProbedAsActivation(t *testing.T) {
	t.Parallel()
	var exitHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/exit-preview" {
			exitHits.Add(1)
			http.SetCookie(w, &http.Cookie{Name: "__prerender_bypass", Value: "", Path: "/", MaxAge: -1})
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", nextDataBody)
	res, err := New().ScanPerHost(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
	assert.Zero(t, exitHits.Load(), "an exit endpoint cannot be evidence of activation")
}

// TestScanPerHost_NoFalsePositive ensures a Next.js host that never sets a
// bypass cookie yields no finding.
func TestScanPerHost_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", nextDataBody)

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "no draft bypass cookie means no finding")
}

// TestScanPerHost_NonNextJSHostSkipped ensures a non-Next.js host is skipped
// even when the draft endpoints would set a bypass cookie.
func TestScanPerHost_NonNextJSHostSkipped(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(draftHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>plain site</body></html>")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host that does not look like Next.js must be skipped")
}

// TestCanProcess covers the custom CanProcess gate: a request needs a response.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil))

	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(rr), "no baseline response means not processable")

	withResp := modtest.Response(rr, "text/html", "ok")
	assert.True(t, m.CanProcess(withResp))
}
