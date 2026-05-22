package nextjs_draft_mode_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
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

// TestScanPerHost_DetectsDraftModeBypass drives the real scan method against a
// Next.js host that sets a draft bypass cookie and asserts a finding.
func TestScanPerHost_DetectsDraftModeBypass(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(draftHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", nextDataBody)

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when a draft bypass cookie is set")
	assert.Equal(t, ModuleID, res[0].ModuleID)
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
