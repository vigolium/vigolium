package api_key_url_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// seedWithAuthHeader returns a modtest request targeting srvURL carrying the given
// auth header, with a synthetic 2xx baseline response attached (the module requires
// the original response to be 2xx before testing the header-to-URL move).
func seedWithAuthHeader(t *testing.T, srvURL, header, value string) *httpmsg.HttpRequestResponse {
	t.Helper()
	base := modtest.Request(t, srvURL+"/api/data")
	raw, err := httpmsg.AddOrReplaceHeader(base.Request().Raw(), header, value)
	require.NoError(t, err)
	parsed, err := httpmsg.ParseRawRequest(string(raw))
	require.NoError(t, err)
	withSvc := httpmsg.NewHttpRequestResponse(parsed.Request().WithService(base.Service()), nil)
	// Attach a synthetic 200 baseline response.
	return modtest.Response(withSvc, "application/json", `{"ok":true}`)
}

// TestScanPerRequest_DetectsAPIKeyInURL drives the real scan method against an
// endpoint that authenticates equally whether the credential arrives in the
// Authorization header or as a URL query parameter. Moving the header value to
// ?access_token= still returns 2xx, which signals the exposure.
func TestScanPerRequest_DetectsAPIKeyInURL(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Accept the credential from either the header or the URL parameter.
		if r.Header.Get("Authorization") != "" ||
			r.URL.Query().Get("access_token") != "" ||
			r.URL.Query().Get("authorization") != "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":"secret"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := seedWithAuthHeader(t, srv.URL, "Authorization", "Bearer sk-test-12345")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when the API key still authenticates via URL parameter")
}

// TestScanPerRequest_NoFalsePositive ensures a server that rejects the credential
// in the URL (only honoring the header) yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the header is honored; URL parameter credentials are rejected.
		if r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":"secret"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := seedWithAuthHeader(t, srv.URL, "Authorization", "Bearer sk-test-12345")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that rejects URL-parameter credentials must not yield a finding")
}

// TestScanPerRequest_NoAuthHeaderNoFinding ensures a request without any auth
// header is a no-op (no header to relocate).
func TestScanPerRequest_NoAuthHeaderNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/api/data"), "application/json", `{"ok":true}`)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "no auth header means no finding")
}
