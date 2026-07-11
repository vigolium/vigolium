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
	"github.com/vigolium/vigolium/pkg/output"
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
	return modtest.Response(withSvc, "application/json", `{"data":"secret"}`)
}

// TestScanPerRequest_DetectsAPIKeyInURL drives the real scan method against an
// endpoint that authenticates equally whether the credential arrives in the
// Authorization header or as a URL query parameter. Moving the header value to
// ?access_token= still returns 2xx, which signals the exposure.
func TestScanPerRequest_DetectsAPIKeyInURL(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Accept only the exact credential from either location. A server that
		// accepts every non-empty token is covered by the negative-control test.
		const credential = "Bearer sk-test-12345"
		if r.Header.Get("Authorization") == credential ||
			r.URL.Query().Get("access_token") == credential ||
			r.URL.Query().Get("authorization") == credential {
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
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeDifferential, res[0].EvidenceGrade)
}

// A parameter that merely changes the response for every value is not proof
// that the valid credential was authenticated. The bit-flipped control catches
// this generic parameter-presence behavior.
func TestScanPerRequest_RejectsAnyValueAcceptance(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("access_token") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":"parameter-present"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(seedWithAuthHeader(t, srv.URL, "Authorization", "Bearer sk-test-12345"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}

func TestScanPerRequest_RequiresURLResponseToMatchAuthenticatedBaseline(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Header.Get("Authorization") != "":
			_, _ = w.Write([]byte(`{"data":"private-account-record"}`))
		case r.URL.Query().Get("access_token") == "Bearer sk-test-12345":
			_, _ = w.Write([]byte(`{"data":"public-token-help-page"}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(seedWithAuthHeader(t, srv.URL, "Authorization", "Bearer sk-test-12345"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
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

// TestScanPerRequest_NoFalsePositive_Unauthenticated reproduces the core false
// positive: an endpoint (or SPA/CDN catch-all) that returns 2xx regardless of
// the credential. Moving the header to a URL parameter still returns 200, but so
// does a request with the credential removed entirely — so the parameter is not
// "accepted" as a credential. The no-credential control gate must suppress it.
func TestScanPerRequest_NoFalsePositive_Unauthenticated(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Always succeeds — credential is irrelevant.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"public"}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := seedWithAuthHeader(t, srv.URL, "Authorization", "Bearer sk-test-12345")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an endpoint that 2xx-es without any credential must not yield a finding")
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
