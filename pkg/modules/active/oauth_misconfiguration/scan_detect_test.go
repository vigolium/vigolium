package oauth_misconfiguration

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

// TestScanPerRequest_DetectsRedirectURIManipulation drives the real scan method
// against a vulnerable OAuth authorization endpoint that reflects whatever
// redirect_uri it is handed straight into the 302 Location header. The module
// injects an attacker-controlled host (evil.example.com) and should observe it
// echoed back, flagging an OAuth open-redirect / redirect_uri manipulation.
//
// The request carries a state parameter so the (network-free) missing-state
// check stays quiet, keeping the finding attributable to redirect_uri handling.
func TestScanPerRequest_DetectsRedirectURIManipulation(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: blindly redirect to the supplied redirect_uri.
		if ru := r.URL.Query().Get("redirect_uri"); ru != "" {
			w.Header().Set("Location", ru) // unvalidated redirect_uri
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/oauth/authorize?client_id=app1&response_type=code&state=xyz&redirect_uri=https://app.example.com/callback")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an OAuth finding when the endpoint echoes a manipulated redirect_uri")

	var sawRedirectFinding bool
	for _, r := range res {
		if r.FuzzingParameter == "redirect_uri" {
			sawRedirectFinding = true
			assert.Equal(t, output.RecordKindFinding, r.RecordKind)
			assert.Equal(t, output.EvidenceGradeBypass, r.EvidenceGrade)
			assert.NotContains(t, r.Info.Description, "enabling authorization code/token theft")
			break
		}
	}
	assert.True(t, sawRedirectFinding, "expected a redirect_uri manipulation finding among results")
}

func TestMissingStateIsObservation(t *testing.T) {
	t.Parallel()
	rr := modtest.Request(t, "https://login.example.test/oauth/authorize?client_id=app&response_type=code")
	urlx, err := rr.URL()
	require.NoError(t, err)
	result, err := New().testMissingState(rr, urlx)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, output.RecordKindObservation, result.RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, result.EvidenceGrade)
	assert.False(t, result.Metadata["csrf_impact_proven"].(bool))
}

func TestResponseTypeAcceptanceWithoutTokenIsCandidate(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("response_type") {
		case "vigolium_invalid_rt":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"unsupported_response_type"}`))
		default:
			w.Header().Set("Location", "https://app.example.com/callback")
			w.WriteHeader(http.StatusFound)
		}
	}))
	defer srv.Close()

	rr := modtest.Request(t, srv.URL+"/oauth/authorize?client_id=app&response_type=code&state=s&redirect_uri=https://app.example.com/callback")
	results, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	var candidate *output.ResultEvent
	for _, result := range results {
		if result.FuzzingParameter == "response_type" {
			candidate = result
		}
	}
	require.NotNil(t, candidate)
	assert.Equal(t, output.RecordKindCandidate, candidate.RecordKind)
	assert.Equal(t, output.EvidenceGradeDifferential, candidate.EvidenceGrade)
	assert.Equal(t, false, candidate.Metadata["access_token_issued"])
}

func TestResponseTypeTokenIssuanceIsFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("response_type") {
		case "token":
			w.Header().Set("Location", "https://app.example.com/callback#access_token=issued-token&token_type=bearer")
			w.WriteHeader(http.StatusFound)
		case "vigolium_invalid_rt":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"unsupported_response_type"}`))
		default:
			w.Header().Set("Location", "https://app.example.com/callback?code=abc")
			w.WriteHeader(http.StatusFound)
		}
	}))
	defer srv.Close()

	rr := modtest.Request(t, srv.URL+"/oauth/authorize?client_id=app&response_type=code&state=s&redirect_uri=https://app.example.com/callback")
	results, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	for _, result := range results {
		if result.FuzzingParameter == "response_type" {
			assert.Equal(t, output.RecordKindFinding, result.RecordKind)
			assert.Equal(t, output.EvidenceGradeImpact, result.EvidenceGrade)
			assert.Equal(t, true, result.Metadata["access_token_issued"])
			return
		}
	}
	t.Fatal("expected response_type token issuance finding")
}

// TestScanPerRequest_RedirectURIEchoedToIdPNoFalsePositive reproduces the
// CDN/OAuth-login false positive: the authorize endpoint reflects the manipulated
// redirect_uri back into the Location's query string but still 302s to the trusted
// SSO/IdP — the attacker host is never the redirect authority, so the auth code
// flows to the SSO (which validates redirect_uri), not the attacker. A bare
// substring match flagged it (and a fresh canary echoes identically); the
// authority-position guard must suppress it.
func TestScanPerRequest_RedirectURIEchoedToIdPNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ru := r.URL.Query().Get("redirect_uri")
		// Forward the (attacker-manipulated) redirect_uri to the IdP as a query
		// parameter, but the redirect authority stays the trusted SSO host.
		loc := "https://sso.trusted.example/authorize?redirect_uri=" + url.QueryEscape(ru)
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/oauth/authorize?client_id=app1&response_type=code&state=xyz&redirect_uri=https://app.example.com/callback")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	for _, r := range res {
		assert.NotContains(t, r.Info.Name, "Open Redirect",
			"a redirect_uri echoed into the IdP Location query (authority unchanged) must not be reported as an open redirect")
	}
}

// TestScanPerRequest_CatchAllEchoNoFalsePositive locks in that the module is
// immune to the universal catch-all / echo-server FP class: a host that answers
// LITERALLY ANY path/param with 200 + text/html and the SAME reflecting page
// (echoing the request URI, no <!DOCTYPE — the body-truncation quirk) must not
// forge any OAuth finding. The module is already structurally protected because it
// only reports on differential/reflection-confirmed signals — a 3xx whose Location
// authority is an attacker-chosen host tracked by a fresh canary (never satisfied
// by a 200 echo), and a response_type downgrade gated on the endpoint REJECTING an
// invalid response_type (an echo accepts every value, so the control drops it). The
// request carries state=xyz so the network-free missing-state check stays quiet.
func TestScanPerRequest_CatchAllEchoNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Universal reflecting shell: every path/param 200s with the same themed page
		// echoing the request URI back. No OAuth error tokens, never a 3xx.
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<div class="app-shell">reflected: ` + r.URL.String() + `</div>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/oauth/authorize?client_id=app1&response_type=code&state=xyz&redirect_uri=https://app.example.com/callback")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a universal catch-all/echo OAuth endpoint must not forge a misconfiguration finding")
}

// TestScanPerRequest_NoFalsePositive ensures a hardened OAuth endpoint yields no
// finding: it carries the CSRF state parameter, only ever redirects to a fixed
// allow-listed callback (never echoing the attacker host), and rejects a
// response_type downgrade with an OAuth error body. None of the three checks
// (redirect_uri manipulation, missing state, response_type downgrade) should fire.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reject anything other than the authorization code flow.
		if rt := r.URL.Query().Get("response_type"); rt != "code" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"unsupported_response_type"}`))
			return
		}
		// Always redirect to the fixed, registered callback regardless of the
		// supplied redirect_uri — a properly validating authorization server.
		w.Header().Set("Location", "https://app.example.com/callback?code=abc")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/oauth/authorize?client_id=app1&response_type=code&state=xyz&redirect_uri=https://app.example.com/callback")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a hardened OAuth endpoint must not yield a misconfiguration finding")
}

// TestScanPerRequest_HardcodedLocationNoFalsePositive reproduces a coincidental
// match: the endpoint always redirects to a FIXED location that happens to
// contain "evil.example.com", regardless of redirect_uri. The fresh-canary
// confirmation must drop it (the canary never appears in Location).
func TestScanPerRequest_HardcodedLocationNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fixed redirect, ignores redirect_uri; the string is hardcoded, not reflected.
		w.Header().Set("Location", "https://evil.example.com/hardcoded-marketing-link")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/oauth/authorize?client_id=app1&response_type=code&state=xyz&redirect_uri=https://app.example.com/callback")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	for _, r := range res {
		assert.NotEqual(t, "redirect_uri", r.FuzzingParameter,
			"a hardcoded Location string that does not track the fresh canary must not be reported")
	}
}

// TestScanPerRequest_ResponseTypeNotValidatedNoFalsePositive reproduces an
// endpoint that accepts ANY response_type (no validation). response_type=token
// "passes", but so does an obviously invalid value, so the control gate must drop
// the downgrade finding.
func TestScanPerRequest_ResponseTypeNotValidatedNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Always 302 to the fixed registered callback, never validating response_type
		// and never echoing redirect_uri.
		w.Header().Set("Location", "https://app.example.com/callback?code=abc")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/oauth/authorize?client_id=app1&response_type=code&state=xyz&redirect_uri=https://app.example.com/callback")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	for _, r := range res {
		assert.NotEqual(t, "response_type", r.FuzzingParameter,
			"an endpoint that accepts any response_type must not be reported as a downgrade")
	}
}
