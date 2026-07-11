package django_browsable_api_exposure

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

// TestScanPerRequest_DetectsBrowsableAPI drives the real scan method against a
// host that returns the Django REST Framework browsable API HTML when asked for
// text/html, exposing the interactive API explorer.
func TestScanPerRequest_DetectsBrowsableAPI(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A real DRF browsable API renders only at its own registered routes; an
		// unknown sibling 404s. Serve the explorer HTML at the two probed endpoints
		// and 404 the guaranteed-nonexistent decoy siblings so the catch-all guard
		// does not (correctly) suppress this genuine finding.
		if r.URL.Path != "/api/users/" && r.URL.Path != "/api/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><link href=\"/static/rest_framework/css/bootstrap.css\">" +
			"</head><body class=\"django-rest-framework\"><div id=\"content-main\">" +
			"<ul class=\"breadcrumb api-breadcrumb\"><li>browsable-api</li></ul></div></body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/api/users/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "one DRF surface should produce one observation")
	assert.Equal(t, output.RecordKindObservation, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, res[0].EvidenceGrade)
	assert.False(t, res[0].IsFinding())
}

func TestScanPerRequest_AuthenticatedBrowsableAPIIsNotCalledPublic(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/users/" && r.Header.Get("Cookie") == "session=developer" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<body class="django-rest-framework"><div id="content-main">browsable-api</div></body>`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	rr := modtest.Request(t, srv.URL+"/api/users/")
	raw, err := httpmsg.AddOrReplaceHeader(rr.Request().Raw(), "Cookie", "session=developer")
	require.NoError(t, err)
	rr = httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequestWithService(rr.Service(), raw), modtest.Response(rr, "text/html", "ok").Response())

	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a browsable interface visible only with the captured session is not public exposure")
}

// TestScanPerRequest_GenericLayoutTokenNoFinding pins the generic-token false
// positive: a benign 200 HTML page that carries only generic layout tokens
// ("content-main", "api-breadcrumb") but NO DRF-specific anchor must not be
// reported as a Django browsable-API exposure. The module re-fetches the original
// page with Accept: text/html, so any themed SPA/marketing shell with a
// content-main div would otherwise self-trigger.
func TestScanPerRequest_GenericLayoutTokenNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><nav class="api-breadcrumb"></nav>` +
			`<main id="content-main"><h1>Welcome</h1></main></body></html>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/dashboard")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "generic layout tokens without a DRF anchor must not yield a finding")
}

// TestScanPerRequest_NoFalsePositive_TruncatedTailCatchAll pins the universal
// catch-all / echo false positive. The host answers LITERALLY ANY path (including
// the guaranteed-nonexistent decoy siblings) with the SAME 200 text/html shell,
// and the captured body is only a truncated tail fragment: no leading
// <!DOCTYPE/<html> head (so the "404 Not Found" anti-marker is gone) with the
// request path reflected up front and a "django-rest-framework" token surviving in
// the tail. Since the genuine browsable API is itself HTML, content-type cannot
// discriminate — only the decoy catch-all guard can (a real browsable API serves
// the DRF anchor solely at its own route, whereas this host serves it everywhere).
func TestScanPerRequest_NoFalsePositive_TruncatedTailCatchAll(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusOK) // same 200 shell for EVERY path & method
		_, _ = w.Write([]byte(r.URL.Path + `"><div class="django-rest-framework">` +
			`<ul class="breadcrumb api-breadcrumb"><li>browsable-api</li></ul></div>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/api/users/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a universal 200 catch-all echoing DRF markers must not be reported")
}

// TestScanPerRequest_NoFalsePositive ensures a plain JSON API (no browsable
// HTML markers) yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"id":1,"name":"alice"}]}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/api/users/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a plain JSON API without browsable markers must not yield a finding")
}
