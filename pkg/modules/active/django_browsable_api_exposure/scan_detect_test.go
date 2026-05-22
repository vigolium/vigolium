package django_browsable_api_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsBrowsableAPI drives the real scan method against a
// host that returns the Django REST Framework browsable API HTML when asked for
// text/html, exposing the interactive API explorer.
func TestScanPerRequest_DetectsBrowsableAPI(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	require.NotEmpty(t, res, "expected a browsable-API finding when DRF serves its HTML explorer")
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
