package open_redirect_confusion

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// TestNew_Metadata verifies the module wires its identity, severity, and tags.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, severity.High, m.Severity())
	assert.Contains(t, m.Tags(), "open-redirect")
}

// TestScanPerRequest_Vulnerable drives a handler that reflects the `next`
// parameter straight into the Location header (a classic open redirect with no
// host validation). The authority-confusion ladder must detect it and the
// multi-round re-confirmation must pass.
func TestScanPerRequest_Vulnerable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next != "" {
			// Vulnerable: redirect to whatever the parameter says, unvalidated.
			w.Header().Set("Location", next)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/login?next=/home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "an unvalidated reflected redirect must be detected via the confusion ladder")
	assert.Equal(t, "next", res[0].FuzzingParameter)
	assert.Equal(t, severity.High, res[0].Info.Severity)
}

// TestScanPerRequest_NotVulnerable ensures a handler that ignores the parameter
// (never redirects off-origin) produces no finding.
func TestScanPerRequest_NotVulnerable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Always 200, never honors `next` — not an open redirect.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>home</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/login?next=/home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a handler that never redirects off-origin must not be flagged")
}

// TestScanPerRequest_NonRedirectParam ensures parameters that do not look like
// redirect sinks are skipped entirely (no requests, no findings).
func TestScanPerRequest_NonRedirectParam(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Even if it would reflect, the param name/value isn't redirect-like.
		if v := r.URL.Query().Get("q"); v != "" {
			w.Header().Set("Location", v)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/search?q=hello")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-redirect-like parameter must be skipped")
}
