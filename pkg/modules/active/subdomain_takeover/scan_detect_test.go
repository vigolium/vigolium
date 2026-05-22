package subdomain_takeover

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// The real DNS/CNAME resolution that picks a candidate host is out of scope for
// a loopback test, but ScanPerHost re-fetches GET / and matches the response
// body/status against the deprovisioned-service fingerprint table — that
// detection logic is fully drivable against an httptest server.

// TestNew_Metadata verifies module identity and tags.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, ModuleTags, m.Tags())
}

// TestCanProcess requires a captured response.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil))
	assert.False(t, m.CanProcess(modtest.Request(t, "http://127.0.0.1/")))
	withResp := modtest.Response(modtest.Request(t, "http://127.0.0.1/"), "text/html", "x")
	assert.True(t, m.CanProcess(withResp))
}

// TestScanPerHost_DetectsHerokuTakeover drives the real scan method against a
// server returning Heroku's "No such app" page with a 404 — the fingerprint of
// a deprovisioned, claimable Heroku app.
func TestScanPerHost_DetectsHerokuTakeover(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>No such app</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a subdomain-takeover finding for the Heroku fingerprint")
	assert.Equal(t, "Subdomain Takeover: Heroku", res[0].Info.Name)
}

// TestScanPerHost_StatusMismatchNoFinding ensures a body marker that requires a
// specific status code does not fire when the status differs. GitHub Pages
// requires a 404; here the marker appears under a 200.
func TestScanPerHost_StatusMismatchNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// GitHub Pages marker, but served with 200 instead of the required 404.
		_, _ = w.Write([]byte("There isn't a GitHub Pages site here."))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "fingerprint with status-code mismatch must not fire")
}

// TestScanPerHost_NoFalsePositive ensures a healthy page yields no finding.
func TestScanPerHost_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>Welcome, this site is live.</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a live site must not yield a takeover finding")
}

// TestTruncate caps over-long bodies and leaves short ones intact.
func TestTruncate(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "abc", truncate("abc", 5))
	assert.Equal(t, "abcde...", truncate("abcdefghij", 5))
}
