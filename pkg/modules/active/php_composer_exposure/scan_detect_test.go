package php_composer_exposure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// composerHandler serves an exposed composer.json for /composer.json and a
// distinct 404 body for everything else (including the random 404 fingerprint
// probe), so the real probe response diverges from the not-found fingerprint.
func composerHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/composer.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "name": "acme/shop",
  "require": {
    "php": ">=8.1",
    "laravel/framework": "^11.0"
  },
  "autoload": {
    "psr-4": { "App\\": "app/" }
  }
}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}
}

// TestScanPerRequest_DetectsComposerJSON drives the real scan method against a
// host that exposes composer.json and asserts the module reports a finding.
func TestScanPerRequest_DetectsComposerJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(composerHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>app</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when composer.json is web-reachable")
	assert.True(t, strings.Contains(res[0].Info.Name, "Composer Manifest"), "finding should name the manifest probe")
}

// TestScanPerRequest_NoFalsePositive ensures a host returning 404 for every
// probed Composer path yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>app</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host with no exposed Composer files must not yield a finding")
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
