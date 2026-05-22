package php_path_info_misconfig

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

// TestScanPerRequest_DetectsPathInfo simulates a cgi.fix_pathinfo=1 server that
// happily serves PATH_INFO requests with 200 and app content, while returning a
// distinct 404 for the random fingerprint path.
func TestScanPerRequest_DetectsPathInfo(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// PATH_INFO test paths are rooted at index.php or a non-existent script.
		if strings.Contains(r.URL.Path, "index.php") || strings.Contains(r.URL.Path, "script.php") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>Welcome to the application home page rendered via PATH_INFO routing</body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("short 404"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when PATH_INFO requests return 200 app content")
}

// TestScanPerRequest_NoFalsePositive ensures a server that rejects PATH_INFO
// requests with 404 yields no findings.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>Not Found</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server rejecting PATH_INFO must not yield findings")
}

// TestCanProcess validates the host-liveness gate.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, New().CanProcess(rr))
	assert.True(t, New().CanProcess(modtest.Response(rr, "text/html", "ok")))
}
