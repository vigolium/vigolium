package django_admin_exposure

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

// TestScanPerRequest_DetectsDjangoAdmin drives the real scan method against a
// host whose /admin/ serves the Django administration login page. The random
// 404 fingerprint path returns a distinct not-found body.
func TestScanPerRequest_DetectsDjangoAdmin(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin") {
			_, _ = w.Write([]byte("<html><head><title>Log in | Django site admin</title></head>" +
				"<body class=\"login\"><h1>Django administration</h1>" +
				"<form><input id=\"id_username\"><input id=\"id_password\">" +
				"<input name=\"csrfmiddlewaretoken\"></form></body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>404 Not Found generic distinct body padding padding</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a Django admin exposure finding when /admin/ serves the admin login")
}

// TestScanPerRequest_NoFalsePositive ensures a host returning 404 for the admin
// paths yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>404 Not Found</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host without a Django admin must not yield a finding")
}
