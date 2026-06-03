package bfla_detection

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

// adminBody is the privileged page content. It is large enough that the full
// unauthenticated response (status line + headers + body) stays within 50% of
// the baseline body length, satisfying the module's isBodyLengthSimilar check.
var adminBody = "<html><body>Admin console: " + strings.Repeat("user record ", 80) + "</body></html>"

// TestScanPerRequest_DetectsBFLA drives the real scan method against an admin
// endpoint that serves the same privileged content whether or not the request
// carries Authorization/Cookie headers (broken function-level authorization).
// A distinct shell is returned for the wildcard probe so the finding isn't
// rejected as a wildcard match.
func TestScanPerRequest_DetectsBFLA(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "-vigolium-wp/") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// Privileged content served regardless of auth headers.
		_, _ = w.Write([]byte(adminBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Seed an authenticated 2xx baseline for the admin path.
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/admin/users"),
		"text/html",
		adminBody,
	)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a BFLA finding when the admin page is reachable without auth")
}

// TestScanPerRequest_NoFalsePositive ensures an admin endpoint that enforces
// authorization (401 once the Authorization/Cookie headers are stripped) yields
// no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "-vigolium-wp/") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// Enforce auth: without credentials, deny.
		if r.Header.Get("Authorization") == "" && r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))
			return
		}
		_, _ = w.Write([]byte(adminBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/admin/users"),
		"text/html",
		adminBody,
	)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an admin page that requires auth must not yield a BFLA finding")
}

// TestScanPerRequest_LoginPageOnUnauthNoFalsePositive reproduces the loose-length
// false positive: stripping auth returns a 200 LOGIN page of similar LENGTH but
// entirely different CONTENT than the admin page. The old "body length within
// 50%" check flagged it; the content-similarity gate must reject it because the
// privileged content was not actually served unauthenticated.
func TestScanPerRequest_LoginPageOnUnauthNoFalsePositive(t *testing.T) {
	t.Parallel()
	loginBody := "<html><body>Please sign in to continue. " + strings.Repeat("username password forgot ", 35) + "</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "-vigolium-wp/") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// Only GET is enabled, so method-switching probes (POST/PUT/DELETE) get a
		// 405 and don't fire — isolating the auth-strip content check.
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Auth stripped → a 200 login page: similar size, totally different content.
		_, _ = w.Write([]byte(loginBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Seed the authenticated admin page as the baseline.
	rr := modtest.Response(modtest.Request(t, srv.URL+"/admin/users"), "text/html", adminBody)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 200 login page of similar length but different content must not be flagged as BFLA")
}
