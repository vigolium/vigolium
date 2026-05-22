package proxy_header_trust

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestCanProcess gates on the presence of a captured response.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil))

	rr := modtest.Request(t, "http://127.0.0.1/")
	assert.False(t, m.CanProcess(rr), "no response attached → not processable")

	withResp := modtest.Response(rr, "text/html", "ok")
	assert.True(t, m.CanProcess(withResp))
}

// TestScanPerRequest_DetectsForwardedHostReflection drives the real scan method
// against a server that reflects X-Forwarded-Host into the response body — the
// classic host-injection sink the module probes with its sentinel host.
func TestScanPerRequest_DetectsForwardedHostReflection(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfh := r.Header.Get("X-Forwarded-Host")
		_, _ = fmt.Fprintf(w, "<html><body>link: https://%s/x</body></html>", xfh)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when X-Forwarded-Host is reflected")

	var found bool
	for _, r := range res {
		if r.Info.Name == "Proxy Header Trust: X-Forwarded-Host Injection" {
			found = true
		}
	}
	assert.True(t, found, "expected the X-Forwarded-Host injection finding")
}

// TestScanPerRequest_DetectsForwardedProtoChange drives the X-Forwarded-Proto
// branch: the server changes its response status when the spoofed proto header
// is present, which the module observes as a behavioral change versus the plain
// baseline (a non-access-denied status, so not attributed to a WAF).
func TestScanPerRequest_DetectsForwardedProtoChange(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Proto") == "https" {
			w.WriteHeader(http.StatusTeapot) // 418: distinct, not access-denied
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	var found bool
	for _, r := range res {
		if r.Info.Name == "Proxy Header Trust: X-Forwarded-Proto Confusion" {
			found = true
		}
	}
	assert.True(t, found, "expected an X-Forwarded-Proto confusion finding")
}

// TestScanPerRequest_NoFalsePositive ensures a static server that ignores every
// forwarding header — and returns a stable status/body — yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>static, no header trust</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that ignores forwarding headers must not yield a finding")
}
