package express_trust_proxy_misconfig

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsHostInjection reflects the X-Forwarded-Host header
// into the response body, which the module treats as a trust-proxy
// misconfiguration (host taken from a client-controlled header).
func TestScanPerRequest_DetectsHostInjection(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the X-Forwarded-Host into a generated absolute URL.
		xfh := r.Header.Get("X-Forwarded-Host")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<a href=\"https://" + xfh + "/reset\">link</a>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/account")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when X-Forwarded-Host is reflected into the body")
}

// TestScanPerRequest_NoFalsePositive serves a fixed body that never reflects any
// injected proxy header, so no probe should fire.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>static content with no reflection</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/account")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a response that ignores forwarded headers must not yield a finding")
}

// TestCheckHostInjection exercises the pure host-reflection helper directly.
func TestCheckHostInjection(t *testing.T) {
	t.Parallel()
	assert.NotEmpty(t, checkHostInjection("<a href=https://"+injectedHost+"/x>", "", ""))
	assert.NotEmpty(t, checkHostInjection("", "", "https://"+injectedHost+"/cb"))
	assert.Empty(t, checkHostInjection("clean body", "clean headers", "/local"))
}

// TestCheckPortInjection exercises the pure port-reflection helper directly.
func TestCheckPortInjection(t *testing.T) {
	t.Parallel()
	assert.NotEmpty(t, checkPortInjection("", "https://host:"+injectedPort+"/cb"))
	assert.NotEmpty(t, checkPortInjection("https://host:"+injectedPort+"/x", ""))
	assert.Empty(t, checkPortInjection("https://host/x", "/local"))
}
