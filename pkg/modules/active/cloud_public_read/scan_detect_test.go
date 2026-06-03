package cloud_public_read

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

// TestScanPerHost_DetectsPublicSensitivePath drives the real scan method against a
// host that serves real (non-error) content for sensitive paths like /backups/.
// A 200 with a body over the minimum length and no error indicators is flagged.
//
// ScanPerHost does not re-check CanProcess, so we drive it against an httptest
// server on 127.0.0.1; the cloud-host gate is exercised separately below.
func TestScanPerHost_DetectsPublicSensitivePath(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<pre>backup-2024-01.sql 12MB\nbackup-2024-02.sql 13MB\nbackup-2024-03.sql 14MB</pre>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>index</html>")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a public-read finding when sensitive paths return real content")
}

// TestScanPerHost_NoFalsePositive ensures a host returning S3-style error bodies
// (AccessDenied/NoSuchKey) for every probe yields no finding even on a 200.
func TestScanPerHost_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>index</html>")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "S3 error responses must not be reported as public-read exposure")
}

// TestScanPerHost_ShortBodyNoFinding ensures a 200 with a body below the minimum
// length is not reported.
func TestScanPerHost_ShortBodyNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>index</html>")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a body under the minimum length must not yield a finding")
}

// TestScanPerHost_WildcardHostNoFalsePositive reproduces the catch-all false
// positive: a host that returns the same 200 shell for EVERY path (including the
// random wildcard probe). Without the soft-404 guard every sensitive path would
// be reported; ConfirmNotSoft404 must recognize the wildcard shell and stay silent.
func TestScanPerHost_WildcardHostNoFalsePositive(t *testing.T) {
	t.Parallel()
	const shell = "<html><body>Generic catch-all landing page for this bucket — no listing available here, move along.</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(shell))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", shell)

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a catch-all host that 200s every path must not be reported as public-read")
}

// TestCanProcess_OnlyCloudStorageHosts verifies the module gates on cloud-storage
// hostnames and requires a baseline response.
func TestCanProcess_OnlyCloudStorageHosts(t *testing.T) {
	t.Parallel()
	m := New()
	// Non-cloud host: gated out even with a response.
	nonCloud := modtest.Response(modtest.Request(t, "http://example.com/"), "text/html", "<html></html>")
	assert.False(t, m.CanProcess(nonCloud), "non-cloud hosts must be skipped")

	// No response: gated out.
	bareCloud := modtest.Request(t, "http://my-bucket.s3.amazonaws.com/")
	assert.False(t, m.CanProcess(bareCloud), "missing baseline response must be skipped")

	// Cloud host with a response: accepted.
	cloud := modtest.Response(modtest.Request(t, "http://my-bucket.s3.amazonaws.com/"), "text/html", "<html></html>")
	assert.True(t, m.CanProcess(cloud), "cloud-storage hosts with a response must be accepted")
}

// TestIsCloudStorageHost covers the host classifier across the major providers.
func TestIsCloudStorageHost(t *testing.T) {
	t.Parallel()
	cloud := []string{
		"my-bucket.s3.amazonaws.com",
		"my-bucket.s3-website-us-east-1.amazonaws.com",
		"storage.googleapis.com",
		"acct.blob.core.windows.net",
		"site.web.core.windows.net",
	}
	for _, h := range cloud {
		assert.True(t, isCloudStorageHost(h), "%s should be classified as cloud storage", h)
	}
	for _, h := range []string{"example.com", "api.internal.local", "127.0.0.1"} {
		assert.False(t, isCloudStorageHost(h), "%s should not be classified as cloud storage", h)
	}
}

// TestIsErrorResponse covers the error-body detector.
func TestIsErrorResponse(t *testing.T) {
	t.Parallel()
	assert.True(t, isErrorResponse("<Error><Code>NoSuchKey</Code></Error>"))
	assert.True(t, isErrorResponse("The specified blob does not exist"))
	assert.False(t, isErrorResponse("a perfectly normal directory listing of files"))
}
