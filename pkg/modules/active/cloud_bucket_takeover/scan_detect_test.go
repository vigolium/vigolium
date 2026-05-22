package cloud_bucket_takeover

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// PARTIAL: CanProcess gates on isCloudStorageHost, which a loopback httptest
// host can never satisfy, so the executor would never dispatch this module
// against a test server. ScanPerHost itself does not re-check the host, so the
// detection logic is driven directly below against a server returning a
// takeover-signature body; CanProcess and the pure helpers are covered
// separately.

// TestNew_Metadata verifies module identity and tags.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, ModuleTags, m.Tags())
}

// TestCanProcess only accepts cloud-storage hosts with a captured response.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil))

	// Loopback host: rejected even with a response.
	plain := modtest.Response(modtest.Request(t, "http://127.0.0.1/"), "text/plain", "x")
	assert.False(t, m.CanProcess(plain), "non-cloud host must be rejected")

	// Cloud-storage host with a response: accepted.
	s3 := modtest.Response(modtest.Request(t, "http://my-bucket.s3.amazonaws.com/"), "application/xml", "x")
	assert.True(t, m.CanProcess(s3), "S3 host with a response must be processable")

	// Cloud-storage host without a response: rejected.
	s3NoResp := modtest.Request(t, "http://my-bucket.s3.amazonaws.com/")
	assert.False(t, m.CanProcess(s3NoResp), "cloud host without a response must be rejected")
}

// TestScanPerHost_DetectsNoSuchBucket drives the real scan method against a
// server that returns the AWS S3 NoSuchBucket error body, the canonical
// claimable-bucket fingerprint.
func TestScanPerHost_DetectsNoSuchBucket(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a bucket-takeover finding for a NoSuchBucket body")
	assert.Contains(t, res[0].Info.Name, "Cloud Bucket Takeover")
}

// TestScanPerHost_NoFalsePositive ensures a live bucket (no takeover signature)
// yields no finding.
func TestScanPerHost_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><ListBucketResult><Name>live-bucket</Name></ListBucketResult>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a live bucket must not yield a takeover finding")
}

// TestIsCloudStorageHost covers the provider host matcher.
func TestIsCloudStorageHost(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"my-bucket.s3.amazonaws.com":         true,
		"my-bucket.s3-website.amazonaws.com": true,
		"storage.googleapis.com":             true,
		"mybucket.storage.googleapis.com":    true,
		"acct.blob.core.windows.net":         true,
		"acct.web.core.windows.net":          true,
		"example.com":                        false,
		"127.0.0.1":                          false,
	}
	for host, want := range cases {
		assert.Equalf(t, want, isCloudStorageHost(host), "host=%s", host)
	}
}

// TestBodyMatchesSignature requires all markers of a signature to be present.
func TestBodyMatchesSignature(t *testing.T) {
	t.Parallel()
	sig := takeoverSignature{name: "S3 Website NoSuchBucket", markers: []string{"NoSuchBucket", "The specified bucket does not exist"}}
	assert.True(t, bodyMatchesSignature("...NoSuchBucket... The specified bucket does not exist", sig))
	assert.False(t, bodyMatchesSignature("only NoSuchBucket here", sig), "missing second marker → no match")
	assert.False(t, bodyMatchesSignature("unrelated body", sig))
}

// TestTruncate caps over-long bodies and leaves short ones intact.
func TestTruncate(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "abc", truncate("abc", 5))
	assert.Equal(t, "abcde...", truncate("abcdefghij", 5))
}
