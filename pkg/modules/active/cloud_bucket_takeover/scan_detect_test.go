package cloud_bucket_takeover

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
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

	m := New()
	m.providerClassifier = func(string) string { return providerAWS }
	res, err := m.ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a dangling-name candidate for a structured NoSuchBucket body")
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeDifferential, res[0].EvidenceGrade)
	assert.False(t, res[0].IsFinding())
	assert.Contains(t, res[0].Info.Name, "Dangling Cloud Storage Name Candidate")
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

	m := New()
	m.providerClassifier = func(string) string { return providerAWS }
	res, err := m.ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a live bucket must not yield a takeover finding")
}

// TestIsCloudStorageHost covers the provider host matcher.
func TestIsCloudStorageHost(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"my-bucket.s3.amazonaws.com":         true,
		"my-bucket.s3-website.amazonaws.com": true,
		"storage.googleapis.com":             false,
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

// TestStructuredProviderErrors rejects generic strings/status codes and
// resource types that do not establish a missing bucket/container.
func TestStructuredProviderErrors(t *testing.T) {
	t.Parallel()
	_, ok := matchCloudNotFound(providerAWS, 404, `<?xml version="1.0"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`)
	assert.True(t, ok)
	_, ok = matchCloudNotFound(providerAWS, 200, `<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`)
	assert.False(t, ok, "status must be provider-consistent")
	_, ok = matchCloudNotFound(providerGCS, 404, `{"error":{"code":404,"message":"not found"}}`)
	assert.False(t, ok, "generic GCS 404 JSON is not a missing-bucket proof")
	_, ok = matchCloudNotFound(providerAzure, 404, `<Error><Code>BlobNotFound</Code><Message>The specified blob does not exist</Message></Error>`)
	assert.False(t, ok, "a missing blob does not mean the container/account is claimable")
}
