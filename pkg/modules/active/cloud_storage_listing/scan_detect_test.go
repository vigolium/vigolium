package cloud_storage_listing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// NEEDS-PHASE-3: ScanPerHost only probes when the target host resolves to a real
// cloud-storage endpoint (*.s3.amazonaws.com, *.blob.core.windows.net, ...). The
// fastdialer-backed requester resolves the service host via DNS, so an
// httptest.Server bound to 127.0.0.1 cannot masquerade as S3/Azure — the host
// gate (isCloudStorageHost) is false and no probe runs. Driving the full scan
// needs a fake-DNS / out-of-band harness. These tests cover construction,
// CanProcess host gating, and the pure detection helpers.

// newCloudRR builds a request/response pair whose service host is host, so
// CanProcess can be exercised against the cloud-storage host gate.
func newCloudRR(t *testing.T, host string, withResponse bool) *httpmsg.HttpRequestResponse {
	t.Helper()
	svc, err := httpmsg.NewService(host, 443, "https")
	require.NoError(t, err)
	raw := "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	req := httpmsg.NewHttpRequestWithService(svc, []byte(raw))
	var resp *httpmsg.HttpResponse
	if withResponse {
		resp = httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	}
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestNew_Metadata verifies the module constructs with its declared identity.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestCanProcess_HostGate confirms CanProcess only accepts live cloud-storage
// hosts and rejects ordinary hosts or missing responses.
func TestCanProcess_HostGate(t *testing.T) {
	t.Parallel()
	m := New()

	assert.True(t, m.CanProcess(newCloudRR(t, "my-bucket.s3.amazonaws.com", true)),
		"an S3 bucket host with a response must be processable")
	assert.True(t, m.CanProcess(newCloudRR(t, "acct.blob.core.windows.net", true)),
		"an Azure blob host with a response must be processable")
	assert.False(t, m.CanProcess(newCloudRR(t, "www.example.com", true)),
		"a non-cloud host must be rejected")
	assert.False(t, m.CanProcess(newCloudRR(t, "my-bucket.s3.amazonaws.com", false)),
		"a cloud host without a response (not yet live) must be rejected")
	assert.False(t, m.CanProcess(nil), "nil context must be rejected")
}

// TestIsCloudStorageHost covers the host-classification helper.
func TestIsCloudStorageHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		host      string
		s3, azure bool
	}{
		{"bucket.s3.amazonaws.com", true, false},
		{"bucket.s3-us-west-2.amazonaws.com", true, false},
		{"bucket.s3-website-us-east-1.amazonaws.com", true, false},
		{"acct.blob.core.windows.net", false, true},
		{"acct.web.core.windows.net", false, true},
		{"www.example.com", false, false},
	}
	for _, c := range cases {
		s3, az := isCloudStorageHost(c.host)
		assert.Equal(t, c.s3, s3, "S3 classification for %s", c.host)
		assert.Equal(t, c.azure, az, "Azure classification for %s", c.host)
	}
}

// TestGetAzureContainerFromPath covers container-name extraction from a path.
func TestGetAzureContainerFromPath(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "mycontainer", getAzureContainerFromPath("/mycontainer/blob.txt"))
	assert.Equal(t, "mycontainer", getAzureContainerFromPath("/mycontainer"))
	assert.Equal(t, "", getAzureContainerFromPath("/"))
	assert.Equal(t, "", getAzureContainerFromPath("/$web/index.html"),
		"the $web static-site container must be skipped")
}

// TestBodyContainsAll covers the marker-matching helper used to confirm a
// listing response.
func TestBodyContainsAll(t *testing.T) {
	t.Parallel()
	body := "<ListBucketResult><Contents><Key>a.txt</Key></Contents></ListBucketResult>"
	assert.True(t, bodyContainsAll(body, s3ListingProbes[0].markers),
		"a real S3 listing body must satisfy all S3 markers")
	assert.False(t, bodyContainsAll("<html>not a listing</html>", s3ListingProbes[0].markers),
		"unrelated HTML must not satisfy the S3 markers")
}
