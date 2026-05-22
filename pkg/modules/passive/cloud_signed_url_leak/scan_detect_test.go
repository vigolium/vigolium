package cloud_signed_url_leak

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// makeHTTPCtx builds a request/response pair for the given content type and body.
func makeHTTPCtx(path, contentType, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_AWSPresigned drives a JSON body containing a leaked AWS
// presigned URL, which should be flagged.
func TestScanPerRequest_AWSPresigned(t *testing.T) {
	t.Parallel()
	m := New()
	url := "https://my-bucket.s3.amazonaws.com/secret.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=3600&X-Amz-Signature=deadbeefcafe1234"
	body := fmt.Sprintf(`{"download": "%s"}`, url)
	ctx := makeHTTPCtx("/api/download", "application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "AWS Presigned URL")
}

// TestScanPerRequest_LongLivedHighSeverity drives a presigned URL whose expiry
// exceeds 24h, which should escalate the finding to High severity.
func TestScanPerRequest_LongLivedHighSeverity(t *testing.T) {
	t.Parallel()
	m := New()
	url := "https://my-bucket.s3.amazonaws.com/secret.pdf?X-Amz-Expires=604800&X-Amz-Signature=deadbeefcafe1234"
	body := fmt.Sprintf(`{"download": "%s"}`, url)
	ctx := makeHTTPCtx("/api/download", "application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, severity.High, results[0].Info.Severity)
}

// TestScanPerRequest_NoSignedURL verifies a benign body with no signed URLs
// yields no findings.
func TestScanPerRequest_NoSignedURL(t *testing.T) {
	t.Parallel()
	m := New()
	body := `{"url": "https://example.com/public/file.pdf"}`
	ctx := makeHTTPCtx("/api/download", "application/json", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
