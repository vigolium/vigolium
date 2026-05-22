package cloud_storage_error_info

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// makeCtx builds a request/response pair with the given status line, headers, and body.
func makeCtx(path, statusLine, headers, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("%s\r\n%s\r\n\r\n%s", statusLine, headers, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_S3Error drives a 403 S3 XML error body that leaks the
// bucket name and error code, which should be reported.
func TestScanPerRequest_S3Error(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message><BucketName>secret-prod-bucket</BucketName><Region>us-east-1</Region></Error>`
	ctx := makeCtx("/file.txt", "HTTP/1.1 403 Forbidden", "Content-Type: application/xml", body)
	require.True(t, m.CanProcess(ctx))

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Cloud Storage Error Information Disclosure", results[0].Info.Name)
}

// TestCanProcess_Success200 verifies a plain 200 OK without storage error
// headers is not processed.
func TestCanProcess_Success200(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeCtx("/", "HTTP/1.1 200 OK", "Content-Type: text/html", "<html></html>")
	assert.False(t, m.CanProcess(ctx))
}

// TestScanPerRequest_NoStorageInfo verifies a 404 error without any cloud
// storage indicators yields no findings.
func TestScanPerRequest_NoStorageInfo(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeCtx("/missing", "HTTP/1.1 404 Not Found", "Content-Type: text/html", "<html><body>Not Found</body></html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
