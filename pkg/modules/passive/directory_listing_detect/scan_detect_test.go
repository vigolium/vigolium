package directory_listing_detect

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds a 200 text/html request/response pair carrying the given body.
func makeHTTPCtx(path, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n%s", body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_ApacheListing drives the Apache directory-listing
// signature (title + h1 "Index of"), the main detection path.
func TestScanPerRequest_ApacheListing(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1></body></html>`
	ctx := makeHTTPCtx("/uploads/", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, results[0].Info.Name, "Apache")
}

// TestScanPerRequest_GenericListing drives the generic "Directory listing for"
// title catch-all pattern.
func TestScanPerRequest_GenericListing(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><head><title>Directory listing for /files/</title></head><body></body></html>`
	ctx := makeHTTPCtx("/files/", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_NoListing verifies an ordinary HTML page is not flagged.
func TestScanPerRequest_NoListing(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/", `<html><body>Welcome home</body></html>`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
