package anomaly_ranking

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

// makeCtx builds a request/response pair with the given status and body.
func makeCtx(path, statusLine, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("%s\r\nContent-Type: text/html\r\n\r\n%s", statusLine, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_Buffers exercises the per-host buffering path. This module
// only updates risk scores in the database and never emits findings inline, so
// ScanPerRequest always returns nil results; we drive several records to cover
// the attribute extraction and buffering logic without panicking.
func TestScanPerRequest_Buffers(t *testing.T) {
	t.Parallel()
	m := New()
	scanCtx := &modkit.ScanContext{}

	for i := 0; i < 5; i++ {
		ctx := makeCtx(fmt.Sprintf("/page%d", i), "HTTP/1.1 200 OK", fmt.Sprintf("<html>body %d</html>", i))
		results, err := m.ScanPerRequest(ctx, scanCtx)
		require.NoError(t, err)
		assert.Empty(t, results, "anomaly ranking never emits inline findings")
	}
}

// TestScanPerRequest_NoResponse verifies records lacking a response are skipped.
func TestScanPerRequest_NoResponse(t *testing.T) {
	t.Parallel()
	m := New()
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	ctx := httpmsg.NewHttpRequestResponse(req, nil)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestFlush_NoUpdater verifies Flush is a safe no-op when the scan context has
// no risk-score updater wired (the bare-context case used in tests).
func TestFlush_NoUpdater(t *testing.T) {
	t.Parallel()
	m := New()
	scanCtx := &modkit.ScanContext{}

	// Buffer enough records to exceed the minimum batch size.
	for i := 0; i < minBatchSize+1; i++ {
		ctx := makeCtx(fmt.Sprintf("/p%d", i), "HTTP/1.1 200 OK", "<html></html>")
		_, err := m.ScanPerRequest(ctx, scanCtx)
		require.NoError(t, err)
	}

	// Should not panic and should clear buffers without a configured updater.
	require.NotPanics(t, func() { m.Flush(scanCtx) })
}
