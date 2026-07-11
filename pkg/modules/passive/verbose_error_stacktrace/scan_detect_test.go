package verbose_error_stacktrace

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// makeHTTPCtx builds a request/response pair with the given content type and body.
func makeHTTPCtx(contentType, body string) *httpmsg.HttpRequestResponse {
	return makeHTTPCtxStatus("500 Internal Server Error", contentType, body)
}

func makeHTTPCtxStatus(status, contentType, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET /api/run HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 %s\r\nContent-Type: %s\r\n\r\n%s", status, contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_PythonTraceback drives a Python traceback exposing internal file
// paths, which should be flagged.
func TestScanPerRequest_PythonTraceback(t *testing.T) {
	t.Parallel()
	m := New()
	body := "Traceback (most recent call last):\n  File \"/app/views.py\", line 42, in handler\n    raise ValueError('boom')"
	ctx := makeHTTPCtx("text/plain", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Python Stack Trace Exposed", results[0].Info.Name)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
}

func TestScanPerRequest_SuccessfulDocumentationIsObservation(t *testing.T) {
	t.Parallel()
	m := New()
	body := "Traceback (most recent call last):\n  File \"/app/views.py\", line 42, in handler\n    raise ValueError('boom')"
	ctx := makeHTTPCtxStatus("200 OK", "text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, results[0].EvidenceGrade)
}

// TestScanPerRequest_JavaStackTrace drives a multi-frame Java stack trace.
func TestScanPerRequest_JavaStackTrace(t *testing.T) {
	t.Parallel()
	m := New()
	body := "Exception:\nat com.example.App.run(App.java:12)\nat com.example.App.main(App.java:5)\n"
	ctx := makeHTTPCtx("text/plain", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "Java Stack Trace Exposed" {
			found = true
		}
	}
	assert.True(t, found, "expected Java stack trace finding")
}

// TestScanPerRequest_NoStackTrace verifies that a benign body produces no findings.
func TestScanPerRequest_NoStackTrace(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("text/html", "<html><body>Everything is fine</body></html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_SkipBinary verifies that binary content types are skipped.
func TestScanPerRequest_SkipBinary(t *testing.T) {
	t.Parallel()
	m := New()
	body := "Traceback (most recent call last):\n  File \"/app/views.py\", line 42, in handler"
	ctx := makeHTTPCtx("image/png", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
