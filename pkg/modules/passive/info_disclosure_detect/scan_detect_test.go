package info_disclosure_detect

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

func makeHTTPCtx(path, rawRespHeaders, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\n%s\r\n\r\n%s", rawRespHeaders, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_StackTrace drives a response body containing a Python
// traceback and expects this broad module not to duplicate the dedicated
// verbose-error-stacktrace detector.
func TestScanPerRequest_StackTraceOwnedByDedicatedModule(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html>Traceback (most recent call last): File "app.py", line 10</html>`
	ctx := makeHTTPCtx("/page", "Content-Type: text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_JSBundleInternalIP is a regression: a private RFC1918 IP
// baked into a minified JS bundle (served text/javascript at an extensionless
// route) is not a disclosure. The Content-Type gate must skip body checks.
func TestScanPerRequest_JSBundleInternalIP(t *testing.T) {
	t.Parallel()
	m := New()
	body := `const cfg={devHost:"192.168.1.50",api:"10.0.0.1"};export default cfg;`
	ctx := makeHTTPCtx("/assets/app", "Content-Type: text/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_InternalIP drives a response body leaking a private RFC1918
// address and expects a finding.
func TestScanPerRequest_InternalIP(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html>Connecting to backend at 192.168.1.50:8080</html>`
	ctx := makeHTTPCtx("/status", "Content-Type: text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, results[0].EvidenceGrade)
}

// TestScanPerRequest_XPoweredBy drives a response with an X-Powered-By header
// revealing the backend framework and expects a finding.
func TestScanPerRequest_XPoweredBy(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/", "Content-Type: text/html\r\nX-Powered-By: PHP/7.4.3", "<html>ok</html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Equal(t, "Framework Version Disclosed", results[0].Info.Name)
}

func TestScanPerRequest_DirectoryListingRequiresStructure(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/files/", "Content-Type: text/html", `<html><title>Index of /files/</title><a href="../">Parent Directory</a></html>`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
}

func TestScanPerRequest_InvalidPrivateIPIgnored(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/docs", "Content-Type: text/html", `<p>Example pattern: 192.168.999.999</p>`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NoDisclosure drives a benign response with no disclosure
// patterns and expects no findings.
func TestScanPerRequest_NoDisclosure(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/", "Content-Type: text/html", "<html><body>Welcome</body></html>")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_SkipBinary drives a body with a stack trace under a binary
// content type and expects no findings (body checks are skipped for binary).
func TestScanPerRequest_SkipBinary(t *testing.T) {
	t.Parallel()
	m := New()
	body := `Traceback (most recent call last):`
	ctx := makeHTTPCtx("/data", "Content-Type: application/octet-stream", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
