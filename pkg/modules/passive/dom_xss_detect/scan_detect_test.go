package dom_xss_detect

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// makeHTTPCtx builds a text/html request/response pair carrying the given body.
func makeHTTPCtx(body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET /page HTTP/1.1\r\nHost: example.com\r\n\r\n")
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

// TestScanPerRequest_SourceAndSink drives a script block that reads a tainted
// source (location.hash) and feeds it into a dangerous sink (document.write),
// the main DOM XSS detection path.
func TestScanPerRequest_SourceAndSink(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><script>document.write(location.hash);</script></html>`
	ctx := makeHTTPCtx(body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, results[0].Info.Description, "DOM XSS")
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
	assert.Contains(t, results[0].DedupKey, "dom-xss-flow")
}

// TestScanPerRequest_OpenRedirect drives a script that flows a controllable
// source into a redirect sink (location.href =), exercising the open-redirect path.
func TestScanPerRequest_OpenRedirect(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><script>var u = location.search; location.href = u;</script></html>`
	ctx := makeHTTPCtx(body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Contains(t, results[0].DedupKey, "dom-open-redirect-flow")
}

// TestScanPerRequest_Benign verifies a script with no DOM source/sink patterns
// is not flagged.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><script>var total = 1 + 2; console.log(total);</script></html>`
	ctx := makeHTTPCtx(body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_SourceOnlyNoFalsePositive(t *testing.T) {
	t.Parallel()
	body := `<html><script>const fragment = location.hash; console.log(fragment);</script></html>`
	results, err := New().ScanPerRequest(makeHTTPCtx(body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "a controllable source without an executable sink is not DOM XSS")
}

func TestScanPerRequest_SinkOnlyNoFalsePositive(t *testing.T) {
	t.Parallel()
	body := `<html><script>document.write("<p>fixed content</p>");</script></html>`
	results, err := New().ScanPerRequest(makeHTTPCtx(body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "a fixed-value sink without attacker-controlled input is not DOM XSS")
}

func TestScanPerRequest_UnrelatedSourceAndSinkNoFalsePositive(t *testing.T) {
	t.Parallel()
	body := `<html><script>const fragment = location.hash; console.log(fragment); document.write("<p>fixed</p>");</script></html>`
	results, err := New().ScanPerRequest(makeHTTPCtx(body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "source and sink co-occurrence without a data flow is not DOM XSS")
}

func TestScanPerRequest_AliasedSourceToSink(t *testing.T) {
	t.Parallel()
	body := `<html><script>const fragment = location.hash; const value = fragment; target.innerHTML = value;</script></html>`
	results, err := New().ScanPerRequest(makeHTTPCtx(body), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, results[0].Info.Description, "target.innerHTML = value")
}

func TestScanPerRequest_SanitizedFlowNoFalsePositive(t *testing.T) {
	t.Parallel()
	body := `<html><script>const fragment = location.hash; const clean = DOMPurify.sanitize(fragment); target.innerHTML = clean;</script></html>`
	results, err := New().ScanPerRequest(makeHTTPCtx(body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "a recognized sanitizer breaks the light detector's taint flow")
}

func TestScanPerRequest_UnrelatedOpenRedirectSourceNoFalsePositive(t *testing.T) {
	t.Parallel()
	body := `<html><script>const query = location.search; console.log(query); location.href = "/home";</script></html>`
	results, err := New().ScanPerRequest(makeHTTPCtx(body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "a fixed redirect is not controlled by the unrelated source")
}
