package unsafe_html_sink

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

// makeHTTPCtx builds a request/response pair with the given path, content type, and body.
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

// TestScanPerRequest_DangerouslySetInnerHTML drives a React dangerouslySetInnerHTML
// sink, which should be flagged as a framework XSS sink.
func TestScanPerRequest_DangerouslySetInnerHTML(t *testing.T) {
	t.Parallel()
	m := New()
	body := `function C(){ return <div dangerouslySetInnerHTML={{__html: data}} />; }`
	ctx := makeHTTPCtx("/app/component.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		assert.Equal(t, ModuleID, r.ModuleID)
		if r.Info.Name == "Unsafe HTML Sink: dangerouslySetInnerHTML (React)" {
			found = true
		}
	}
	assert.True(t, found, "expected dangerouslySetInnerHTML finding")
}

// TestScanPerRequest_InnerHTMLAndEval drives both an innerHTML assignment and an
// eval() call, which should produce separate findings.
func TestScanPerRequest_InnerHTMLAndEval(t *testing.T) {
	t.Parallel()
	m := New()
	body := `el.innerHTML = userInput; eval(userCode);`
	ctx := makeHTTPCtx("/app/main.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.GreaterOrEqual(t, len(results), 2)
}

// TestScanPerRequest_EvalSuppressedInTestFile verifies that eval() detection is
// suppressed for spec/test/mock files.
func TestScanPerRequest_EvalSuppressedInTestFile(t *testing.T) {
	t.Parallel()
	m := New()
	body := `eval(payload);`
	ctx := makeHTTPCtx("/app/main.test.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_CleanCode verifies that benign JS code produces no findings.
func TestScanPerRequest_CleanCode(t *testing.T) {
	t.Parallel()
	m := New()
	body := `function add(a, b) { return a + b; }`
	ctx := makeHTTPCtx("/app/util.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
