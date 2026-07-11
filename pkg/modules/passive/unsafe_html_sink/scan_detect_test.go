package unsafe_html_sink

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
			assert.Equal(t, output.RecordKindObservation, r.RecordKind)
			assert.Equal(t, output.EvidenceGradeObservation, r.EvidenceGrade)
		}
	}
	assert.True(t, found, "expected dangerouslySetInnerHTML finding")
}

func TestScanPerRequest_NewFunctionSuppressedInTestFile(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/app/compiler.spec.js", "application/javascript", `new Function("return 1")();`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
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

// TestScanPerRequest_ReactRuntimePropFilter_NoFinding ensures React's own
// runtime prop-filter, which string-compares the prop name
// ("dangerouslySetInnerHTML"!==a), is not flagged — this bare-string mention was
// the dominant false positive on every React main-*.js bundle.
func TestScanPerRequest_ReactRuntimePropFilter_NoFinding(t *testing.T) {
	t.Parallel()
	m := New()
	body := `function f(r,n){for(var a in r)if(r.hasOwnProperty(a)&&"children"!==a&&"dangerouslySetInnerHTML"!==a&&void 0!==r[a]){}}`
	ctx := makeHTTPCtx("/_next/static/chunks/main-93dbaebda72da021.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "React runtime prop-name string comparison must not be flagged")
}

// TestScanPerRequest_MinifiedDangerousProp_Firing keeps a genuine minified
// dangerouslySetInnerHTML object assignment (dangerouslySetInnerHTML:{__html:x}).
func TestScanPerRequest_MinifiedDangerousProp_Firing(t *testing.T) {
	t.Parallel()
	m := New()
	body := `e.createElement("div",{dangerouslySetInnerHTML:{__html:a}})`
	ctx := makeHTTPCtx("/app/chunk.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results, "a real dangerouslySetInnerHTML assignment must still be flagged")
}

// TestScanPerRequest_EmptyClearingWrites_NoFinding drops inert clearing/no-op
// sink writes (el.innerHTML="", document.write("")).
func TestScanPerRequest_EmptyClearingWrites_NoFinding(t *testing.T) {
	t.Parallel()
	m := New()
	body := `el.innerHTML = ""; frame.document.write('');`
	ctx := makeHTTPCtx("/WebResource.axd", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "empty clearing writes carry no markup and must not be flagged")
}

// TestScanPerRequest_NonEmptyInnerHTML_Firing keeps a real innerHTML assignment
// with a dynamic value.
func TestScanPerRequest_NonEmptyInnerHTML_Firing(t *testing.T) {
	t.Parallel()
	m := New()
	body := `el.innerHTML = buildRow(userInput);`
	ctx := makeHTTPCtx("/app/render.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results, "a non-empty innerHTML assignment must still be flagged")
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
