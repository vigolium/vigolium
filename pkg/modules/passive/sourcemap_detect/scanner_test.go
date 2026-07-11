package sourcemap_detect

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func makeHTTPCtx(url, contentType, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", url))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)

	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))

	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, severity.Low, m.Severity())
	assert.Equal(t, severity.Firm, m.Confidence())
	assert.Equal(t, modkit.PassiveScanScopeResponse, m.Scope())
	assert.Equal(t, modkit.ScanScopeRequest, m.ScanScopes())
}

func TestCanProcess_Nil(t *testing.T) {
	m := New()
	assert.False(t, m.CanProcess(nil))

	req := httpmsg.NewHttpRequest([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	ctx := httpmsg.NewHttpRequestResponse(req, nil)
	assert.False(t, m.CanProcess(ctx))
}

func TestCanProcess_EmptyBody(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/app.js", "application/javascript", "")
	assert.False(t, m.CanProcess(ctx))
}

func TestCanProcess_JSContent(t *testing.T) {
	m := New()
	for _, ct := range []string{
		"application/javascript",
		"application/x-javascript",
		"text/javascript",
		"application/ecmascript",
		"text/css",
	} {
		ctx := makeHTTPCtx("/app.js", ct, "var x = 1;")
		assert.True(t, m.CanProcess(ctx), "should accept %s", ct)
	}
}

func TestCanProcess_MapURL(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/app.js.map", "application/json", `{"version":3}`)
	assert.True(t, m.CanProcess(ctx))
}

func TestCanProcess_HTMLReject(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/index.html", "text/html", "<html></html>")
	assert.False(t, m.CanProcess(ctx))
}

func TestCanProcess_ImageReject(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/logo.png", "image/png", "PNG data")
	assert.False(t, m.CanProcess(ctx))
}

func TestScanPerRequest_SourceMappingURL(t *testing.T) {
	m := New()
	body := `var x = 1;
//# sourceMappingURL=app.js.map`
	ctx := makeHTTPCtx("/app.js", "application/javascript", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, ModuleID, r.ModuleID)
	assert.Equal(t, "SourceMappingURL Reference", r.Info.Name)
	assert.Equal(t, severity.Low, r.Info.Severity)
	assert.Equal(t, severity.Firm, r.Info.Confidence)
	assert.Contains(t, r.ExtractedResults, "app.js.map")
	assert.Contains(t, r.Info.Tags, "sourcemap")
	assert.Contains(t, r.Info.Tags, "information-disclosure")
	assert.Equal(t, output.RecordKindObservation, r.RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, r.EvidenceGrade)
}

func TestScanPerRequest_BlockCommentURL(t *testing.T) {
	m := New()
	body := `body { color: red; }
/*# sourceMappingURL=styles.css.map */`
	ctx := makeHTTPCtx("/styles.css", "text/css", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].ExtractedResults, "styles.css.map")
}

func TestScanPerRequest_InlineDataURI(t *testing.T) {
	m := New()
	body := `var x = 1;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==`
	ctx := makeHTTPCtx("/app.js", "application/javascript", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, true, r.Metadata["has_inline"])
	assert.Equal(t, output.RecordKindObservation, r.RecordKind)
}

func TestScanPerRequest_ValidInlineMapIsCandidate(t *testing.T) {
	m := New()
	mapJSON := `{"version":3,"sources":["src/app.ts"],"mappings":"AAAA","sourcesContent":["const x = 1;"]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(mapJSON))
	body := "var x=1;\n//# sourceMappingURL=data:application/json;base64," + encoded
	ctx := makeHTTPCtx("/app.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "Inline Sourcemap Embedded", results[0].Info.Name)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
}

func TestScanPerRequest_MapFileExposed(t *testing.T) {
	m := New()
	body := `{"version":3,"sources":["src/app.ts","src/utils.ts"],"mappings":"AAAA","names":[]}`
	ctx := makeHTTPCtx("/app.js.map", "application/json", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, ModuleID, r.ModuleID)
	assert.Equal(t, "Sourcemap File Accessible", r.Info.Name)
	assert.Equal(t, severity.Low, r.Info.Severity)
	assert.Equal(t, severity.Certain, r.Info.Confidence)
	assert.Equal(t, output.RecordKindCandidate, r.RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, r.EvidenceGrade)
	assert.Contains(t, r.ExtractedResults, "src/app.ts")
	assert.Contains(t, r.ExtractedResults, "src/utils.ts")
	assert.Contains(t, r.Info.Tags, "sourcemap")
	assert.NotContains(t, r.Info.Tags, "source-code")
}

func TestScanPerRequest_MapFileWithSourcesContent(t *testing.T) {
	m := New()
	body := `{"version":3,"sources":["src/app.ts"],"mappings":"AAAA","sourcesContent":["const x = 1;"]}`
	ctx := makeHTTPCtx("/app.js.map", "application/json", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, severity.Medium, r.Info.Severity)
	assert.Contains(t, r.Info.Tags, "source-code")
	assert.Equal(t, true, r.Metadata["has_source_content"])
}

func TestScanPerRequest_MapFileInvalidJSON(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/app.js.map", "application/json", "not json at all")
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestScanPerRequest_MapFileMissingFields(t *testing.T) {
	m := New()

	tests := []struct {
		name string
		body string
	}{
		{"missing version", `{"sources":["a.ts"],"mappings":"AAAA"}`},
		{"missing sources", `{"version":3,"mappings":"AAAA"}`},
		{"empty sources", `{"version":3,"sources":[],"mappings":"AAAA"}`},
		{"missing mappings", `{"version":3,"sources":["a.ts"]}`},
		{"empty mappings", `{"version":3,"sources":["a.ts"],"mappings":""}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := makeHTTPCtx("/app.js.map", "application/json", tc.body)
			scanCtx := &modkit.ScanContext{}
			results, err := m.ScanPerRequest(ctx, scanCtx)
			require.NoError(t, err)
			assert.Nil(t, results)
		})
	}
}

func TestScanPerRequest_NoSourceMappingRef(t *testing.T) {
	m := New()
	body := `var x = 1; // just a normal comment`
	ctx := makeHTTPCtx("/app.js", "application/javascript", body)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestScanPerRequest_Dedup(t *testing.T) {
	m := New()
	body := `var x = 1;
//# sourceMappingURL=app.js.map`
	ctx := makeHTTPCtx("/app.js", "application/javascript", body)
	scanCtx := &modkit.ScanContext{}

	// First call should produce results
	results1, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results1, 1)

	// Second call with same host+path (no dedup manager → no dedup, both return results)
	// With a nil DedupMgr, dedup is skipped so both calls return results.
	// This tests that the dedup code path doesn't panic with nil manager.
	results2, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.Len(t, results2, 1)
}

func TestIsMapFileURL(t *testing.T) {
	assert.True(t, isMapFileURL("/app.js.map"))
	assert.True(t, isMapFileURL("/styles.css.MAP"))
	assert.True(t, isMapFileURL("/bundle.min.js.map"))
	assert.False(t, isMapFileURL("/app.js"))
	assert.False(t, isMapFileURL("/sitemap.xml"))
	assert.False(t, isMapFileURL("/map"))
}

func TestIsJSOrCSSContentType(t *testing.T) {
	assert.True(t, isJSOrCSSContentType("application/javascript"))
	assert.True(t, isJSOrCSSContentType("text/javascript"))
	assert.True(t, isJSOrCSSContentType("application/x-javascript"))
	assert.True(t, isJSOrCSSContentType("application/ecmascript"))
	assert.True(t, isJSOrCSSContentType("text/css"))
	assert.True(t, isJSOrCSSContentType("text/css; charset=utf-8"))
	assert.False(t, isJSOrCSSContentType("text/html"))
	assert.False(t, isJSOrCSSContentType("application/json"))
	assert.False(t, isJSOrCSSContentType(""))
}

func TestIsInlineSourcemap(t *testing.T) {
	assert.True(t, isInlineSourcemap("data:application/json;base64,abc"))
	assert.True(t, isInlineSourcemap("Data:application/json;base64,abc"))
	assert.False(t, isInlineSourcemap("app.js.map"))
	assert.False(t, isInlineSourcemap("https://example.com/app.js.map"))
}
