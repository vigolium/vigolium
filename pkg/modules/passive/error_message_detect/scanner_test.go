package error_message_detect

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
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

func TestCanProcess(t *testing.T) {
	m := New()
	assert.False(t, m.CanProcess(nil))
}

func makeHTTPCtx(path, contentType, body string) *httpmsg.HttpRequestResponse {
	return makeHTTPStatusCtx(path, contentType, body, 200, "OK")
}

func makeHTTPStatusCtx(path, contentType, body string, status int, reason string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: %s\r\n\r\n%s", status, reason, contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_JSBundleNotFlagged is a regression for the FP class where
// error/stack-trace tokens baked into a minified JS bundle (served as
// text/javascript at an extensionless route, so the URL-extension guard misses
// it) were reported as live errors. The Content-Type gate must skip them.
func TestScanPerRequest_JSBundleNotFlagged(t *testing.T) {
	m := New()
	body := `function h(e){if(e instanceof TypeError){throw new ReferenceError("java.lang.x")}}var sql="You have an error in your SQL syntax";`
	ctx := makeHTTPCtx("/assets/index-uYP", "text/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_DebugPage(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/test", "text/html", `<html><body>Application-Trace DEBUG = True Exception of type DemoError</body></html>`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "Debug Page in Error Response" {
			found = true
			assert.Equal(t, ModuleID, r.ModuleID)
			assert.Equal(t, output.RecordKindObservation, r.RecordKind)
			break
		}
	}
	assert.True(t, found, "expected Debug Page finding")
}

func TestScanPerRequest_JavaError(t *testing.T) {
	m := New()
	ctx := makeHTTPStatusCtx("/api/test", "text/html", `<html>java.lang.NullPointerException at com.example.App.main(App.java:42)</html>`, 500, "Internal Server Error")
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "Java Error in Error Response" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected Java Error finding")
}

func TestScanPerRequest_SQLError(t *testing.T) {
	m := New()
	ctx := makeHTTPStatusCtx("/search", "text/html", `<html>You have an error in your SQL syntax near 'SELECT * FROM users'</html>`, 500, "Internal Server Error")
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "SQL Error in Error Response" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected SQL Error finding")
}

func TestScanPerRequest_ASPError(t *testing.T) {
	m := New()
	ctx := makeHTTPStatusCtx("/page", "text/html", `<html>Server Error in Application --- End of inner exception stack trace ---</html>`, 500, "Internal Server Error")
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "ASP.NET Error in Error Response" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected ASP Error finding")
}

func TestScanPerRequest_GenericTokenAloneIsIgnored(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/app", "text/html", `<html>TypeError: Cannot read property 'foo' of undefined</html>`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_RuntimeErrorNeedsLocationAndErrorStatus(t *testing.T) {
	m := New()
	ctx := makeHTTPStatusCtx("/app", "text/html", "TypeError: boom\n at handler (/srv/app.js:17:3)", 500, "Internal Server Error")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "Runtime Error in Error Response", results[0].Info.Name)
}

func TestScanPerRequest_NoMatch(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/", "text/html", `<html><body>Hello World</body></html>`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_SkipMediaURL(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/image.png", "image/png", `Traceback`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_SkipBinaryContent(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/data", "image/jpeg", `java.lang.NullPointerException`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_ApacheError(t *testing.T) {
	m := New()
	ctx := makeHTTPStatusCtx("/test", "text/html", `<html>AH00124: Request exceeded the server limit</html>`, 500, "Internal Server Error")
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "Apache Error in Error Response" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected Apache Error finding")
}

func TestScanPerRequest_PostgreSQLError(t *testing.T) {
	m := New()
	ctx := makeHTTPStatusCtx("/query", "text/html", `<html>org.postgresql.util.PSQLException: query failed: relation "users" does not exist</html>`, 500, "Internal Server Error")
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "SQL Error in Error Response" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected SQL Error finding for PostgreSQL")
}

func TestScanPerRequest_SwaggerAndOnLineAreNotErrors(t *testing.T) {
	m := New()
	ctx := makeHTTPStatusCtx("/docs", "text/html", `<script>swaggerUi()</script><p>See configuration on line 12.</p>`, 404, "Not Found")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_StructuredTraceOwnedByVerboseModule(t *testing.T) {
	m := New()
	body := "java.lang.IllegalStateException: boom\n" +
		" at com.example.One.run(One.java:10)\n" +
		" at com.example.Two.run(Two.java:20)\n"
	ctx := makeHTTPStatusCtx("/boom", "text/plain", body, 500, "Internal Server Error")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
