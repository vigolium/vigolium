package error_message_detect

import (
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestScanPerRequest_DebugPage(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/test", "text/html", `<html><body>Traceback (most recent call last): File "app.py" DEBUG = True</body></html>`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "Debug Page in Response" {
			found = true
			assert.Equal(t, ModuleID, r.ModuleID)
			break
		}
	}
	assert.True(t, found, "expected Debug Page finding")
}

func TestScanPerRequest_JavaError(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/api/test", "text/html", `<html>java.lang.NullPointerException at com.example.App.main(App.java:42)</html>`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "Java Error in Response" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected Java Error finding")
}

func TestScanPerRequest_SQLError(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/search", "text/html", `<html>You have an error in your SQL syntax near 'SELECT * FROM users'</html>`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "SQL Error in Response" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected SQL Error finding")
}

func TestScanPerRequest_ASPError(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/page", "text/html", `<html>Server Error in Application --- End of inner exception stack trace ---</html>`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "ASP Error in Response" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected ASP Error finding")
}

func TestScanPerRequest_GenericError(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/app", "text/html", `<html>TypeError: Cannot read property 'foo' of undefined</html>`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "Generic Error in Response" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected Generic Error finding")
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
	ctx := makeHTTPCtx("/test", "text/html", `<html>AH00124: Request exceeded the limit</html>`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "Apache Error in Response" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected Apache Error finding")
}

func TestScanPerRequest_PostgreSQLError(t *testing.T) {
	m := New()
	ctx := makeHTTPCtx("/query", "text/html", `<html>PostgreSQL query ERROR: relation "users" does not exist</html>`)
	scanCtx := &modkit.ScanContext{}

	results, err := m.ScanPerRequest(ctx, scanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "SQL Error in Response" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected SQL Error finding for PostgreSQL")
}
