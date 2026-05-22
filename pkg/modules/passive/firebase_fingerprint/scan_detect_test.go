package firebase_fingerprint

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

// TestScanPerRequest_FirebaseConfig drives a JS response carrying a full
// Firebase config object (strong signal + extractable values) and expects a
// fingerprint finding.
func TestScanPerRequest_FirebaseConfig(t *testing.T) {
	t.Parallel()
	m := New()
	body := `var firebaseConfig = {
		"apiKey": "AIzaSyA1234567890abcdefghijklmnopqrstuvw",
		"authDomain": "myapp-prod.firebaseapp.com",
		"databaseURL": "https://myapp-prod.firebaseio.com",
		"projectId": "myapp-prod",
		"storageBucket": "myapp-prod.appspot.com",
		"appId": "1:1234567890:web:abcdef123456"
	};
	firebase.initializeApp(firebaseConfig);`
	ctx := makeHTTPCtx("/app.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "Firebase Installation Detected" {
			found = true
			assert.Equal(t, ModuleID, r.ModuleID)
			break
		}
	}
	assert.True(t, found, "expected Firebase Installation Detected finding")
}

// TestScanPerRequest_DevProject drives a Firebase config that references a
// dev/staging project ID and expects the non-production misconfiguration
// finding in addition to the fingerprint.
func TestScanPerRequest_DevProject(t *testing.T) {
	t.Parallel()
	m := New()
	body := `firebaseConfig = {"projectId":"myapp-staging", "databaseURL":"https://myapp-staging.firebaseio.com"};`
	ctx := makeHTTPCtx("/index.html", "text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	found := false
	for _, r := range results {
		if r.Info.Name == "Firebase Non-Production Project in Use" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected non-production project finding")
}

// TestScanPerRequest_NoFirebase drives a benign HTML response with no Firebase
// signals and expects no findings.
func TestScanPerRequest_NoFirebase(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/", "text/html", `<html><body>Hello World</body></html>`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NonHTMLJS drives a non-HTML/JS content type and expects
// the module to bail out before scanning.
func TestScanPerRequest_NonHTMLJS(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/data.txt", "text/plain", `firebase.initializeApp({projectId:"x"})`)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
