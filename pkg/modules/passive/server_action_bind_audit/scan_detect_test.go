package server_action_bind_audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// makeJSCtx builds a request/response pair serving the given JS body from a .js
// path so CanProcess accepts it.
func makeJSCtx(body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET /app/actions.js HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" + body))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_SensitiveBindNoAuth drives a Server Action binding a
// sensitive id via .bind(null, postId) with no authz check, expecting an IDOR
// finding.
func TestScanPerRequest_SensitiveBindNoAuth(t *testing.T) {
	t.Parallel()
	m := New()
	body := `'use server'; const action = deletePost.bind(null, postId);`
	ctx := makeJSCtx(body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Server Action Bound-Identifier Candidate", results[0].Info.Name)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.False(t, results[0].IsFinding())
}

// TestScanPerRequest_SensitiveBindWithAuth verifies an authz check (checkPermission)
// mitigates the bind risk, producing no finding.
func TestScanPerRequest_SensitiveBindWithAuth(t *testing.T) {
	t.Parallel()
	m := New()
	body := `'use server'; checkPermission(); const action = deletePost.bind(null, postId);`
	ctx := makeJSCtx(body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NonSensitiveBind verifies a .bind() with a non-sensitive
// identifier is not flagged.
func TestScanPerRequest_NonSensitiveBind(t *testing.T) {
	t.Parallel()
	m := New()
	body := `'use server'; const action = handler.bind(null, formData);`
	ctx := makeJSCtx(body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NotServerAction verifies a plain JS file with no 'use
// server' directive produces no finding.
func TestScanPerRequest_NotServerAction(t *testing.T) {
	t.Parallel()
	m := New()
	body := `const action = deletePost.bind(null, postId);`
	ctx := makeJSCtx(body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
