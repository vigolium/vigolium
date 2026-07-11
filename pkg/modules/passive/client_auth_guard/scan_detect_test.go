package client_auth_guard

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// makeJSCtx builds a JavaScript request/response pair carrying the given body.
func makeJSCtx(path, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n%s", body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_ClientOnlyGuard drives a client component that performs a
// useEffect-based redirect to /login. A passive bundle scan can only retain it
// as an observation, not call it a bypass.
func TestScanPerRequest_ClientOnlyGuard(t *testing.T) {
	t.Parallel()
	m := New()
	body := `"use client";
export default function Page() {
  useEffect(() => {
    if (!user) router.push('/login');
  }, [user]);
  return <Dashboard />;
}`
	ctx := makeJSCtx("/dashboard.js", body)
	require.True(t, m.CanProcess(ctx))

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Client-Side Auth Redirect Observation", results[0].Info.Name)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, results[0].EvidenceGrade)
	assert.Equal(t, severity.Info, results[0].Info.Severity)
}

// TestScanPerRequest_WithServerAuth verifies that a client redirect alongside a
// server-side auth check is not flagged.
func TestScanPerRequest_WithServerAuth(t *testing.T) {
	t.Parallel()
	m := New()
	body := `"use client";
const session = await getServerSession();
export default function Page() {
  useEffect(() => {
    if (!user) router.push('/login');
  }, [user]);
}`
	ctx := makeJSCtx("/dashboard.js", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NoUseClient verifies a server component (no "use client")
// is skipped entirely.
func TestScanPerRequest_NoUseClient(t *testing.T) {
	t.Parallel()
	m := New()
	body := `export default function Page() {
  useEffect(() => { router.push('/login'); }, []);
}`
	ctx := makeJSCtx("/dashboard.js", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
