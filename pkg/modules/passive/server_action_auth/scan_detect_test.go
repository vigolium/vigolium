package server_action_auth

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
	return makeJSCtxAt("/app/actions.js", body)
}

// makeJSCtxAt is makeJSCtx with a caller-chosen request path.
func makeJSCtxAt(path, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET " + path + " HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" + body))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_NextStaticBundleSkipped is the regression for the
// client-build-artifact false positive: the Next.js compiler ships the
// "use server" directive string plus loose mutation-shaped tokens
// (Object.create(...), .remove(...)) in framework runtime chunks, so scanning a
// /_next/static/ bundle produced one "Server Action Missing Authorization"
// finding per host. Server action bodies are compiled out of client bundles, so
// the module must skip these immutable build paths.
func TestScanPerRequest_NextStaticBundleSkipped(t *testing.T) {
	t.Parallel()
	m := New()
	// Same signal that fires at /app/actions.js, but served from a client bundle.
	body := `function t(){"use server"};o.create({});e.remove(1)`
	ctx := makeJSCtxAt("/_next/static/chunks/main-93dbaebda72da021.js", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "a client build artifact must not be scanned for server-action bugs")
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_MutationNoAuth drives a Server Action with a 'use server'
// directive and a DB mutation but no auth check, and expects a finding.
func TestScanPerRequest_MutationNoAuth(t *testing.T) {
	t.Parallel()
	m := New()
	body := `async function saveUser(data){'use server'; await prisma.user.create({data}); }`
	ctx := makeJSCtx(body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Server Action Authorization Candidate", results[0].Info.Name)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.False(t, results[0].IsFinding())
}

// TestScanPerRequest_MutationWithAuth verifies that a Server Action performing a
// mutation but also calling an auth check produces no finding.
func TestScanPerRequest_MutationWithAuth(t *testing.T) {
	t.Parallel()
	m := New()
	body := `async function saveUser(data){'use server'; const s = await getServerSession(); await prisma.user.create({data}); }`
	ctx := makeJSCtx(body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NoMutation verifies that a 'use server' action with no
// mutation pattern produces no finding.
func TestScanPerRequest_NoMutation(t *testing.T) {
	t.Parallel()
	m := New()
	body := `async function getData(){'use server'; return fetch('/api'); }`
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
	body := `function add(a,b){ return a+b; }`
	ctx := makeJSCtx(body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
