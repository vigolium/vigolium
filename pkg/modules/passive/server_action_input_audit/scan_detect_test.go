package server_action_input_audit

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

// TestScanPerRequest_MissingValidation drives a Server Action that reads FormData and
// performs a DB write without any runtime validation library, which should flag.
func TestScanPerRequest_MissingValidation(t *testing.T) {
	t.Parallel()
	m := New()
	body := `'use server'
async function createUser(formData) {
  const name = formData.get('name');
  await prisma.user.create({ data: { name } });
}`
	ctx := makeHTTPCtx("/app/actions.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Server Action Missing Input Validation", results[0].Info.Name)
}

// TestScanPerRequest_WithValidation verifies that a Server Action using a zod schema
// (runtime validation) does not flag.
func TestScanPerRequest_WithValidation(t *testing.T) {
	t.Parallel()
	m := New()
	body := `'use server'
async function createUser(formData) {
  const data = z.object({ name: z.string() }).parse({ name: formData.get('name') });
  await prisma.user.create({ data });
}`
	ctx := makeHTTPCtx("/app/actions.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NoServerAction verifies that JS without a "use server" directive
// produces no findings.
func TestScanPerRequest_NoServerAction(t *testing.T) {
	t.Parallel()
	m := New()
	body := `function greet(name) { return "hello " + name; }`
	ctx := makeHTTPCtx("/app/util.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
