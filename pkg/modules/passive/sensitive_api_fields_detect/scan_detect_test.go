package sensitive_api_fields_detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeJSONCtx builds a JSON request/response pair with the given body.
func makeJSONCtx(body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET /api/user HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_SensitiveFields drives a JSON body exposing a password and
// api_key field and expects a finding from this module.
func TestScanPerRequest_SensitiveFields(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeJSONCtx(`{"user":"bob","password":"hunter2","api_key":"abc123"}`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Sensitive API Fields Detected", results[0].Info.Name)
}

// TestScanPerRequest_SchemaAntiPattern verifies a JSON schema/doc response
// (containing "openapi") is skipped despite a sensitive field name.
func TestScanPerRequest_SchemaAntiPattern(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeJSONCtx(`{"openapi":"3.0.0","components":{"schemas":{"password":{}}}}`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_Benign drives a JSON body with no sensitive field names and
// expects no findings.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeJSONCtx(`{"id":1,"name":"widget","price":9.99}`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
