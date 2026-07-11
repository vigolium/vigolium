package nuxt_config_audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// makeHTTPCtx builds a request/response pair from the given path, response
// headers, and body.
func makeHTTPCtx(path, headers, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET " + path + " HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 200 OK\r\n" + headers + "\r\n" + body
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_StateAWSKey drives an AWS access key embedded in the
// __NUXT__ state blob, which is a public-identifier observation rather than a
// private AWS secret-access-key finding.
func TestScanPerRequest_StateAWSKey(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><script>window.__NUXT__={"awsKey":"AKIA1234567890ABCDEF"};</script></html>`
	ctx := makeHTTPCtx("/", "Content-Type: text/html\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Contains(t, results[0].Info.Name, "Nuxt State Security Signals")
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, results[0].EvidenceGrade)
}

// TestScanPerRequest_DevtoolsEnabled drives the devtools:true config pattern
// in a nuxt JS bundle.
func TestScanPerRequest_DevtoolsEnabled(t *testing.T) {
	t.Parallel()
	m := New()
	body := `export default { devtools: true }`
	ctx := makeHTTPCtx("/nuxt.config.js", "Content-Type: application/javascript\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	found := false
	for _, r := range results {
		if r.Info.Name == "Nuxt Config: Devtools Enabled" {
			found = true
			assert.Equal(t, output.RecordKindObservation, r.RecordKind)
			assert.Equal(t, output.EvidenceGradeObservation, r.EvidenceGrade)
		}
	}
	assert.True(t, found, "expected devtools finding")
}

func TestScanPerRequest_PrivateStateTokenIsCandidate(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><script>window.__NUXT__={"api_token":"sk_live_01` + `23456789ab` + `cdef"};</script></html>`
	ctx := makeHTTPCtx("/", "Content-Type: text/html\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
	for _, evidence := range results[0].ExtractedResults {
		assert.NotContains(t, evidence, "sk_live_01" + "23456789ab" + "cdef")
	}
}

// TestScanPerRequest_Benign verifies a clean HTML page produces no finding.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><script>window.__NUXT__={"page":"home"};</script></html>`
	ctx := makeHTTPCtx("/", "Content-Type: text/html\r\n", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
