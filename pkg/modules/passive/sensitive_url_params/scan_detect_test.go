package sensitive_url_params

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// makeReqCtx builds a request/response pair from the given GET request line path
// (including query string).
func makeReqCtx(pathAndQuery string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET " + pathAndQuery + " HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_SensitiveParam drives a URL with an api_key query parameter
// and expects a finding flagging the parameter name (value masked).
func TestScanPerRequest_SensitiveParam(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeReqCtx("/search?q=widgets&api_key=supersecretvalue")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "api_key", results[0].FuzzingParameter)
	assert.Contains(t, results[0].Info.Description, "api_key")
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
}

// TestScanPerRequest_PasswordParam drives a URL with a password parameter and
// expects a finding.
func TestScanPerRequest_PasswordParam(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeReqCtx("/login?user=bob&password=hunter2")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "password", results[0].FuzzingParameter)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
}

// TestScanPerRequest_Benign drives a URL with only benign parameters and expects
// no findings.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeReqCtx("/search?q=widgets&page=2&sort=name")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_SubstringNameDoesNotTrigger(t *testing.T) {
	t.Parallel()
	for _, q := range []string{
		"/shipping?shipping=express",
		"/tokenizer?tokenizer=wordpiece",
		"/search?pinpoint=location",
	} {
		m := New()
		results, err := m.ScanPerRequest(makeReqCtx(q), &modkit.ScanContext{})
		require.NoError(t, err)
		assert.Emptyf(t, results, "query %q should not match a substring-only parameter name", q)
	}
}

func TestScanPerRequest_PaginationTokenIsObservation(t *testing.T) {
	t.Parallel()
	m := New()
	results, err := m.ScanPerRequest(makeReqCtx("/items?page_token=eyJwYWdlIjoyfQ"), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, results[0].EvidenceGrade)
}

func TestScanPerRequest_PublicIdentifierIsObservation(t *testing.T) {
	t.Parallel()
	m := New()
	results, err := m.ScanPerRequest(makeReqCtx("/maps?api_key=AIzaSyDUMMY000000000000000000000000000"), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
}

// TestScanPerRequest_PlaceholderValueSkipped verifies a sensitive parameter whose
// value is empty or a JS placeholder is not flagged — nothing is disclosed.
func TestScanPerRequest_PlaceholderValueSkipped(t *testing.T) {
	t.Parallel()
	for _, q := range []string{
		"/api?api_key=null",
		"/api?token=undefined",
		"/api?password=",
		"/api?secret=NaN",
	} {
		m := New()
		results, err := m.ScanPerRequest(makeReqCtx(q), &modkit.ScanContext{})
		require.NoError(t, err)
		assert.Emptyf(t, results, "query %q should not be flagged", q)
	}
}
