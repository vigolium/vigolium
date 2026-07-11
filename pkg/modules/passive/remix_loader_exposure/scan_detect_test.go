package remix_loader_exposure

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// makeHTTPCtx builds an HTML request/response pair with the given body.
func makeHTTPCtx(body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_SensitiveLoaderData drives a Remix context blob carrying an
// API key in loader data and expects an exposure finding from this module.
func TestScanPerRequest_SensitiveLoaderData(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<script>window.__remixContext={"state":{"api_key":"sk_live_01` + `23456789ab` + `cdef"}};</script>`
	ctx := makeHTTPCtx(body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, "Potential Remix Loader Data Exposure", results[0].Info.Name)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
	for _, evidence := range results[0].ExtractedResults {
		assert.NotContains(t, evidence, "sk_live_01" + "23456789ab" + "cdef")
	}
}

func TestScanPerRequest_RoleAndEmailAreObservations(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<script>window.__remixContext={"state":{"role":"admin","email":"user@example.test"}};</script>`
	results, err := m.ScanPerRequest(makeHTTPCtx(body), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, results[0].EvidenceGrade)
}

// TestScanPerRequest_StateBlobOnly is the regression for the presence-only false
// positive: every Remix page ships a state blob (window.__remixManifest /
// __remixContext / "loaderData"), so blob presence WITHOUT any sensitive value
// must NOT produce a finding — otherwise the module fired Medium/Firm on every
// Remix site. A finding now requires an actual sensitive-data match.
func TestScanPerRequest_StateBlobOnly(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<script>window.__remixManifest={"routes":{}};</script>`
	ctx := makeHTTPCtx(body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "a Remix state blob with no sensitive data is normal for any Remix app, not a leak")
}

// TestScanPerRequest_Benign drives an HTML page with no Remix markers and
// expects no findings.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("<html><body>Plain page with no remix data</body></html>")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
