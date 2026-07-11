package firebase_functions_exposure

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// NEEDS-PHASE-3: positive detection probes real *.cloudfunctions.net URLs
// extracted from the seed response body. The module builds raw absolute-URL
// requests against cloudfunctions.net with no service/host override, so it
// cannot be redirected to an in-process httptest server; confirming
// unauthenticated access or error leakage requires a live (or DNS-mocked)
// Cloud Functions endpoint.

// TestNew_Metadata verifies module construction and identity.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.NotEmpty(t, m.Name())
	assert.NotEmpty(t, m.ModuleTags)
}

// TestCanProcess covers the response-required guard.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil))

	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(rr), "no response attached should be rejected")

	withResp := modtest.Response(rr, "text/html", "<html></html>")
	assert.True(t, m.CanProcess(withResp))
}

// TestScanPerRequest_NoFunctionURL ensures a body with no cloudfunctions.net
// URLs short-circuits with no finding and no outbound probe.
func TestScanPerRequest_NoFunctionURL(t *testing.T) {
	t.Parallel()
	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, "http://example.com/"),
		"text/html",
		"<html><body>no cloud functions referenced</body></html>",
	)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "no Cloud Function URL in body must yield no finding")
}

// TestCloudFuncURLRegex confirms the function URL and its trailing function
// name are extracted. The region/project split is greedy (group 1 absorbs the
// extra hyphenated segments), so we assert on the stable function-name group.
func TestCloudFuncURLRegex(t *testing.T) {
	t.Parallel()
	m := cloudFuncURLRe.FindStringSubmatch("https://us-central1-demo-app.cloudfunctions.net/listUsers")
	require.Len(t, m, 4)
	assert.Equal(t, "https://us-central1-demo-app.cloudfunctions.net/listUsers", m[0])
	assert.Equal(t, "listUsers", m[3])

	assert.Nil(t, cloudFuncURLRe.FindStringSubmatch("https://example.com/no-match"))
}

// TestExtractHost exercises the pure host-extraction helper.
func TestExtractHost(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "us-central1-demo-app.cloudfunctions.net",
		extractHost("https://us-central1-demo-app.cloudfunctions.net/listUsers"))
	assert.Equal(t, "host.example", extractHost("http://host.example"))
}

func TestMeaningfulFunctionResponse(t *testing.T) {
	t.Parallel()
	assert.True(t, meaningfulFunctionResponse(`{"items":[{"id":1}]}`, "application/json"))
	assert.False(t, meaningfulFunctionResponse(`{}`, "application/json"))
	assert.False(t, meaningfulFunctionResponse(`not-json`, "application/json"))
	assert.False(t, meaningfulFunctionResponse(`ok`, "text/plain"))
}

func TestStackLeakEvidenceRequiresIndependentCategories(t *testing.T) {
	t.Parallel()
	markers, categories := stackLeakEvidence("TypeError: bad input")
	assert.GreaterOrEqual(t, len(markers), 1)
	assert.Equal(t, 1, categories, "generic exception text alone is not a stack trace")

	markers, categories = stackLeakEvidence("TypeError: bad input\n at Object.handler (/workspace/index.js:12)\nnode_modules/pkg/index.js")
	assert.GreaterOrEqual(t, len(markers), 3)
	assert.GreaterOrEqual(t, categories, 2)
}
