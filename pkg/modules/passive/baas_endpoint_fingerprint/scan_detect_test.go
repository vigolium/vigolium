package baas_endpoint_fingerprint

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

func makeHTTPCtx(host, path, contentType, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure(host, 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// findByProvider returns the finding whose metadata provider matches, or nil.
func findByProvider(results []*outResult, name string) *outResult {
	for _, r := range results {
		if r.Metadata["provider"] == name {
			return r
		}
	}
	return nil
}

// outResult is a tiny alias to keep the helper signature readable.
type outResult = output.ResultEvent

func TestScanPerRequest_DetectsProviders(t *testing.T) {
	t.Parallel()
	m := New()
	// One reference per provider category, mixed into a config blob.
	body := `cfg={` +
		`okta:"https://acme-test.okta.com/oauth2/default",` +
		`fn:"https://europe-west1-harvester-dev-env.cloudfunctions.net/x",` + // firebase-owned: must be ignored
		`supabase:"https://abcdefghijklmnopqrst.supabase.co",` +
		`convex:"https://wandering-cat-123.convex.cloud",` +
		`lambda:"https://abcdefghijklmnop1234.lambda-url.eu-west-1.on.aws/",` +
		`run:"https://my-svc-abcdef.europe-west1.run.app",` +
		`sentry:"https://deadbeef@o4509.ingest.de.sentry.io/123"` +
		`}`
	ctx := makeHTTPCtx("app.example.com", "/main.js", "application/javascript", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	// Okta tenant extracted.
	okta := findByProvider(results, "okta")
	require.NotNil(t, okta, "expected okta finding")
	assert.Equal(t, "acme-test", okta.Metadata["instance"])
	assert.Equal(t, "identity", okta.Metadata["category"])
	assert.Equal(t, ModuleSeverity, okta.Info.Severity)

	// Each non-firebase provider is detected.
	for _, name := range []string{"supabase", "convex", "lambda-url", "cloud-run", "sentry"} {
		assert.NotNil(t, findByProvider(results, name), "expected %s finding", name)
	}

	// Firebase Cloud Functions are intentionally left to firebase_fingerprint.
	assert.Nil(t, findByProvider(results, "cloudfunctions"))
	for _, r := range results {
		assert.NotContains(t, r.Matched, "cloudfunctions.net")
	}
}

func TestScanPerRequest_NoProviders(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><body>nothing to see here, just https://example.com/page</body></html>`
	ctx := makeHTTPCtx("app.example.com", "/", "text/html", body)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_SkipsBinary(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("app.example.com", "/logo.png", "image/png", `https://x.okta.com`)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
