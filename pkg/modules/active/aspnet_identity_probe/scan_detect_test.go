package aspnet_identity_probe

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsOIDCDiscovery serves an OIDC discovery document at
// /.well-known/openid-configuration. The module probes the fixed identity paths
// and should flag both the probe match and the OIDC metadata enumeration follow-up.
func TestScanPerRequest_DetectsOIDCDiscovery(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"issuer":"https://id.example.com","authorization_endpoint":"https://id.example.com/connect/authorize","token_endpoint":"https://id.example.com/connect/token","scopes_supported":["openid","profile"]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 page not found - unique-baseline-marker"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an identity-exposure finding when the OIDC discovery document is served")
}

// TestScanPerRequest_NoFalsePositive ensures a host with no identity endpoints
// (all probes 404) produces no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 Not Found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host with no identity endpoints must not yield a finding")
}

// TestCanProcess_RequiresResponse verifies the module only runs with a baseline response.
func TestCanProcess_RequiresResponse(t *testing.T) {
	t.Parallel()
	m := New()
	bare := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(bare))
	assert.True(t, m.CanProcess(modtest.Response(bare, "text/html", "<html></html>")))
}

// TestExtractOIDCMetadata covers the discovery-document field extractor.
func TestExtractOIDCMetadata(t *testing.T) {
	t.Parallel()
	discovery := map[string]interface{}{
		"issuer":           "https://id.example.com",
		"token_endpoint":   "https://id.example.com/connect/token",
		"scopes_supported": []interface{}{"openid", "profile"},
	}
	extracted := extractOIDCMetadata(discovery)
	require.NotEmpty(t, extracted)
	joined := strings.Join(extracted, " | ")
	assert.Contains(t, joined, "Issuer: https://id.example.com")
	assert.Contains(t, joined, "token_endpoint")
	assert.Contains(t, joined, "openid, profile")
}
