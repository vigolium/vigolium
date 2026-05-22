package proxy_pingback

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// PARTIAL: proxy/pingback confirmation is purely out-of-band — the target only
// "fails" by making an outbound request to an Interactsh/OAST callback URL,
// which httptest cannot observe. These tests cover construction, metadata, and
// the no-OAST early-return path; the asynchronous callback path is exercised by
// the OAST/canary harness instead.

// TestNew_Metadata verifies the module wires its identity, severity, and tags.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, severity.High, m.Severity())
	assert.Contains(t, m.Tags(), "ssrf")
}

// TestScanPerRequest_NoOAST ensures the probe sweep is a no-op (no finding, no
// error) when no OAST provider is configured — the only path observable in-band.
func TestScanPerRequest_NoOAST(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "without an OAST provider the proxy pingback module must not produce findings")
}
