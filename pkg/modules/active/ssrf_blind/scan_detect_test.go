package ssrf_blind

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

// PARTIAL: blind SSRF confirmation is purely out-of-band (Interactsh/OAST DNS or
// HTTP callback) and cannot be observed in-band with httptest. These tests cover
// construction, metadata, the no-OAST early-return path, and the pure
// URL-parameter heuristic; the asynchronous callback path is exercised by the
// OAST/canary harness instead.

// TestNew_Metadata verifies the module wires its identity, severity, and tags.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, severity.High, m.Severity())
	assert.Contains(t, m.Tags(), "ssrf")
}

// TestScanPerInsertionPoint_NoOAST ensures the scan is a no-op (no finding, no
// error) when no OAST provider is configured — the only path observable in-band.
func TestScanPerInsertionPoint_NoOAST(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/fetch?url=http://example.com")
	ip := modtest.InsertionPoint(t, rr, "url")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "without an OAST provider the blind SSRF module must not produce findings")
}

// TestLooksLikeURLParam exercises the pure URL-parameter heuristic by name and
// by value prefix.
func TestLooksLikeURLParam(t *testing.T) {
	t.Parallel()
	// Name-based matches.
	assert.True(t, looksLikeURLParam("redirect_url", "anything"))
	assert.True(t, looksLikeURLParam("callback", "x"))
	assert.True(t, looksLikeURLParam("proxy", "x"))
	// Value-based matches.
	assert.True(t, looksLikeURLParam("q", "http://internal/"))
	assert.True(t, looksLikeURLParam("q", "https://internal/"))
	assert.True(t, looksLikeURLParam("q", "//internal/"))
	// Neither name nor value suggests a URL.
	assert.False(t, looksLikeURLParam("q", "hello"))
	assert.False(t, looksLikeURLParam("count", "42"))
}
