package log4shell_probe

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

// PARTIAL: Log4Shell confirmation depends entirely on an out-of-band JNDI/LDAP
// or DNS callback to an Interactsh/OAST server, which httptest cannot emulate.
// These tests cover construction, metadata, and both no-OAST early-return paths
// (per-request header injection and per-insertion-point); the asynchronous
// callback path is exercised by the OAST/canary harness instead.

// TestNew_Metadata verifies the module wires its identity, severity, and tags.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, severity.Critical, m.Severity())
	assert.Contains(t, m.Tags(), "rce")
}

// TestScanPerRequest_NoOAST ensures the header-injection path is a no-op when no
// OAST provider is configured.
func TestScanPerRequest_NoOAST(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "without an OAST provider the Log4Shell probe must not produce findings")
}

// TestScanPerInsertionPoint_NoOAST ensures the parameter-injection path is a
// no-op when no OAST provider is configured.
func TestScanPerInsertionPoint_NoOAST(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app?q=1")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "without an OAST provider the Log4Shell probe must not produce findings")
}
