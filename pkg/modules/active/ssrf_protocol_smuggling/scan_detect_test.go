package ssrf_protocol_smuggling

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

// PARTIAL: confirmation is purely out-of-band (Interactsh/OAST callback) and
// cannot be observed in-band with httptest. These tests cover construction/
// metadata, the no-OAST early-return path, and the URL-parameter heuristic; the
// asynchronous callback path is exercised by the OAST/canary harness instead.

// TestNew_Metadata verifies the module wires its identity, severity, and tags.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, severity.High, m.Severity())
	assert.Contains(t, m.Tags(), "ssrf")
}

// TestScanPerInsertionPoint_NoOAST ensures the scan is a no-op when no OAST
// provider is configured — the only path observable in-band.
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
	assert.Empty(t, res, "without an OAST provider the smuggling module must not produce findings")
}

// TestSmugglePayloads_Shape verifies every payload carries the OAST placeholder
// and a literal CR-LF (or unicode CR-LF) — the property the transit encoding
// relies on.
func TestSmugglePayloads_Shape(t *testing.T) {
	t.Parallel()
	for _, p := range smugglePayloads {
		assert.Contains(t, p.tmpl, oastPlaceholder, "payload %q must target the OAST host", p.label)
		hasCRLF := containsAny(p.tmpl, "\r\n", "－＊")
		assert.True(t, hasCRLF, "payload %q must embed a CR-LF (ASCII or unicode) sequence", p.label)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}
