package response_header_injection

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerInsertionPoint_DetectsBodyInjection drives the real scan method
// against a server that reflects the (URL-decoded) query parameter value into
// the response body without sanitizing CRLF sequences. The module's body-break
// payload injects "\r\n\r\n<injected>CANARY</injected>"; once that lands in the
// response body the module reports a CRLF/response-injection finding.
func TestScanPerInsertionPoint_DetectsBodyInjection(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the decoded parameter value verbatim into the body. The body-break
		// payload carries CRLF + an <injected>canary</injected> marker which then
		// appears in the body, mirroring a server that copies input unsanitized.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("echo: " + r.URL.Query().Get("q")))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=test")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a response-injection finding when CRLF+canary lands in the body")
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a server that never reflects
// the parameter (and sets no attacker-controlled headers) yields no finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("static response, input ignored"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=test")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that ignores the parameter must not yield an injection finding")
}
