package pdf_generation_injection

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// reflectingHandler echoes the named query parameter back into an HTML body,
// simulating a server-side HTML-to-PDF generator that renders attacker markup
// verbatim — the in-band reflection signature the module's Strategy 1 detects.
func reflectingHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>" + v + "</body></html>"))
	}
}

// TestScanPerInsertionPoint_DetectsReflection drives the real scan method against
// a content-bearing parameter whose injected HTML probe is reflected verbatim.
func TestScanPerInsertionPoint_DetectsReflection(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(reflectingHandler("content"))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/pdf?content=hello")
	ip := modtest.InsertionPoint(t, rr, "content")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a PDF-injection finding when the HTML probe marker is reflected")
	assert.Equal(t, "content", res[0].FuzzingParameter)
	assert.Contains(t, res[0].Info.Name, "PDF Generation Injection")
}

// TestScanPerInsertionPoint_NonPDFParamSkipped ensures a parameter whose name
// does not suggest content/HTML input is skipped entirely (no probing).
func TestScanPerInsertionPoint_NonPDFParamSkipped(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(reflectingHandler("token"))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/pdf?token=hello")
	ip := modtest.InsertionPoint(t, rr, "token")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-content parameter must not be probed for PDF injection")
}

// TestScanPerInsertionPoint_NoReflection ensures a content parameter that is
// never reflected (no PDF, no marker, no OAST) yields no finding.
func TestScanPerInsertionPoint_NoReflection(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>static page</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/pdf?content=hello")
	ip := modtest.InsertionPoint(t, rr, "content")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that never reflects the probe must not yield a PDF-injection finding")
}

// TestIsPDFRelatedParam exercises the pure parameter-name classifier.
func TestIsPDFRelatedParam(t *testing.T) {
	t.Parallel()
	assert.True(t, isPDFRelatedParam("content"))
	assert.True(t, isPDFRelatedParam("invoiceHtml"))
	assert.True(t, isPDFRelatedParam("report"))
	assert.False(t, isPDFRelatedParam("token"))
	assert.False(t, isPDFRelatedParam("session_id"))
}

// TestIsPDFResponse exercises the pure PDF-detection helper across magic bytes
// and content-type signatures.
func TestIsPDFResponse(t *testing.T) {
	t.Parallel()
	assert.True(t, isPDFResponse("%PDF-1.7\n...", ""))
	assert.True(t, isPDFResponse("", "HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n\r\n"))
	assert.False(t, isPDFResponse("<html></html>", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"))
}
