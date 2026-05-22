package xss_scanner

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsReflectedXSS drives the real scan method against a
// server that reflects every query value verbatim into an HTML body. The
// module's canary must come back unencoded, producing a finding.
func TestScanPerRequest_DetectsReflectedXSS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		var b strings.Builder
		b.WriteString("<html><body>results for: ")
		for _, vs := range r.URL.Query() {
			for _, v := range vs {
				b.WriteString(v) // reflected unencoded — the vulnerable behaviour
			}
		}
		b.WriteString("</body></html>")
		_, _ = io.WriteString(w, b.String())
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a reflected-XSS finding when the canary returns unencoded in HTML")
}

// TestScanPerRequest_NoFalsePositiveEncoded ensures that when the server
// HTML-encodes reflected input, the module reports nothing.
func TestScanPerRequest_NoFalsePositiveEncoded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		var b strings.Builder
		b.WriteString("<html><body>results for: ")
		for _, vs := range r.URL.Query() {
			for _, v := range vs {
				// Encode the dangerous characters so no live markup is produced.
				enc := strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(v)
				b.WriteString(enc)
			}
		}
		b.WriteString("</body></html>")
		_, _ = io.WriteString(w, b.String())
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "HTML-encoded reflection must not be reported as XSS")
}

// TestScanPerRequest_NoFalsePositiveNonHTML ensures non-HTML responses are
// skipped even when the input is reflected verbatim (no HTML sink → no XSS).
func TestScanPerRequest_NoFalsePositiveNonHTML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"q":"`+r.URL.Query().Get("q")+`"}`)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "JSON reflection must not be reported as XSS")
}
