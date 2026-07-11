package pdf_generation_injection

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
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

// TestScanPerInsertionPoint_RawReflectionIsNotPDFEvidence verifies that ordinary
// HTML echoing is not mislabeled as server-side PDF generation or execution.
func TestScanPerInsertionPoint_RawReflectionIsNotPDFEvidence(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(reflectingHandler("content"))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/pdf?content=hello")
	ip := modtest.InsertionPoint(t, rr, "content")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "raw HTML reflection does not prove PDF rendering or code execution")
}

func TestClassifyReflection_RuntimeHTMLMarkerIsCandidate(t *testing.T) {
	t.Parallel()
	rp := reflectionPayload{
		payload: `<h1>VIGOLIUM_&#80;DF_RENDER_test</h1>`, marker: "VIGOLIUM_PDF_RENDER_test",
		name: "html-rendering", sev: severity.Medium, conf: severity.Firm,
		kind: output.RecordKindCandidate, grade: output.EvidenceGradeCandidate,
	}
	verdict := classifyReflection(rp, "%PDF baseline", "%PDF VIGOLIUM_PDF_RENDER_test", "Content-Type: application/pdf")
	assert.True(t, verdict.hit)
}

func TestClassifyReflection_RawPayloadInPDFIsNotExecution(t *testing.T) {
	t.Parallel()
	rp := reflectionPayload{
		payload: `<script>document.write('VIGOLIUM_PDF_'+'EXEC_test')</script>`, marker: "VIGOLIUM_PDF_EXEC_test",
		name: "js-execution", sev: severity.High, conf: severity.Firm,
	}
	verdict := classifyReflection(rp, "%PDF baseline", "%PDF "+rp.payload, "Content-Type: application/pdf")
	assert.False(t, verdict.hit, "echoing split JavaScript source does not create the runtime-only marker")
}

func TestClassifyReflection_AnyPDFDoesNotProveFileRead(t *testing.T) {
	t.Parallel()
	rp := reflectionPayload{
		payload: `<iframe src="file:///etc/passwd"></iframe>`, marker: "root:x:0:0:",
		name: "local-file-read", sev: severity.High, conf: severity.Certain,
	}
	assert.False(t, classifyReflection(rp, "%PDF baseline", "%PDF ordinary invoice", "Content-Type: application/pdf").hit)
	assert.True(t, classifyReflection(rp, "%PDF baseline", "%PDF root:x:0:0:root:/root:/bin/bash", "Content-Type: application/pdf").hit)
}

func TestClassifyReflection_BaselineMarkerSuppressesFinding(t *testing.T) {
	t.Parallel()
	rp := reflectionPayload{payload: "probe", marker: "root:x:0:0:", name: "local-file-read"}
	assert.False(t, classifyReflection(rp, "%PDF root:x:0:0:", "%PDF root:x:0:0:", "Content-Type: application/pdf").hit)
}

// jsonEchoHandler echoes the injected parameter back verbatim inside a JSON
// validation-error body — the FastAPI/Pydantic `int_parsing` 422 shape, where
// the bad value (HTML tags intact) lands in the error's `input` field. The
// markup survives unescaped as a JSON string value but is never rendered as
// HTML, so it is not PDF-generation evidence.
func jsonEchoHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(
			`{"detail":[{"type":"int_parsing","loc":["query","` + param +
				`"],"msg":"Input should be a valid integer","input":"` + v + `"}]}`))
	}
}

// TestScanPerInsertionPoint_JSONErrorEchoNotHTML is the regression for the
// FastAPI JSON-validation-error false positive: the injected <h1> probe is echoed
// verbatim in an application/json 422 body, so the raw-payload substring test
// passes, yet the marker is a JSON string value that never renders as HTML. The
// content-type gate must reject it.
func TestScanPerInsertionPoint_JSONErrorEchoNotHTML(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(jsonEchoHandler("page"))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/feed?page=1")
	ip := modtest.InsertionPoint(t, rr, "page")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an HTML marker echoed inside a JSON error body is not HTML-rendering evidence")
}

// encodedReflectingHandler echoes the param back URL-ENCODED inside a URL string
// — the Cloudflare-Access / SSO-login redirect_url pattern. The bare marker text
// survives but the injected <h1> tags come back as %3Ch1%3E, so nothing rendered
// as HTML. The module must NOT treat neutralized reflection as PDF injection.
func encodedReflectingHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(
			`<html><body><a href="/login?redirect_url=` +
				url.QueryEscape(v) + `">retry</a></body></html>`))
	}
}

// TestScanPerInsertionPoint_NeutralizedReflection is the Cloudflare-Access SSO
// false-positive: the marker text reflects but the HTML tags are URL-encoded, so
// the body is effectively the same with or without live markup. No finding.
func TestScanPerInsertionPoint_NeutralizedReflection(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(encodedReflectingHandler("content"))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/pdf?content=hello")
	ip := modtest.InsertionPoint(t, rr, "content")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "URL-encoded marker reflection (SSO redirect_url echo) is neutralized — not PDF injection")
}

// TestScanPerInsertionPoint_LoginShellSkipped ensures a login/SSO wall that
// reflects raw markup but renders a password field is not flagged: such pages
// echo redirect-style params into the page and are never PDF generators.
func TestScanPerInsertionPoint_LoginShellSkipped(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("content")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(
			`<html><body>` + v +
				`<form><input type="password" name="pw"></form></body></html>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/pdf?content=hello")
	ip := modtest.InsertionPoint(t, rr, "content")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a login/SSO wall that reflects markup must not be flagged as PDF injection")
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

func TestScanPerInsertionPoint_OrdinaryPDFDoesNotProveFileRead(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		_, _ = w.Write([]byte("%PDF-1.7\nordinary static invoice content"))
	}))
	defer srv.Close()

	rr := modtest.Request(t, srv.URL+"/render?content=hello")
	ip := modtest.InsertionPoint(t, rr, "content")
	res, err := New().ScanPerInsertionPoint(rr, ip, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a normal PDF response without runtime/file markers is not an injection finding")
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
