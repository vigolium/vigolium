package response_header_injection

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
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// extractedLocation returns the "location=" value recorded in a finding's
// extracted results (the detection-location kind), or "" if absent.
func extractedLocation(extracted []string) string {
	for _, e := range extracted {
		if v, ok := strings.CutPrefix(e, "location="); ok {
			return v
		}
	}
	return ""
}

// headerSplitServer reflects the decoded "q" parameter verbatim into a real
// response header value over a hijacked connection. Because the parameter
// carries raw CRLF bytes, an injected "X-Injected:"/"Set-Cookie:" line is parsed
// by the HTTP client as a genuine header (or splits the header block) — a real
// CRLF response-header injection rather than mere body reflection.
func headerSplitServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Copy the decoded value (CRLF bytes intact) straight into a header value.
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nX-Reflect: " + v + "\r\nConnection: close\r\n\r\nok"))
	}))
}

// bodyBreakSplitServer reflects "q" into a header value ONLY for the body-break
// payload (the one carrying "<injected>…</injected>"), responding cleanly to the
// header-style payloads so Methods 1 & 2 do not match first. This forces the
// body-break detection path and produces a genuine split where the injected
// marker becomes the LEADING content of the response body.
func bodyBreakSplitServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if !strings.Contains(v, "<injected>") {
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nX-Reflect: " + v + "\r\nConnection: close\r\n\r\n"))
	}))
}

// cookieReflectStripCRLFServer reproduces the reported false positive verbatim: a
// SAML-login endpoint behind CloudFront copies the `q` parameter into a
// Set-Cookie VALUE, but the fronting proxy neutralises the injected CR/LF bytes
// to spaces, so the marker lands mid-line inside an existing header value and the
// header block is never split. The original finding flagged this 200/Content-
// Length:0 response as a confirmed CRLF injection — it must now yield nothing.
func cookieReflectStripCRLFServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		// Mimic the CloudFront/front-end behaviour: collapse CR and LF to spaces
		// so the value stays on a single header line (no split occurs).
		safe := strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nSet-Cookie: q=" + safe +
			";Path=/;HttpOnly;Secure\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
	}))
}

// jsonReflectServer mirrors the real-world false positive: the decoded parameter
// value (CRLF bytes preserved as DATA) is echoed back inside a JSON string in the
// legitimate response body under Content-Type: application/json. The header block
// is never split — this is value reflection, not a CRLF header injection.
func jsonReflectServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Write the value verbatim (no HTML/JSON escaping of the marker), exactly
		// as the datadog-RUM endpoint did in the reported finding.
		_, _ = io.WriteString(w, `{"request_id":"`+v+`"}`)
	}))
}

// TestScanPerInsertionPoint_GenuineHeaderSplit drives the scan against a server
// that copies the parameter into a real response header, splitting the header
// stream. This is a confirmed CRLF response-header injection.
func TestScanPerInsertionPoint_GenuineHeaderSplit(t *testing.T) {
	t.Parallel()
	srv := headerSplitServer()
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=test")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a confirmed header-injection finding")
	assert.Equal(t, locResponseHeader, extractedLocation(res[0].ExtractedResults),
		"a header split must be reported as a response_header injection")
	assert.Equal(t, severity.Undefined, res[0].Info.Severity,
		"without RQP escalation the module default severity is applied later in the pipeline")
}

// TestScanPerInsertionPoint_GenuineBodySplit exercises the body-break path: the
// injected CRLF terminates the header block so the marker is the leading body
// content — genuine HTTP response splitting.
func TestScanPerInsertionPoint_GenuineBodySplit(t *testing.T) {
	t.Parallel()
	srv := bodyBreakSplitServer()
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=test")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a response-splitting finding")
	assert.Equal(t, locBodyInjection, extractedLocation(res[0].ExtractedResults),
		"a leading-body marker after a CRLF split must be reported as response_body_injection")
}

// TestScanPerInsertionPoint_BodyReflectionIsSuspect is the regression test for
// the reported false positive: a JSON endpoint that merely echoes the parameter
// value (CRLF preserved as data) into its body must NOT be reported as a
// confirmed CRLF header injection. It is downgraded to Suspect/Tentative.
func TestScanPerInsertionPoint_BodyReflectionIsSuspect(t *testing.T) {
	t.Parallel()
	srv := jsonReflectServer()
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=test")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "value reflection should still surface, but as a low-confidence Suspect")
	assert.Equal(t, locBodyReflection, extractedLocation(res[0].ExtractedResults),
		"a marker reflected inside the JSON body is reflection, not header injection")
	assert.Equal(t, severity.Suspect, res[0].Info.Severity,
		"body reflection must be reported at Suspect severity, not as a confirmed injection")
	assert.Equal(t, severity.Tentative, res[0].Info.Confidence,
		"body reflection is unconfirmed (Tentative)")
}

// TestScanPerInsertionPoint_HeaderValueReflectionStrippedCRLF is the regression
// test for the reported CloudFront/SAML false positive: the parameter is copied
// into a Set-Cookie value with its CR/LF neutralised to spaces, so the injected
// marker sits mid-line inside an existing header value. The header block is never
// split, so this must NOT be reported as a header injection at any severity.
func TestScanPerInsertionPoint_HeaderValueReflectionStrippedCRLF(t *testing.T) {
	t.Parallel()
	srv := cookieReflectStripCRLFServer()
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=test")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res,
		"a value reflected mid-line into a header (CRLF neutralised) is not a CRLF split and must not be reported")
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

// TestMarkerLeadsBody covers the discriminator that separates a genuine body
// split (marker leads the body) from value reflection (marker embedded in a
// structured body).
func TestMarkerLeadsBody(t *testing.T) {
	t.Parallel()
	const marker = "<injected>vigCANARY</injected>"

	assert.True(t, markerLeadsBody(marker+"\r\ntrailing", marker),
		"marker at the start of the body is a genuine split")
	assert.True(t, markerLeadsBody("\r\n  "+marker, marker),
		"leading CRLF/whitespace before the marker is still a genuine split")
	assert.False(t, markerLeadsBody(`{"request_id":"abc\r\n\r\n`+marker+`"}`, marker),
		"marker embedded inside a JSON string is reflection, not a split")
	assert.False(t, markerLeadsBody("echo: test\r\n\r\n"+marker, marker),
		"marker preceded by echoed content is reflection, not a split")
}

// TestClassifyBodyBreak verifies the three-way classification of a body-break
// match.
func TestClassifyBodyBreak(t *testing.T) {
	t.Parallel()
	const canary = "vigCANARY"
	marker := "<injected>" + canary + "</injected>"

	t.Run("header split", func(t *testing.T) {
		// A genuine split: the injected CRLF survived, so the marker begins its
		// own header line (preceded by a real \n).
		loc, _, ok := classifyBodyBreak("X-Reflect: test\r\n"+marker+"\r\nConnection: close\r\n", "body", "full", canary)
		require.True(t, ok)
		assert.Equal(t, locResponseHeader, loc)
	})
	t.Run("header value reflection (stripped CRLF) is not a split", func(t *testing.T) {
		// The reported false positive: the marker sits mid-line inside an existing
		// header value (CR/LF neutralised to spaces). This is NOT an injection.
		_, _, ok := classifyBodyBreak("Set-Cookie: idp=http://okta/exk    "+marker+";Path=/\r\n", "", "full", canary)
		assert.False(t, ok, "a marker mid-line in a header value must not classify as a header split")
	})
	t.Run("leading body split", func(t *testing.T) {
		loc, _, ok := classifyBodyBreak("Content-Type: text/html\r\n", marker+"\r\nrest", "full", canary)
		require.True(t, ok)
		assert.Equal(t, locBodyInjection, loc)
	})
	t.Run("embedded reflection", func(t *testing.T) {
		loc, _, ok := classifyBodyBreak("Content-Type: application/json\r\n", `{"id":"x\r\n`+marker+`"}`, "full", canary)
		require.True(t, ok)
		assert.Equal(t, locBodyReflection, loc)
	})
	t.Run("absent", func(t *testing.T) {
		_, _, ok := classifyBodyBreak("Content-Type: text/html\r\n", "no marker here", "full", canary)
		assert.False(t, ok)
	})
}

// TestMarkerStartsHeaderLine covers the structural discriminator between a
// genuine CRLF split (marker begins its own header line) and value reflection
// into an existing header (marker mid-line, CR/LF neutralised).
func TestMarkerStartsHeaderLine(t *testing.T) {
	t.Parallel()
	const marker = "<injected>vigCANARY</injected>"

	assert.True(t, markerStartsHeaderLine("X-Reflect: test\r\n"+marker+"\r\n", marker),
		"marker after a real CRLF line terminator is a genuine new header line")
	assert.True(t, markerStartsHeaderLine("X-Reflect: test\n"+marker+"\n", marker),
		"bare-LF before the marker is still a real line terminator on the wire")
	assert.False(t, markerStartsHeaderLine("Set-Cookie: idp=http://okta/exk    "+marker+";Path=/\r\n", marker),
		"marker mid-line inside a header value (CRLF stripped to spaces) is not a split")
	assert.False(t, markerStartsHeaderLine("Set-Cookie: idp=value;Path=/\r\n", marker),
		"absent marker is not a split")
}
