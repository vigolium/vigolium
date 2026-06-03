package ssti_detection

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// TestScanPerInsertionPoint_NoFalsePositiveOnRedirectEcho reproduces the
// reported diff-based SSTI false positive: an identity/CIAM-style host that
// 301-redirects every request and echoes the requested query string into the
// Location header. Break (`{{7/0}}`) and escape (`{{7/1}}`) are different
// literal strings, so they produce different Location values — but the body is
// a fixed stub and the status is a constant 301, so there is no template
// evaluation to observe. The module must NOT flag this.
//
// Before the fix, the Location header CRC32 was part of the comparison
// fingerprint, so the echoed (and therefore different) Location made every
// break/escape pair "differ" and the module reported SSTI on a plain redirect.
func TestScanPerInsertionPoint_NoFalsePositiveOnRedirectEcho(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the request query (which carries the injected payload) into the
		// redirect target, exactly like the reported CIAM host.
		w.Header().Set("Location", "/login?next="+r.URL.RawQuery)
		w.WriteHeader(http.StatusMovedPermanently)
		// Fixed-length stub body, identical for every payload.
		_, _ = io.WriteString(w, "<html><body>Moved Permanently</body></html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "redirect that only echoes the payload into Location must not be flagged as SSTI")
}

// TestScanPerInsertionPoint_DetectsEvaluatingEndpoint is the positive control:
// it proves the redirect/reflection hardening did not suppress genuine
// detection. The server models a template engine that *evaluates* the injected
// expression — it returns a different (non-echoed) 200 body depending on whether
// the generic-syntax probe's break (malformed math, unbalanced parens) or escape
// (valid math) was injected, without ever reflecting the payload itself.
func TestScanPerInsertionPoint_DetectsEvaluatingEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Note: classify the targeted parameter value only, never echo it.
		_, _ = io.WriteString(w, classifyEvaluation(r.URL.Query().Get("q")))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=1")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "an endpoint that evaluates injected expressions must still be flagged")
	assert.Contains(t, res[0].Info.Description, "SSTI Detection")
	// Every SSTI finding is now emitted at Info severity (diff-based heuristic,
	// confirm-by-human), regardless of which probe matched.
	assert.Equal(t, severity.Info, res[0].Info.Severity,
		"diff-based SSTI findings must be downgraded to Info severity")
}

// TestScanPerInsertionPoint_NoFalsePositiveOnErrorPageReflection reproduces the
// reported diff-based SSTI false positive on an endpoint that reflects the
// injected payload into a fixed-length error page. Break (`${7/0}`) and escape
// (`${7/1}`) are the same length, so status (500) and content-length are
// identical for both — the only difference is the one reflected byte echoed into
// the body. That is reflection, not template evaluation, and the module must not
// flag it. (Pattern: the body-reflection gate in diffscan.)
func TestScanPerInsertionPoint_NoFalsePositiveOnErrorPageReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		// Echo the payload verbatim, then pad to a constant total length so that
		// content_length is identical for every payload and the reflected bytes
		// are the only body difference — exactly the reported FP shape.
		body := "<html><body>Internal Server Error while processing: " + q + "</body></html>"
		if len(body) < 4096 {
			body += strings.Repeat(" ", 4096-len(body))
		}
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an error page that merely reflects the payload at constant length must not be flagged as SSTI")
}

// TestScanPerInsertionPoint_NoFalsePositiveOn404CookieRotation reproduces the
// reported diff-based SSTI false positive on a 404 with an empty body that
// issues a freshly-named session cookie on every request. The only observable
// difference between break and escape is the rotating Set-Cookie name set, which
// is per-request volatility — nothing rendered, nothing evaluated. The module
// must not flag it. (Patterns: SET_COOKIE_NAMES excluded from the fingerprint,
// plus the non-rendered-context gate for the empty 404 body.)
func TestScanPerInsertionPoint_NoFalsePositiveOn404CookieRotation(t *testing.T) {
	var counter int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt64(&counter, 1)
		http.SetCookie(w, &http.Cookie{Name: fmt.Sprintf("sess_%d", n), Value: "x"})
		w.WriteHeader(http.StatusNotFound)
		// Empty body.
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 404 with an empty body whose only per-request difference is a rotating Set-Cookie must not be flagged as SSTI")
}

// classifyEvaluation models a template engine without reflecting input:
//   - template metacharacters  -> a stable "template" page (so engine-specific
//     probes do not accidentally fire and the soft/crude baselines differ)
//   - balanced parentheses     -> "MATH-OK" (valid expression evaluated)
//   - unbalanced parentheses   -> "MATH-ERROR" (syntax error)
//
// The generic-syntax probe injects an unbalanced break and a balanced escape
// with no template metacharacters, so it yields MATH-ERROR vs MATH-OK — a real,
// non-reflective, non-redirect difference the module should detect.
func classifyEvaluation(q string) string {
	// Template metacharacters, deliberately excluding the math operators
	// (* / ( )) that the generic-syntax probe relies on, so that probe is
	// classified by parenthesis balance instead.
	if strings.ContainsAny(q, "{}$<>%#@~[]=") {
		return "TEMPLATE-METACHAR-PAGE"
	}
	if balancedParens(q) {
		return "MATH-OK"
	}
	return "MATH-ERROR-SYNTAX"
}

func balancedParens(s string) bool {
	depth := 0
	for _, c := range s {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}
