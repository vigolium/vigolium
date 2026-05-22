package angular_template_injection

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// basicExprRe matches the basic-expression probe body {{N*M}} (and the
// constructor-bypass variant's inner `return N*M`) so the test server can emulate
// an Angular template engine by evaluating the multiplication.
var basicExprRe = regexp.MustCompile(`\{\{(?:constructor\.constructor\('return )?(\d+)\*(\d+)(?:'\)\(\))?\}\}`)

// evalAngular replaces any {{N*M}} expression in s with the computed product,
// emulating server-side Angular template evaluation.
func evalAngular(s string) string {
	return basicExprRe.ReplaceAllStringFunc(s, func(m string) string {
		parts := basicExprRe.FindStringSubmatch(m)
		a, _ := strconv.Atoi(parts[1])
		b, _ := strconv.Atoi(parts[2])
		return strconv.Itoa(a * b)
	})
}

// TestScanPerInsertionPoint_DetectsTemplateInjection points the module at an
// endpoint that evaluates Angular expressions in the `q` parameter and reflects the
// result. The injected {{mathA*mathB}} resolves to the computed product, which the
// module confirms across multiple attempts.
func TestScanPerInsertionPoint_DetectsTemplateInjection(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		_, _ = w.Write([]byte("<html><body>result: " + evalAngular(q) + "</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an Angular template injection finding when {{N*M}} is evaluated")
}

// TestScanPerInsertionPoint_NoFalsePositive ensures an endpoint that echoes the raw
// (unevaluated) parameter never yields a finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect the parameter verbatim — no template evaluation.
		_, _ = w.Write([]byte("<html><body>you said: " + r.URL.Query().Get("q") + "</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "verbatim reflection without evaluation must not yield a finding")
}
