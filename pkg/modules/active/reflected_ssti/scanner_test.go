package reflected_ssti

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/modules/modtest"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// mulExprRe matches the N*M multiplication embedded in every breakout payload,
// regardless of the surrounding template delimiters, so the test backend can
// emulate a template engine by evaluating it.
var mulExprRe = regexp.MustCompile(`(\d+)\*(\d+)`)

// evalSSTI replaces any N*M expression in s with the computed product, emulating
// server-side template evaluation across every delimiter form the module probes.
func evalSSTI(s string) string {
	return mulExprRe.ReplaceAllStringFunc(s, func(m string) string {
		parts := mulExprRe.FindStringSubmatch(m)
		a, _ := strconv.Atoi(parts[1])
		b, _ := strconv.Atoi(parts[2])
		return strconv.Itoa(a * b)
	})
}

// TestScanPerInsertionPoint_EvaluatedSSTIConfirmed drives the module against a
// backend that evaluates the injected expression and reflects the product. The
// primary probe matches and the reflection-tracking confirmation (fresh random
// operands) evaluates every round, so the finding is reported.
func TestScanPerInsertionPoint_EvaluatedSSTIConfirmed(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>result: " + evalSSTI(r.URL.Query().Get("q")) + "</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "an endpoint that evaluates the expression (tracking fresh operands) must be reported")
}

// TestScanPerInsertionPoint_CoincidentalResultDropped is the generic-value false
// positive: the backend always contains the fixed primary result (3987280) for an
// unrelated reason — here a static product id — but never evaluates any template.
// The primary substring match fires, yet the confirmation's fresh random products
// never appear, so the finding is dropped.
func TestScanPerInsertionPoint_CoincidentalResultDropped(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// 3987280 is baked into the page (a product id), not produced by evaluating
		// the injected expression.
		_, _ = w.Write([]byte(`<html><body data-product-id="3987280">no templating here</body></html>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "the fixed result appearing in the page by coincidence (no evaluation) must not be flagged")
}

func TestNew(t *testing.T) {
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, severity.High, m.Severity())
	assert.Equal(t, severity.Certain, m.Confidence())
	assert.Equal(t, modkit.ScanScopeInsertionPoint, m.ScanScopes())
}

// TestResultMatchesProduct guards the core detection invariant: the module
// searches responses for m.result, which must equal the arithmetic product
// embedded in the injected payloads. If the payload bounds are changed without
// updating result (or vice versa) the module would silently never match,
// producing a class of false negatives that no integration test would surface
// without a live SSTI target.
func TestResultMatchesProduct(t *testing.T) {
	const firstNum, lastNum = 1970, 2024
	m := New()

	wantResult := strconv.Itoa(firstNum * lastNum)
	assert.Equal(t, wantResult, m.result,
		"m.result must equal %d*%d so the detector matches the evaluated expression", firstNum, lastNum)

	product := strconv.Itoa(firstNum * lastNum)
	expr := strconv.Itoa(firstNum) + "*" + strconv.Itoa(lastNum)
	for i, p := range m.payloads {
		assert.Contains(t, p, expr,
			"payload[%d] (%q) must embed the %s expression the result is derived from", i, p, expr)
		// The literal product must NOT be pre-baked into the payload — the
		// server has to evaluate the expression for the marker to appear.
		assert.NotContains(t, p, product,
			"payload[%d] (%q) must not contain the literal product, or detection would false-positive on echoes", i, p)
	}
}

func TestBuildPayloads(t *testing.T) {
	payloads := buildPayloads(7, 7)
	assert.NotEmpty(t, payloads)

	for i, p := range payloads {
		assert.NotEmpty(t, p, "payload[%d] must not be empty", i)
		assert.Contains(t, p, "7*7", "payload[%d] (%q) must embed the math expression", i, p)
	}

	// Should cover a spread of distinct template-engine delimiters, not a
	// single repeated form.
	distinct := map[string]struct{}{}
	for _, p := range payloads {
		distinct[p] = struct{}{}
	}
	assert.GreaterOrEqual(t, len(distinct), 10,
		"expected a varied set of delimiter forms to cover multiple engines")

	// Spot-check that common engine delimiters are represented.
	joined := strings.Join(payloads, "\n")
	assert.Contains(t, joined, "{{7*7}}", "Jinja2/Twig-style delimiter expected")
	assert.Contains(t, joined, "<%=7*7%>", "ERB/EJS-style delimiter expected")
}
