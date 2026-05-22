package reflected_ssti

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

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
