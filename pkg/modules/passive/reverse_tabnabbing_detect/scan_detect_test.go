package reverse_tabnabbing_detect

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestOrdinaryBlankLinkUsesImplicitNoopener(t *testing.T) {
	t.Parallel()
	html := `<html><body>` +
		`<a href="https://elsewhere.example/x" target="_blank">modern implicit noopener</a>` +
		`<a href="https://elsewhere.example/y" target="_blank" rel="noopener">explicitly safe</a>` +
		`</body></html>`

	rr := modtest.Request(t, "http://example.com/page")
	rr = modtest.Response(rr, "text/html", html)

	res, err := New().ScanPerRequest(rr, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}

func TestFlagsExplicitCrossOriginOpener(t *testing.T) {
	t.Parallel()
	html := `<html><body>` +
		`<a href="https://elsewhere.example/x" target="_blank" rel="external opener">unsafe</a>` +
		`<a href="https://elsewhere.example/y" target="_blank" rel="opener noopener">noopener wins</a>` +
		`<a href="/local" target="_blank" rel="opener">same origin</a>` +
		`</body></html>`

	rr := modtest.Request(t, "http://example.com/page")
	rr = modtest.Response(rr, "text/html", html)

	res, err := New().ScanPerRequest(rr, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	joined := strings.Join(res[0].ExtractedResults, "\n")
	assert.Contains(t, joined, "https://elsewhere.example/x")
	assert.NotContains(t, joined, "https://elsewhere.example/y")
	assert.NotContains(t, joined, "/local")
	assert.Equal(t, "candidate", string(res[0].RecordKind))
}

func TestOriginComparisonIncludesSchemeAndPort(t *testing.T) {
	t.Parallel()
	html := `<a href="http://example.com/path" target="_blank" rel="opener">scheme downgrade</a>` +
		`<a href="https://example.com:444/path" target="_blank" rel="opener">different port</a>`
	rr := modtest.Response(modtest.Request(t, "https://example.com/page"), "text/html", html)
	res, err := New().ScanPerRequest(rr, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	joined := strings.Join(res[0].ExtractedResults, "\n")
	assert.Contains(t, joined, "http://example.com/path")
	assert.Contains(t, joined, "https://example.com:444/path")
}
