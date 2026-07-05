package reverse_tabnabbing_detect

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestFlagsCrossOriginBlankLink(t *testing.T) {
	t.Parallel()
	html := `<html><body>` +
		`<a href="https://evil.com/x" target="_blank">bad</a>` + // flagged
		`<a href="https://evil.com/y" target="_blank" rel="noopener">safe</a>` + // rel present
		`<a href="/local" target="_blank">relative</a>` + // same-origin
		`<a href="https://example.com/z" target="_blank">same host</a>` + // same host
		`</body></html>`

	rr := modtest.Request(t, "http://example.com/page")
	rr = modtest.Response(rr, "text/html", html)

	res, err := New().ScanPerRequest(rr, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "expected exactly one reverse-tabnabbing finding")
	// Only the cross-origin no-rel link is listed.
	joined := strings.Join(res[0].ExtractedResults, "\n")
	assert.Contains(t, joined, "https://evil.com/x")
	assert.NotContains(t, joined, "https://evil.com/y")
	assert.NotContains(t, joined, "/local")
	assert.NotContains(t, joined, "example.com/z")
}

func TestNoFindingWhenAllSafe(t *testing.T) {
	t.Parallel()
	html := `<html><body>` +
		`<a href="https://evil.com/x" target="_blank" rel="noopener noreferrer">ok</a>` +
		`<a href="/local">no blank</a>` +
		`</body></html>`

	rr := modtest.Request(t, "http://example.com/page")
	rr = modtest.Response(rr, "text/html", html)

	res, err := New().ScanPerRequest(rr, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}
