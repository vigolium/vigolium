package ssr_hydration_xss

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// The module gates on the response's shared, memoised HTML parse
// and runs its lexical pass only for a page whose parse holds a truncated
// hydration script. Proven by removing the script from the already-parsed
// tree: a module that still scanned the raw body on every page would report.
func TestGatesOnSharedHTMLDocument(t *testing.T) {
	t.Parallel()
	body := `<html><body>` +
		`<script id="__NEXT_DATA__" type="application/json">{"q":"x</script><img src=x onerror=alert(1)>y"}</script>` +
		`</body></html>`
	ctx := modtest.HTTPCtx("/page", "text/html", body)

	doc, err := ctx.Response().HTMLDocument()
	require.NoError(t, err)
	script := findElement(doc, "script")
	require.NotNil(t, script)
	script.Parent.RemoveChild(script)

	results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Empty(t, results, "the shared parse holds no hydration script, so the lexical pass must not run")
}

func TestHasTruncatedHydrationScript(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		body string
		want bool
	}{
		{`<script id="__NEXT_DATA__" type="application/json">{"q":"x</script><b>y</b>`, true},
		{`<script>self.__next_f.push([1,"a</script>`, true},
		{`<script id="__NEXT_DATA__" type="application/json">{"q":"x"}</script>`, false},
		{`<script>var a = {"q": "x</script>`, false}, // not a hydration script
	} {
		doc, err := html.Parse(strings.NewReader(tc.body))
		require.NoError(t, err)
		require.Equal(t, tc.want, hasTruncatedHydrationScript(doc), tc.body)
	}
}

func findElement(n *html.Node, tag string) *html.Node {
	if n.Type == html.ElementNode && n.Data == tag {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if f := findElement(c, tag); f != nil {
			return f
		}
	}
	return nil
}
