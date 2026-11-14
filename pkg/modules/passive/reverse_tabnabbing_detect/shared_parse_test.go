package reverse_tabnabbing_detect

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// The module reads the response's shared, memoised HTML parse instead of
// tokenizing the body again. Proven by planting the offending link
// in the already-parsed tree only: a module re-reading the raw body misses it.
func TestUsesSharedHTMLDocument(t *testing.T) {
	t.Parallel()
	rr := modtest.Request(t, "http://example.com/page")
	rr = modtest.Response(rr, "text/html", `<html><body><p>no links</p></body></html>`)

	doc, err := rr.Response().HTMLDocument()
	require.NoError(t, err)
	body := findElement(doc, "body")
	require.NotNil(t, body)
	body.AppendChild(&html.Node{
		Type: html.ElementNode, DataAtom: atom.A, Data: "a",
		Attr: []html.Attribute{
			{Key: "href", Val: "https://elsewhere.example/x"},
			{Key: "target", Val: "_blank"},
			{Key: "rel", Val: "opener"},
		},
	})

	res, err := New().ScanPerRequest(rr, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "the link planted in the shared parse must be seen")
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
