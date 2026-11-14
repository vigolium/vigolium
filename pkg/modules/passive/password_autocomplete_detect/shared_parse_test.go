package password_autocomplete_detect

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// The module reads the response's shared, memoised HTML parse instead of
// tokenizing the body again. Proven by planting the password field
// in the already-parsed tree only: a module re-reading the raw body misses it.
func TestUsesSharedHTMLDocument(t *testing.T) {
	t.Parallel()
	rr := modtest.Request(t, "http://example.com/login")
	rr = modtest.Response(rr, "text/html", `<html><body><form action="/login"></form></body></html>`)

	doc, err := rr.Response().HTMLDocument()
	require.NoError(t, err)
	form := findElement(doc, "form")
	require.NotNil(t, form)
	form.AppendChild(&html.Node{
		Type: html.ElementNode, DataAtom: atom.Input, Data: "input",
		Attr: []html.Attribute{{Key: "type", Val: "password"}, {Key: "name", Val: "password"}},
	})

	res, err := New().ScanPerRequest(rr, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "the field planted in the shared parse must be seen")
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
