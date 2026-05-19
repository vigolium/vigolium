package formparser

import (
	"bytes"
	"strings"

	"golang.org/x/net/html"
)

// getAttr returns the value of an attribute from an html.Node.
// Returns empty string if attribute not found.
func getAttr(n *html.Node, key string) string {
	if n == nil {
		return ""
	}
	for _, attr := range n.Attr {
		if strings.EqualFold(attr.Key, key) {
			return attr.Val
		}
	}
	return ""
}

// hasAttr checks if an html.Node has a specific attribute (regardless of value).
func hasAttr(n *html.Node, key string) bool {
	if n == nil {
		return false
	}
	for _, attr := range n.Attr {
		if strings.EqualFold(attr.Key, key) {
			return true
		}
	}
	return false
}

// isElement checks if node is an element with the given tag name.
func isElement(n *html.Node, tagName string) bool {
	return n != nil && n.Type == html.ElementNode && strings.EqualFold(n.Data, tagName)
}

// getTextContent extracts all text content from a node and its descendants.
func getTextContent(n *html.Node) string {
	if n == nil {
		return ""
	}

	if n.Type == html.TextNode {
		return n.Data
	}

	var sb strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		sb.WriteString(getTextContent(c))
	}
	return sb.String()
}

// renderNode renders an html.Node and its children to HTML string.
func renderNode(n *html.Node) string {
	if n == nil {
		return ""
	}
	var buf bytes.Buffer
	if err := html.Render(&buf, n); err != nil {
		return ""
	}
	return buf.String()
}

// findFirstElement finds the first element with given tag name in subtree (depth-first).
func findFirstElement(n *html.Node, tagName string) *html.Node {
	if n == nil {
		return nil
	}

	if isElement(n, tagName) {
		return n
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if found := findFirstElement(c, tagName); found != nil {
			return found
		}
	}
	return nil
}

// findAllElements finds all elements with given tag name in subtree.
func findAllElements(n *html.Node, tagName string) []*html.Node {
	var results []*html.Node
	findAllElementsRecursive(n, tagName, &results)
	return results
}

func findAllElementsRecursive(n *html.Node, tagName string, results *[]*html.Node) {
	if n == nil {
		return
	}

	if isElement(n, tagName) {
		*results = append(*results, n)
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		findAllElementsRecursive(c, tagName, results)
	}
}
