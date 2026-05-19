// Package testutil provides common test utilities for spitolas tests.
package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// getProjectRoot returns the repository root directory.
func getProjectRoot() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("failed to get caller info")
	}
	// testutil.go is at pkg/spitolas/internal/testutil/testutil.go
	// Go up 4 levels: testutil -> internal -> spitolas -> pkg -> repo root
	return filepath.Join(filepath.Dir(filename), "..", "..", "..", "..")
}

// LoadTestHTML loads an HTML file from testdata/html/ directory.
func LoadTestHTML(t testing.TB, filename string) string {
	t.Helper()
	path := filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html", filename)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to load test HTML %s: %v", filename, err)
	}
	return string(content)
}

// LoadTestFile loads any file from testdata/ directory.
func LoadTestFile(t testing.TB, relativePath string) string {
	t.Helper()
	path := filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", relativePath)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to load test file %s: %v", relativePath, err)
	}
	return string(content)
}

// ParseHTML parses an HTML string into an html.Node tree.
func ParseHTML(t testing.TB, htmlStr string) *html.Node {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		t.Fatalf("failed to parse HTML: %v", err)
	}
	return doc
}

// ResetCounters is a placeholder - tests should call package-specific reset functions directly.
// For state tests: state.ResetCounter()
// For action tests: action.ResetCounter()
// This avoids import cycles in the testutil package.

// AssertEqual fails the test if expected != actual.
func AssertEqual(t testing.TB, expected, actual interface{}, msgAndArgs ...interface{}) {
	t.Helper()
	if expected != actual {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("assertion failed: expected %v, got %v%s", expected, actual, msg)
	}
}

// AssertNotEqual fails the test if expected == actual.
func AssertNotEqual(t testing.TB, expected, actual interface{}, msgAndArgs ...interface{}) {
	t.Helper()
	if expected == actual {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("assertion failed: expected values to differ, both are %v%s", expected, msg)
	}
}

// AssertTrue fails the test if condition is false.
func AssertTrue(t testing.TB, condition bool, msgAndArgs ...interface{}) {
	t.Helper()
	if !condition {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("assertion failed: expected true%s", msg)
	}
}

// AssertFalse fails the test if condition is true.
func AssertFalse(t testing.TB, condition bool, msgAndArgs ...interface{}) {
	t.Helper()
	if condition {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("assertion failed: expected false%s", msg)
	}
}

// AssertNil fails the test if value is not nil.
func AssertNil(t testing.TB, value interface{}, msgAndArgs ...interface{}) {
	t.Helper()
	if value != nil {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("assertion failed: expected nil, got %v%s", value, msg)
	}
}

// AssertNotNil fails the test if value is nil.
func AssertNotNil(t testing.TB, value interface{}, msgAndArgs ...interface{}) {
	t.Helper()
	if value == nil {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("assertion failed: expected non-nil%s", msg)
	}
}

// AssertContains fails the test if haystack does not contain needle.
func AssertContains(t testing.TB, haystack, needle string, msgAndArgs ...interface{}) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("assertion failed: %q does not contain %q%s", truncate(haystack, 100), needle, msg)
	}
}

// AssertNotContains fails the test if haystack contains needle.
func AssertNotContains(t testing.TB, haystack, needle string, msgAndArgs ...interface{}) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("assertion failed: %q should not contain %q%s", truncate(haystack, 100), needle, msg)
	}
}

// AssertHasPrefix fails the test if s does not start with prefix.
func AssertHasPrefix(t testing.TB, s, prefix string, msgAndArgs ...interface{}) {
	t.Helper()
	if !strings.HasPrefix(s, prefix) {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("assertion failed: %q does not start with %q%s", truncate(s, 100), prefix, msg)
	}
}

// AssertNoError fails the test if err is not nil.
func AssertNoError(t testing.TB, err error, msgAndArgs ...interface{}) {
	t.Helper()
	if err != nil {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("assertion failed: unexpected error: %v%s", err, msg)
	}
}

// AssertError fails the test if err is nil.
func AssertError(t testing.TB, err error, msgAndArgs ...interface{}) {
	t.Helper()
	if err == nil {
		msg := formatMessage(msgAndArgs...)
		t.Errorf("assertion failed: expected error but got nil%s", msg)
	}
}

// formatMessage formats optional message arguments.
func formatMessage(msgAndArgs ...interface{}) string {
	if len(msgAndArgs) == 0 {
		return ""
	}
	if len(msgAndArgs) == 1 {
		return ": " + msgAndArgs[0].(string)
	}
	format := msgAndArgs[0].(string)
	return ": " + strings.TrimSpace(strings.ReplaceAll(format, "%", "%%"))
}

// truncate truncates a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// FindElementByID finds an element by its id attribute in an HTML tree.
func FindElementByID(doc *html.Node, id string) *html.Node {
	var result *html.Node
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode {
			for _, attr := range n.Attr {
				if attr.Key == "id" && attr.Val == id {
					result = n
					return
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
			if result != nil {
				return
			}
		}
	}
	traverse(doc)
	return result
}

// FindElementsByTag finds all elements with the given tag name.
func FindElementsByTag(doc *html.Node, tag string) []*html.Node {
	var results []*html.Node
	tag = strings.ToLower(tag)
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.ToLower(n.Data) == tag {
			results = append(results, n)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(doc)
	return results
}

// GetAttribute gets an attribute value from an element.
func GetAttribute(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

// GetTextContent extracts text content from a node.
func GetTextContent(n *html.Node) string {
	var buf strings.Builder
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.TextNode {
			buf.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(n)
	return strings.TrimSpace(buf.String())
}
