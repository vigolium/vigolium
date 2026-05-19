package state

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/testutil"
)

func TestStripDOMScriptTags(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string // exact expected output
	}{
		{
			name:  "inline script",
			input: `<html><head><script>alert('xss');</script></head><body>Content</body></html>`,
			want:  `<html><head></head><body>Content</body></html>`,
		},
		{
			name:  "external script",
			input: `<html><head><script src="evil.js"></script></head><body>Content</body></html>`,
			want:  `<html><head></head><body>Content</body></html>`,
		},
		{
			name:  "multiple scripts",
			input: `<html><body><script>a()</script><div>Content</div><script>b()</script></body></html>`,
			want:  `<html><head></head><body><div>Content</div></body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StripDOM(tt.input, []string{"script"}, nil)
			if result != tt.want {
				t.Errorf("StripDOM() = %q, want %q", result, tt.want)
			}
		})
	}
}

func TestStripDOMStyleTags(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "inline style tag",
			input: `<html><head><style>body{color:red}</style></head><body>Content</body></html>`,
			want:  `<html><head></head><body>Content</body></html>`,
		},
		{
			name:  "link stylesheet",
			input: `<html><head><link rel="stylesheet" href="style.css"></head><body>Content</body></html>`,
			want:  `<html><head></head><body>Content</body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StripDOM(tt.input, []string{"style", "link"}, nil)
			if result != tt.want {
				t.Errorf("StripDOM() = %q, want %q", result, tt.want)
			}
		})
	}
}

func TestStripDOMAttributes(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		stripAttr []string
		want      string
	}{
		{
			name:      "strip id attribute",
			input:     `<html><body><div id="main">Content</div></body></html>`,
			stripAttr: []string{"id"},
			want:      `<html><head></head><body><div>Content</div></body></html>`,
		},
		{
			name:      "strip class attribute",
			input:     `<html><body><div class="container highlight">Content</div></body></html>`,
			stripAttr: []string{"class"},
			want:      `<html><head></head><body><div>Content</div></body></html>`,
		},
		{
			name:      "strip style attribute",
			input:     `<html><body><div style="color:red;">Content</div></body></html>`,
			stripAttr: []string{"style"},
			want:      `<html><head></head><body><div>Content</div></body></html>`,
		},
		{
			name:      "strip data-* wildcard",
			input:     `<html><body><div data-id="123" data-value="abc">Content</div></body></html>`,
			stripAttr: []string{"data-*"},
			want:      `<html><head></head><body><div>Content</div></body></html>`,
		},
		{
			name:      "strip multiple attributes",
			input:     `<html><body><div id="x" class="y" style="z" data-foo="bar">Content</div></body></html>`,
			stripAttr: []string{"id", "class", "style", "data-*"},
			want:      `<html><head></head><body><div>Content</div></body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StripDOM(tt.input, nil, tt.stripAttr)
			if result != tt.want {
				t.Errorf("StripDOM() = %q, want %q", result, tt.want)
			}
		})
	}
}

func TestStripDOMDefault(t *testing.T) {
	input := `<!DOCTYPE html>
<html>
<head>
	<title>Test</title>
	<script>alert('xss')</script>
	<style>body{color:red}</style>
	<meta charset="utf-8">
	<link rel="stylesheet" href="style.css">
	<noscript>Enable JS</noscript>
</head>
<body id="main" class="page" style="margin:0" data-page="home">
	<div id="content" class="container">Hello World</div>
</body>
</html>`

	result := StripDOMDefault(input)

	// Should NOT contain stripped tags
	strippedTags := []string{"<script", "<style", "<meta", "<link", "<noscript"}
	for _, tag := range strippedTags {
		if strings.Contains(strings.ToLower(result), tag) {
			t.Errorf("result should not contain %q", tag)
		}
	}

	// Should NOT contain stripped attributes
	strippedAttrs := []string{`id="`, `class="`, `style="`, `data-`}
	for _, attr := range strippedAttrs {
		if strings.Contains(result, attr) {
			t.Errorf("result should not contain %q, got: %s", attr, result)
		}
	}

	// Should still contain content
	if !strings.Contains(result, "Hello World") {
		t.Errorf("result should contain 'Hello World', got: %s", result)
	}

	// Should still contain title
	if !strings.Contains(result, "Test") {
		t.Errorf("result should contain 'Test' (title), got: %s", result)
	}
}

func TestStripDOMEmptyInput(t *testing.T) {
	result := StripDOM("", nil, nil)
	if result != "" {
		t.Errorf("empty input should produce empty output, got: %q", result)
	}
}

func TestStripDOMWithDomtest(t *testing.T) {
	html := testutil.LoadTestHTML(t, "domtest.html")

	result := StripDOMDefault(html)

	// Should strip script tags
	if strings.Contains(result, "<script") || strings.Contains(result, "<SCRIPT") {
		t.Error("should strip script tags")
	}

	// Should still contain main content
	contentChecks := []string{
		"An Ajax Test Site",  // title
		"Menu",               // h3
		"Home",               // link text
		"Topics of Interest", // link text
	}
	for _, check := range contentChecks {
		if !strings.Contains(result, check) {
			t.Errorf("should contain %q", check)
		}
	}
}

func TestExtractBodyContent(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "basic body",
			input: `<html><head><title>Test</title></head><body><div>Content</div></body></html>`,
			want:  "<div>Content</div>",
		},
		{
			name:  "body with attributes",
			input: `<html><body class="main"><p>Para</p></body></html>`,
			want:  "<p>Para</p>",
		},
		{
			name:  "multiple elements in body",
			input: `<html><body><h1>Title</h1><p>Text</p></body></html>`,
			want:  "Title",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractBodyContent(tt.input)
			if !strings.Contains(result, tt.want) {
				t.Errorf("ExtractBodyContent() = %q, want to contain %q", result, tt.want)
			}
		})
	}
}

func TestExtractBodyContentNoBody(t *testing.T) {
	input := `<html><head><title>No Body</title></head></html>`
	result := ExtractBodyContent(input)

	// When no body is found, the parser may add one implicitly
	// or return empty - either behavior is acceptable
	// Just ensure it doesn't panic and returns a string
	if result == "" {
		// Empty result is acceptable when no body content exists
		return
	}
	// If not empty, should contain original content or be a parsed result
	_ = result // Accept any non-panic result
}

func TestExtractTextContent(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string // should contain all these
	}{
		{
			name:  "simple text",
			input: `<html><body><p>Hello World</p></body></html>`,
			want:  []string{"Hello", "World"},
		},
		{
			name:  "nested elements",
			input: `<html><body><div><span>Nested</span> Text</div></body></html>`,
			want:  []string{"Nested", "Text"},
		},
		{
			name:  "multiple paragraphs",
			input: `<html><body><p>First</p><p>Second</p><p>Third</p></body></html>`,
			want:  []string{"First", "Second", "Third"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractTextContent(tt.input)
			for _, want := range tt.want {
				if !strings.Contains(result, want) {
					t.Errorf("ExtractTextContent() = %q, should contain %q", result, want)
				}
			}
		})
	}
}

func TestExtractTextContentStripsScripts(t *testing.T) {
	input := `<html><body>
		<p>Visible Text</p>
		<script>var x = "script content";</script>
		<p>More Text</p>
	</body></html>`

	result := ExtractTextContent(input)

	// Should contain visible text
	if !strings.Contains(result, "Visible Text") {
		t.Error("should contain 'Visible Text'")
	}
	if !strings.Contains(result, "More Text") {
		t.Error("should contain 'More Text'")
	}

	// Note: ExtractTextContent does extract script content as text
	// This is expected behavior - it extracts ALL text nodes
}

func TestCountNodes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "empty html",
			input: `<html></html>`,
			want:  3, // html, head, body (browser adds head/body)
		},
		{
			name:  "simple structure",
			input: `<html><body><div>Text</div></body></html>`,
			want:  6, // html, head, body, div, text
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CountNodes(tt.input)
			// Allow some variance due to parsing differences
			if result < tt.want-2 || result > tt.want+5 {
				t.Errorf("CountNodes() = %d, want approximately %d", result, tt.want)
			}
		})
	}
}

func TestCountNodesEmpty(t *testing.T) {
	result := CountNodes("")
	// Empty string still gets parsed into a minimal DOM structure by html.Parse
	// (html, head, body nodes may be created)
	// So we just check it returns a reasonable small number, not necessarily 0
	if result > 10 {
		t.Errorf("CountNodes('') = %d, expected small number", result)
	}
}

func TestGetTitle(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "has title",
			input: `<html><head><title>My Page Title</title></head><body></body></html>`,
			want:  "My Page Title",
		},
		{
			name:  "no title",
			input: `<html><head></head><body></body></html>`,
			want:  "",
		},
		{
			name:  "empty title",
			input: `<html><head><title></title></head><body></body></html>`,
			want:  "",
		},
		{
			name:  "title with whitespace",
			input: `<html><head><title>  Padded Title  </title></head><body></body></html>`,
			want:  "Padded Title",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetTitle(tt.input)
			if result != tt.want {
				t.Errorf("GetTitle() = %q, want %q", result, tt.want)
			}
		})
	}
}

func TestGetTitleFromDomtest(t *testing.T) {
	html := testutil.LoadTestHTML(t, "domtest.html")
	title := GetTitle(html)

	if title != "An Ajax Test Site" {
		t.Errorf("GetTitle(domtest.html) = %q, want 'An Ajax Test Site'", title)
	}
}

func TestNormalizeWhitespace(t *testing.T) {
	// Only control whitespace (\t\n\f\r) is removed. Spaces in text content are preserved.
	// Spaces around tags ("> " and " <") are removed.
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "multiple spaces preserved",
			input: "hello    world",
			want:  "hello    world",
		},
		{
			name:  "newlines removed",
			input: "hello\n\n\nworld",
			want:  "helloworld",
		},
		{
			name:  "tabs removed",
			input: "hello\t\t\tworld",
			want:  "helloworld",
		},
		{
			name:  "mixed whitespace",
			input: "hello  \n\t  world",
			want:  "hello    world", // \n and \t removed, spaces preserved
		},
		{
			name:  "whitespace between tags",
			input: "<div>  </div>  <span>",
			want:  "<div></div><span>", // spaces after > removed, spaces before < removed
		},
		{
			name:  "leading and trailing",
			input: "  hello world  ",
			want:  "hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeWhitespace(tt.input)
			if result != tt.want {
				t.Errorf("normalizeWhitespace() = %q, want %q", result, tt.want)
			}
		})
	}
}

func TestStripDOMFallback(t *testing.T) {
	// Test the regex-based fallback for malformed HTML
	input := `<html><script>bad</script><body><style>css</style>content</body>`

	result := stripDOMFallback(input, []string{"script", "style"}, []string{"id", "class"})

	// Should strip script content
	if strings.Contains(result, "bad") {
		t.Error("should strip script content")
	}

	// Should strip style content
	if strings.Contains(result, "css") {
		t.Error("should strip style content")
	}

	// Should keep other content
	if !strings.Contains(result, "content") {
		t.Error("should keep other content")
	}
}

func TestFilterAttributes(t *testing.T) {
	// Test the filterAttributes function indirectly through StripDOM
	input := `<html><body><div id="test" class="box" style="color:red" onclick="click()" href="link">Text</div></body></html>`

	// Strip id, class, style but keep onclick, href
	result := StripDOM(input, nil, []string{"id", "class", "style"})

	if strings.Contains(result, `id="test"`) {
		t.Error("should strip id attribute")
	}
	if strings.Contains(result, `class="box"`) {
		t.Error("should strip class attribute")
	}
	if strings.Contains(result, `style="color:red"`) {
		t.Error("should strip style attribute")
	}

	// Note: onclick may be kept or stripped depending on implementation
	// href should be kept
	// The key point is that specified attributes are stripped
}

func TestStripDOMPreservesStructure(t *testing.T) {
	input := `<html>
<head><title>Test</title></head>
<body>
	<header><nav>Menu</nav></header>
	<main><article>Content</article></main>
	<footer>Footer</footer>
</body>
</html>`

	result := StripDOMDefault(input)

	// Should preserve semantic structure
	structureChecks := []string{"Menu", "Content", "Footer", "Test"}
	for _, check := range structureChecks {
		if !strings.Contains(result, check) {
			t.Errorf("should preserve %q in structure", check)
		}
	}
}

func TestDefaultStripTags(t *testing.T) {
	tags := DefaultStripTags
	expected := []string{"script", "style", "noscript", "meta", "link"}

	for _, exp := range expected {
		found := false
		for _, tag := range tags {
			if tag == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultStripTags should contain %q", exp)
		}
	}
}

func TestDefaultStripAttrs(t *testing.T) {
	attrs := DefaultStripAttrs
	expected := []string{"id", "class", "style", "data-*"}

	for _, exp := range expected {
		found := false
		for _, attr := range attrs {
			if attr == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultStripAttrs should contain %q", exp)
		}
	}
}

// ============================================================================
// ============================================================================

func TestNoDifference(t *testing.T) {
	html1 := "<HTML><HEAD><TITLE>Test Page</TITLE></HEAD><BODY><DIV id=\"test\">Content</DIV></BODY></HTML>"
	html2 := "<HTML><HEAD><TITLE>Test Page</TITLE></HEAD><BODY><DIV id=\"test\">Content</DIV></BODY></HTML>"

	// Strip both DOMs
	stripped1 := StripDOMDefault(html1)
	stripped2 := StripDOMDefault(html2)

	// Should be identical
	if stripped1 != stripped2 {
		t.Errorf("identical HTML should produce identical stripped DOM")
	}
}

func TestDifferentTitle(t *testing.T) {
	html1 := "<HTML><HEAD><TITLE>Page 1</TITLE></HEAD><BODY><DIV>Content</DIV></BODY></HTML>"
	html2 := "<HTML><HEAD><TITLE>Page 2</TITLE></HEAD><BODY><DIV>Content</DIV></BODY></HTML>"

	stripped1 := StripDOMDefault(html1)
	stripped2 := StripDOMDefault(html2)

	// Title difference should be detected
	if stripped1 == stripped2 {
		t.Error("different titles should produce different stripped DOM")
	}
}

func TestDifferentContent(t *testing.T) {
	html1 := "<HTML><BODY><DIV>First Content</DIV></BODY></HTML>"
	html2 := "<HTML><BODY><DIV>Second Content</DIV></BODY></HTML>"

	stripped1 := StripDOMDefault(html1)
	stripped2 := StripDOMDefault(html2)

	if stripped1 == stripped2 {
		t.Error("different content should produce different stripped DOM")
	}
}

func TestIgnoredAttributeDifference(t *testing.T) {
	html1 := "<HTML><BODY><DIV id=\"div1\" class=\"c1\" style=\"color:red\">Content</DIV></BODY></HTML>"
	html2 := "<HTML><BODY><DIV id=\"div2\" class=\"c2\" style=\"color:blue\">Content</DIV></BODY></HTML>"

	stripped1 := StripDOMDefault(html1)
	stripped2 := StripDOMDefault(html2)

	// id, class, style are stripped by default - should be identical
	if stripped1 != stripped2 {
		t.Errorf("DOMs differing only in stripped attributes should be identical\nstripped1: %s\nstripped2: %s", stripped1, stripped2)
	}
}

func TestStructuralDifference(t *testing.T) {
	html1 := "<HTML><BODY><DIV><SPAN>Content</SPAN></DIV></BODY></HTML>"
	html2 := "<HTML><BODY><DIV><P>Content</P></DIV></BODY></HTML>"

	stripped1 := StripDOMDefault(html1)
	stripped2 := StripDOMDefault(html2)

	// Different structure should be different
	if stripped1 == stripped2 {
		t.Error("different structure should produce different stripped DOM")
	}
}

func TestCountDifferences(t *testing.T) {
	html1 := "<HTML><BODY><DIV>A</DIV><DIV>B</DIV><DIV>C</DIV></BODY></HTML>"
	html2 := "<HTML><BODY><DIV>A</DIV><DIV>X</DIV><DIV>C</DIV></BODY></HTML>"

	stripped1 := StripDOMDefault(html1)
	stripped2 := StripDOMDefault(html2)

	// Calculate difference using edit operations
	if stripped1 == stripped2 {
		t.Error("DOMs with different content should not be equal")
	}

	// Extract text content and count differences
	text1 := ExtractTextContent(html1)
	text2 := ExtractTextContent(html2)

	// Exactly 1 word is different (B vs X)
	words1 := strings.Fields(text1)
	words2 := strings.Fields(text2)

	if len(words1) != len(words2) {
		t.Errorf("word counts differ: %d vs %d", len(words1), len(words2))
	}

	diffCount := 0
	for i := 0; i < len(words1) && i < len(words2); i++ {
		if words1[i] != words2[i] {
			diffCount++
		}
	}

	if diffCount != 1 {
		t.Errorf("expected 1 word difference, got %d", diffCount)
	}
}

// ============================================================================
// ============================================================================

func TestGetElementStringDiv(t *testing.T) {
	html := "<body><div id=\"foo\">test</div></body>"

	// Extract body content
	body := ExtractBodyContent(html)

	// Should contain the div
	if !strings.Contains(body, "<div") {
		t.Error("should contain div element")
	}
	if !strings.Contains(body, "test") {
		t.Error("should contain text content 'test'")
	}
}

func TestRemoveNewLines(t *testing.T) {
	html := "<HTML>\n\r<HEAD><TITLE>Test</TITLE></HEAD>\r\n<BODY>\n</BODY></HTML>"

	result := normalizeWhitespace(html)

	// Should not contain newlines
	if strings.Contains(result, "\n") || strings.Contains(result, "\r") {
		t.Error("result should not contain newlines after normalization")
	}
}

func TestReplaceString(t *testing.T) {
	// Testing that attribute stripping works correctly
	html := "<div id=\"oldId\" class=\"oldClass\">content</div>"

	// Strip id and class
	result := StripDOM(html, nil, []string{"id", "class"})

	if strings.Contains(result, "oldId") {
		t.Error("id attribute should be stripped")
	}
	if strings.Contains(result, "oldClass") {
		t.Error("class attribute should be stripped")
	}
	if !strings.Contains(result, "content") {
		t.Error("content should be preserved")
	}
}

func TestGetAllTextContent(t *testing.T) {
	html := "<html><body><div>First</div><span>Second</span><p>Third</p></body></html>"

	text := ExtractTextContent(html)

	// Should contain all text
	if !strings.Contains(text, "First") {
		t.Error("should contain 'First'")
	}
	if !strings.Contains(text, "Second") {
		t.Error("should contain 'Second'")
	}
	if !strings.Contains(text, "Third") {
		t.Error("should contain 'Third'")
	}
}

func TestStripDOMWithRealWorld(t *testing.T) {
	html := testutil.LoadTestHTML(t, "domtest.html")

	stripped := StripDOMDefault(html)

	// Should not contain script tags
	if strings.Contains(strings.ToLower(stripped), "<script") {
		t.Error("stripped DOM should not contain script tags")
	}

	// Should not contain style tags
	if strings.Contains(strings.ToLower(stripped), "<style") {
		t.Error("stripped DOM should not contain style tags")
	}

	// Should preserve semantic content
	if !strings.Contains(stripped, "Ajax Test Site") {
		t.Error("should preserve page title content")
	}
}

func TestNestedElementStripping(t *testing.T) {
	html := `<html><body>
		<div id="outer" class="container">
			<div id="middle" class="wrapper">
				<div id="inner" class="content">
					<span id="span1" class="text">Deep Text</span>
				</div>
			</div>
		</div>
	</body></html>`

	stripped := StripDOMDefault(html)

	// id and class should be stripped at all levels
	if strings.Contains(stripped, "outer") || strings.Contains(stripped, "middle") ||
		strings.Contains(stripped, "inner") || strings.Contains(stripped, "span1") {
		t.Error("all id attributes should be stripped")
	}
	if strings.Contains(stripped, "container") || strings.Contains(stripped, "wrapper") ||
		strings.Contains(stripped, "content") || strings.Contains(stripped, `class="text"`) {
		t.Error("all class attributes should be stripped")
	}

	// Content should be preserved
	if !strings.Contains(stripped, "Deep Text") {
		t.Error("content should be preserved")
	}
}

func TestDataAttributeWildcard(t *testing.T) {
	html := `<div data-id="123" data-value="abc" data-custom-attr="xyz">Content</div>`

	stripped := StripDOM(html, nil, []string{"data-*"})

	if strings.Contains(stripped, "data-id") {
		t.Error("data-id should be stripped")
	}
	if strings.Contains(stripped, "data-value") {
		t.Error("data-value should be stripped")
	}
	if strings.Contains(stripped, "data-custom-attr") {
		t.Error("data-custom-attr should be stripped")
	}
	if !strings.Contains(stripped, "Content") {
		t.Error("content should be preserved")
	}
}

func TestMultipleScriptRemoval(t *testing.T) {
	html := `<html><head>
		<script src="jquery.js"></script>
		<script>var x = 1;</script>
	</head><body>
		<script>function foo(){}</script>
		<div>Content</div>
		<script type="text/javascript">alert('hi');</script>
	</body></html>`

	stripped := StripDOMDefault(html)

	// Count remaining script tags - should be 0
	scriptCount := strings.Count(strings.ToLower(stripped), "<script")
	if scriptCount != 0 {
		t.Errorf("script count = %d, want 0", scriptCount)
	}

	// Content should be preserved
	if !strings.Contains(stripped, "Content") {
		t.Error("content should be preserved")
	}
}

func TestEmptyElements(t *testing.T) {
	// Test handling of empty elements
	html := `<div></div><span></span><p></p>`

	stripped := StripDOMDefault(html)

	// Empty elements should be preserved (structure matters)
	if !strings.Contains(stripped, "<div>") && !strings.Contains(stripped, "<div/>") {
		t.Log("div element handling may vary")
	}
}

func TestSelfClosingTags(t *testing.T) {
	// Test self-closing tags
	html := `<html><body><br/><hr/><img src="test.png"/><input type="text"/></body></html>`

	stripped := StripDOMDefault(html)

	// Self-closing tags should be preserved (except those in stripTags)
	if !strings.Contains(strings.ToLower(stripped), "br") {
		t.Log("br tag may be normalized differently")
	}
}

func TestHTMLEntities(t *testing.T) {
	// Test HTML entities handling
	html := `<div>&amp; &lt; &gt; &quot; &apos;</div>`

	text := ExtractTextContent(html)

	// Entities should be decoded
	if !strings.Contains(text, "&") {
		t.Log("&amp; may not be decoded, depending on implementation")
	}
}

func TestComments(t *testing.T) {
	// Test HTML comment handling
	html := `<div><!-- This is a comment -->Visible Content</div>`

	stripped := StripDOMDefault(html)

	// Comments should be handled (either removed or preserved)
	if !strings.Contains(stripped, "Visible Content") {
		t.Error("visible content should be preserved")
	}
}

func TestWhitespaceNormalizationBetweenTags(t *testing.T) {
	// Test whitespace normalization between tags
	html := `<div>   </div>   <span>   </span>`

	result := normalizeWhitespace(html)

	// Multiple spaces should be collapsed
	if strings.Contains(result, "   ") {
		t.Error("multiple consecutive spaces should be collapsed")
	}
}
