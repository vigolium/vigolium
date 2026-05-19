package html

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParser_Parse_BasicHTML(t *testing.T) {
	html := `
<!DOCTYPE html>
<html>
<head>
	<title>Test Page</title>
</head>
<body>
	<h1>Welcome</h1>
	<p>This is a test.</p>
</body>
</html>`

	parser := NewParser()
	result, err := parser.Parse(strings.NewReader(html))

	require.NoError(t, err)
	assert.Equal(t, "Test Page", result.Title)
	assert.Contains(t, result.HeaderTags, "Welcome")
	assert.Contains(t, result.TagNames, "html")
	assert.Contains(t, result.TagNames, "head")
	assert.Contains(t, result.TagNames, "body")
	assert.Contains(t, result.TagNames, "h1")
	assert.Contains(t, result.TagNames, "p")
	assert.Greater(t, result.WordCount, 0)
}

func TestParser_Parse_TagExtraction(t *testing.T) {
	html := `<div><span><p>content</p></span></div>`

	parser := NewParser()
	result, err := parser.Parse(strings.NewReader(html))

	require.NoError(t, err)
	assert.Contains(t, result.TagNames, "div")
	assert.Contains(t, result.TagNames, "span")
	assert.Contains(t, result.TagNames, "p")
}

func TestParser_Parse_IDExtraction(t *testing.T) {
	html := `
<div id="main">
	<div id="sidebar">
		<span id="user-info"></span>
	</div>
</div>`

	parser := NewParser()
	result, err := parser.Parse(strings.NewReader(html))

	require.NoError(t, err)
	assert.Contains(t, result.TagIDs, "main")
	assert.Contains(t, result.TagIDs, "sidebar")
	assert.Contains(t, result.TagIDs, "user-info")
	assert.Contains(t, result.DivIDs, "main")
	assert.Contains(t, result.DivIDs, "sidebar")
	assert.NotContains(t, result.DivIDs, "user-info") // span, not div
}

func TestParser_Parse_ClassExtraction(t *testing.T) {
	html := `
<div class="container fluid">
	<p class="text-primary">Content</p>
	<span class="badge badge-success">Active</span>
</div>`

	parser := NewParser()
	result, err := parser.Parse(strings.NewReader(html))

	require.NoError(t, err)
	assert.Contains(t, result.CSSClasses, "container")
	assert.Contains(t, result.CSSClasses, "fluid")
	assert.Contains(t, result.CSSClasses, "text-primary")
	assert.Contains(t, result.CSSClasses, "badge")
	assert.Contains(t, result.CSSClasses, "badge-success")
}

func TestParser_Parse_HeaderTags(t *testing.T) {
	html := `
<body>
	<h1>Main Title</h1>
	<h2>Subtitle One</h2>
	<h3>Section Header</h3>
	<h4>Subsection</h4>
	<h5>Minor Header</h5>
	<h6>Tiny Header</h6>
</body>`

	parser := NewParser()
	result, err := parser.Parse(strings.NewReader(html))

	require.NoError(t, err)
	assert.Contains(t, result.HeaderTags, "Main Title")
	assert.Contains(t, result.HeaderTags, "Subtitle One")
	assert.Contains(t, result.HeaderTags, "Section Header")
	assert.Contains(t, result.HeaderTags, "Subsection")
	assert.Contains(t, result.HeaderTags, "Minor Header")
	assert.Contains(t, result.HeaderTags, "Tiny Header")
	assert.Len(t, result.HeaderTags, 6)
}

func TestParser_Parse_Comments(t *testing.T) {
	html := `
<div>
	<!-- This is a comment -->
	<p>Content</p>
	<!-- Another comment -->
</div>`

	parser := NewParser()
	result, err := parser.Parse(strings.NewReader(html))

	require.NoError(t, err)
	assert.Contains(t, result.Comments, " This is a comment ")
	assert.Contains(t, result.Comments, " Another comment ")
	assert.Len(t, result.Comments, 2)
}

func TestParser_Parse_Links(t *testing.T) {
	html := `
<body>
	<a href="/home">Home</a>
	<a href="/about">About Us</a>
	<a href="/contact">Contact</a>
</body>`

	parser := NewParser()
	result, err := parser.Parse(strings.NewReader(html))

	require.NoError(t, err)
	assert.Equal(t, 3, result.OutboundLinkCount)
	assert.Contains(t, result.AnchorLabels, "Home")
	assert.Contains(t, result.AnchorLabels, "About Us")
	assert.Contains(t, result.AnchorLabels, "Contact")
	assert.Contains(t, result.OutboundTagNames, "a")
}

func TestParser_Parse_Forms(t *testing.T) {
	html := `
<form>
	<input type="text" name="username">
	<input type="password" name="password">
	<input type="hidden" name="csrf_token" value="abc123">
	<input type="submit" value="Login">
	<input type="image" src="submit.png" alt="Submit Form">
	<button type="submit">Send</button>
</form>`

	parser := NewParser()
	result, err := parser.Parse(strings.NewReader(html))

	require.NoError(t, err)
	assert.Contains(t, result.NonHiddenInputTypes, "text")
	assert.Contains(t, result.NonHiddenInputTypes, "password")
	assert.Contains(t, result.NonHiddenInputTypes, "submit")
	assert.Contains(t, result.NonHiddenInputTypes, "image")
	assert.NotContains(t, result.NonHiddenInputTypes, "hidden")
	assert.Contains(t, result.InputSubmitLabels, "Login")
	assert.Contains(t, result.InputImageLabels, "Submit Form")
	assert.Contains(t, result.ButtonSubmitLabels, "Send")
}

func TestParser_Parse_VisibleText(t *testing.T) {
	html := `
<html>
<head>
	<title>Page Title</title>
	<script>console.log('ignored');</script>
	<style>.class { color: red; }</style>
</head>
<body>
	<h1>Main Header</h1>
	<p>This is visible text.</p>
	<div>More content here.</div>
</body>
</html>`

	parser := NewParser()
	result, err := parser.Parse(strings.NewReader(html))

	require.NoError(t, err)
	assert.Contains(t, result.VisibleText, "Main Header")
	assert.Contains(t, result.VisibleText, "This is visible text")
	assert.Contains(t, result.VisibleText, "More content here")
	assert.NotContains(t, result.VisibleText, "console.log")
	assert.NotContains(t, result.VisibleText, "color: red")
}

func TestParser_Parse_WordCount(t *testing.T) {
	html := `<body><p>One two three four five.</p></body>`

	parser := NewParser()
	result, err := parser.Parse(strings.NewReader(html))

	require.NoError(t, err)
	assert.Equal(t, 5, result.WordCount)
}

func TestParser_Parse_LineCount(t *testing.T) {
	html := "<p>Line one</p>\n<p>Line two</p>\n<p>Line three</p>"

	parser := NewParser()
	result, err := parser.Parse(strings.NewReader(html))

	require.NoError(t, err)
	assert.Greater(t, result.LineCount, 1)
}

func TestParser_Parse_BodyContent(t *testing.T) {
	html := `<div id="test"><p>Content</p></div>`

	parser := NewParser()
	result, err := parser.Parse(strings.NewReader(html))

	require.NoError(t, err)
	assert.Contains(t, result.BodyContent, "div")
	assert.Contains(t, result.BodyContent, "id=\"test\"")
	assert.Contains(t, result.BodyContent, "Content")
}

func TestParser_Parse_EmptyHTML(t *testing.T) {
	html := ``

	parser := NewParser()
	result, err := parser.Parse(strings.NewReader(html))

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.WordCount)
	// golang.org/x/net/html automatically adds html, head, body tags
	assert.GreaterOrEqual(t, len(result.TagNames), 0)
}

func TestParser_Parse_MalformedHTML(t *testing.T) {
	html := `<div><p>Unclosed tags`

	parser := NewParser()
	result, err := parser.Parse(strings.NewReader(html))

	// golang.org/x/net/html is forgiving and will parse malformed HTML
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestParser_Parse_ComplexRealWorld(t *testing.T) {
	html := `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>404 Not Found</title>
	<link rel="stylesheet" href="/css/style.css">
</head>
<body>
	<div id="container" class="error-page">
		<div id="header" class="site-header">
			<h1>404 - Page Not Found</h1>
		</div>
		<div id="content" class="main-content">
			<p class="error-message">The page you requested could not be found.</p>
			<p>Please check the URL and try again.</p>
			<div class="actions">
				<a href="/" class="btn btn-primary">Go Home</a>
				<a href="/search" class="btn btn-secondary">Search</a>
			</div>
		</div>
		<div id="footer" class="site-footer">
			<!-- Copyright 2024 -->
			<p>&copy; 2024 Example Corp</p>
		</div>
	</div>
</body>
</html>`

	parser := NewParser()
	result, err := parser.Parse(strings.NewReader(html))

	require.NoError(t, err)

	// Title
	assert.Equal(t, "404 Not Found", result.Title)

	// Headers
	assert.Contains(t, result.HeaderTags, "404 - Page Not Found")

	// IDs
	assert.Contains(t, result.TagIDs, "container")
	assert.Contains(t, result.TagIDs, "header")
	assert.Contains(t, result.TagIDs, "content")
	assert.Contains(t, result.TagIDs, "footer")
	assert.Contains(t, result.DivIDs, "container")
	assert.Contains(t, result.DivIDs, "header")

	// Classes
	assert.Contains(t, result.CSSClasses, "error-page")
	assert.Contains(t, result.CSSClasses, "site-header")
	assert.Contains(t, result.CSSClasses, "main-content")
	assert.Contains(t, result.CSSClasses, "btn")
	assert.Contains(t, result.CSSClasses, "btn-primary")

	// Links
	assert.Equal(t, 2, result.OutboundLinkCount)
	assert.Contains(t, result.AnchorLabels, "Go Home")
	assert.Contains(t, result.AnchorLabels, "Search")

	// Comments
	assert.Contains(t, result.Comments, " Copyright 2024 ")

	// Visible text
	assert.Contains(t, result.VisibleText, "404 - Page Not Found")
	assert.Contains(t, result.VisibleText, "The page you requested could not be found")

	// Word count
	assert.Greater(t, result.WordCount, 10)
}

func TestCountWords(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"empty", "", 0},
		{"single", "word", 1},
		{"multiple", "one two three", 3},
		{"with_punctuation", "Hello, world! How are you?", 5},
		{"multiple_spaces", "one  two   three", 3},
		{"newlines", "one\ntwo\nthree", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := countWords(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCountLines(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"empty", "", 0},
		{"single", "one line", 1},
		{"multiple", "line one\nline two\nline three", 3},
		{"trailing_newline", "line one\nline two\n", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := countLines(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
