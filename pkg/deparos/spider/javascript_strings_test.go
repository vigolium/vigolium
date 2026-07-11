package spider

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJavaScriptStringExtractor_ExtractStrings(t *testing.T) {
	tests := []struct {
		name     string
		jsCode   string
		offset   int
		expected []*JSString
	}{
		{
			name:   "simple double quote string",
			jsCode: `var url = "https://example.com/api";`,
			offset: 0,
			expected: []*JSString{
				{Value: "https://example.com/api", Position: 11},
			},
		},
		{
			name:   "simple single quote string",
			jsCode: `var url = 'https://example.com/api';`,
			offset: 0,
			expected: []*JSString{
				{Value: "https://example.com/api", Position: 11},
			},
		},
		{
			name:   "multiple strings",
			jsCode: `var a = "first"; var b = 'second'; var c = "third";`,
			offset: 0,
			expected: []*JSString{
				{Value: "first", Position: 9},
				{Value: "second", Position: 26},
				{Value: "third", Position: 44},
			},
		},
		{
			name:   "string with escaped quotes",
			jsCode: `var str = "He said \"hello\" there";`,
			offset: 0,
			expected: []*JSString{
				{Value: `He said \"hello\" there`, Position: 11},
			},
		},
		{
			name:   "string with escaped backslash",
			jsCode: `var path = "C:\\Users\\test\\file.txt";`,
			offset: 0,
			expected: []*JSString{
				{Value: `C:\\Users\\test\\file.txt`, Position: 12},
			},
		},
		{
			name:   "empty strings",
			jsCode: `var a = ""; var b = '';`,
			offset: 0,
			expected: []*JSString{
				{Value: "", Position: 9},
				{Value: "", Position: 21},
			},
		},
		{
			name:   "line comment should be ignored",
			jsCode: "// This is a comment with \"string\"\nvar url = \"test\";",
			offset: 0,
			expected: []*JSString{
				{Value: "test", Position: 46},
			},
		},
		{
			name:   "block comment should be ignored",
			jsCode: `/* This is a comment with "string" */ var url = "test";`,
			offset: 0,
			expected: []*JSString{
				{Value: "test", Position: 49},
			},
		},
		{
			name:   "nested block comment with strings",
			jsCode: `var a = "before"; /* "commented" */ var b = "after";`,
			offset: 0,
			expected: []*JSString{
				{Value: "before", Position: 9},
				{Value: "after", Position: 45},
			},
		},
		{
			name:   "string containing comment-like text",
			jsCode: `var str = "This has // comment syntax";`,
			offset: 0,
			expected: []*JSString{
				{Value: "This has // comment syntax", Position: 11},
			},
		},
		{
			name:   "string with HTML content",
			jsCode: `var html = "<div class='test'>Hello</div>";`,
			offset: 0,
			expected: []*JSString{
				{Value: "<div class='test'>Hello</div>", Position: 12},
			},
		},
		{
			name:   "string with URL",
			jsCode: `var url = "https://example.com/path?query=value#fragment";`,
			offset: 0,
			expected: []*JSString{
				{Value: "https://example.com/path?query=value#fragment", Position: 11},
			},
		},
		{
			name:     "unclosed string at end",
			jsCode:   `var str = "unclosed`,
			offset:   0,
			expected: []*JSString{
				// No strings extracted because string is not closed
			},
		},
		{
			name:   "string with newline escape",
			jsCode: `var str = "line1\nline2\nline3";`,
			offset: 0,
			expected: []*JSString{
				{Value: `line1\nline2\nline3`, Position: 11},
			},
		},
		{
			name:   "mixed quotes",
			jsCode: `var a = "double"; var b = 'single'; var c = "double again";`,
			offset: 0,
			expected: []*JSString{
				{Value: "double", Position: 9},
				{Value: "single", Position: 27},
				{Value: "double again", Position: 45},
			},
		},
		{
			name:   "consecutive strings",
			jsCode: `"first""second""third"`,
			offset: 0,
			expected: []*JSString{
				{Value: "first", Position: 1},
				{Value: "second", Position: 8},
				{Value: "third", Position: 16},
			},
		},
		{
			name:   "string with offset",
			jsCode: `var url = "test";`,
			offset: 100,
			expected: []*JSString{
				{Value: "test", Position: 111}, // 100 + 11
			},
		},
		{
			name:   "line comment with newline",
			jsCode: "// comment\nvar url = \"test\";",
			offset: 0,
			expected: []*JSString{
				{Value: "test", Position: 22},
			},
		},
		{
			name:   "block comment multiline",
			jsCode: "/* line1\nline2\nline3 */\nvar url = \"test\";",
			offset: 0,
			expected: []*JSString{
				{Value: "test", Position: 35},
			},
		},
		{
			name: "complex real-world example",
			jsCode: `
function loadUser(id) {
    var apiUrl = "https://api.example.com/users/" + id;
    // Fetch user data
    fetch(apiUrl).then(function(response) {
        var html = '<div class="user">' + response.name + '</div>';
        /* Process the HTML */
        document.body.innerHTML = html;
    });
}
`,
			offset: 0,
			expected: []*JSString{
				{Value: "https://api.example.com/users/", Position: 43},
				{Value: `<div class="user">`, Position: 168},
				{Value: `</div>`, Position: 207},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewJavaScriptStringExtractor(nil, nil)
			result := extractor.ExtractStrings(tt.jsCode, tt.offset)

			require.Len(t, result, len(tt.expected), "Expected %d strings, got %d", len(tt.expected), len(result))

			for i, expected := range tt.expected {
				assert.Equal(t, expected.Value, result[i].Value, "String %d value mismatch", i)
				assert.Equal(t, expected.Position, result[i].Position, "String %d position mismatch", i)
			}
		})
	}
}

func TestJavaScriptStringExtractor_LooksLikeHTML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "simple HTML tag",
			input:    "<div>test</div>",
			expected: true,
		},
		{
			name:     "HTML with attributes",
			input:    `<a href="http://example.com">link</a>`,
			expected: true,
		},
		{
			name:     "self-closing tag",
			input:    `<img src="test.jpg" />`,
			expected: true,
		},
		{
			name:     "plain text no HTML",
			input:    "just plain text",
			expected: false,
		},
		{
			name:     "URL without HTML",
			input:    "https://example.com/path",
			expected: false,
		},
		{
			name:     "only opening bracket",
			input:    "test < 5",
			expected: false,
		},
		{
			name:     "only closing bracket",
			input:    "test > 5",
			expected: false,
		},
		{
			name:     "both brackets but not HTML",
			input:    "5 < x > 3",
			expected: true, // Simple heuristic returns true
		},
		{
			name:     "HTML fragment",
			input:    `<span class="test">Content</span>`,
			expected: true,
		},
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewJavaScriptStringExtractor(nil, nil)
			result := extractor.LooksLikeHTML(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJavaScriptStringExtractor_ScanStringForURLs(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectFound bool
	}{
		{
			name:        "contains absolute HTTP URL",
			input:       "http://example.com/path",
			expectFound: true,
		},
		{
			name:        "contains absolute HTTPS URL",
			input:       "https://example.com/path",
			expectFound: true,
		},
		{
			name:        "contains WS URL",
			input:       "ws://example.com/socket",
			expectFound: true,
		},
		{
			name:        "contains WSS URL",
			input:       "wss://example.com/socket",
			expectFound: true,
		},
		{
			name:        "no URL",
			input:       "just plain text here",
			expectFound: false,
		},
		{
			name:        "too short",
			input:       "short",
			expectFound: false,
		},
		{
			name:        "URL in middle of text",
			input:       "Check out https://example.com for more info",
			expectFound: true,
		},
		{
			name:        "relative URL",
			input:       "/api/users/123",
			expectFound: true,
		},
	}

	baseURL, _ := url.Parse("https://example.com")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := NewURLResolver()

			inlineScanner := NewInlineURLScanner(resolver)
			extractor := NewJavaScriptStringExtractor(inlineScanner, nil)

			ctx := context.Background()
			// ScanStringForURLs reports whether ANY URL is present (absolute or
			// relative); it only EMITS relative routes (absolute URLs are surfaced by
			// the companion inlineScanner.Extract pass). Emission is covered by
			// TestJavaScriptStringExtractor_EmitsInlineURLs; here we assert the bool.
			result := extractor.ScanStringForURLs(ctx, baseURL, tt.input, 0, nil)

			if tt.expectFound {
				assert.True(t, result, "Expected URL to be found")
			} else {
				assert.False(t, result, "Expected no URL to be found")
			}
		})
	}
}

func TestJavaScriptStringExtractor_Extract(t *testing.T) {
	baseURL, _ := url.Parse("https://example.com")

	tests := []struct {
		name          string
		jsCode        string
		expectedLinks []expectedLink
	}{
		{
			name:          "JavaScript with HTML string",
			jsCode:        `var html = "<div>test</div>";`,
			expectedLinks: []expectedLink{},
		},
		{
			name:          "JavaScript with short string",
			jsCode:        `var x = "short";`,
			expectedLinks: []expectedLink{},
		},
		{
			name:          "JavaScript with long non-URL string",
			jsCode:        `var msg = "This is a long message without any URLs";`,
			expectedLinks: []expectedLink{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := NewURLResolver()

			inlineScanner := NewInlineURLScanner(resolver)
			htmlExtractor := NewHTMLAttributeExtractor(resolver)
			extractor := NewJavaScriptStringExtractor(inlineScanner, htmlExtractor)

			response := &HTTPResponse{
				URL:       baseURL,
				Body:      []byte(tt.jsCode),
				BodyStart: 0,
			}

			ctx := context.Background()
			var discoveredLinks []*DiscoveredLink
			err := extractor.Extract(ctx, baseURL, response, func(link *DiscoveredLink) {
				discoveredLinks = append(discoveredLinks, link)
			})

			require.NoError(t, err)
			require.Len(t, discoveredLinks, len(tt.expectedLinks), "Expected %d links, got %d", len(tt.expectedLinks), len(discoveredLinks))

			for i, expected := range tt.expectedLinks {
				actual := discoveredLinks[i]
				assert.Equal(t, expected.url, actual.URL.String(), "Link %d URL mismatch", i)
				assert.Equal(t, expected.rawURL, actual.RawURL, "Link %d RawURL mismatch", i)
				assert.Equal(t, expected.sourceType, actual.SourceType, "Link %d SourceType mismatch", i)
				assert.Equal(t, expected.resourceType, actual.ResourceType, "Link %d ResourceType mismatch", i)
				assert.Equal(t, expected.position, actual.StartPos, "Link %d Position mismatch", i)
			}
		})
	}
}

// TestJavaScriptStringExtractor_EmitsInlineURLs proves the fallback now SURFACES
// URLs found in JS string literals (previously detected but dropped) — both
// absolute endpoints and, importantly, relative routes like /api/users that
// JSTangle may miss when disabled or unsuccessful.
func TestJavaScriptStringExtractor_EmitsInlineURLs(t *testing.T) {
	baseURL, _ := url.Parse("https://example.com")

	// Relative routes are the coverage gap this fills. (Absolute scheme URLs in JS
	// strings are surfaced by the inlineScanner.Extract pass, tested elsewhere.)
	cases := []struct {
		name    string
		jsCode  string
		wantURL string
	}{
		{
			name:    "relative route in string",
			jsCode:  `fetch("/api/users/list");`,
			wantURL: "https://example.com/api/users/list",
		},
		{
			name:    "relative admin path in string",
			jsCode:  `const p = "/admin/settings";`,
			wantURL: "https://example.com/admin/settings",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := NewURLResolver()
			inlineScanner := NewInlineURLScanner(resolver)
			htmlExtractor := NewHTMLAttributeExtractor(resolver)
			extractor := NewJavaScriptStringExtractor(inlineScanner, htmlExtractor)

			var links []*DiscoveredLink
			err := extractor.Extract(context.Background(), baseURL, &HTTPResponse{
				URL: baseURL, Body: []byte(tc.jsCode), BodyStart: 0,
			}, func(l *DiscoveredLink) { links = append(links, l) })
			require.NoError(t, err)

			var got []string
			for _, l := range links {
				got = append(got, l.URL.String())
			}
			assert.Contains(t, got, tc.wantURL, "inline URL must be surfaced as a discovered link")
		})
	}
}

func TestJavaScriptStringExtractor_EdgeCases(t *testing.T) {
	extractor := NewJavaScriptStringExtractor(nil, nil)

	t.Run("empty code", func(t *testing.T) {
		result := extractor.ExtractStrings("", 0)
		assert.Empty(t, result)
	})

	t.Run("only comments", func(t *testing.T) {
		result := extractor.ExtractStrings("// comment\n/* block */", 0)
		assert.Empty(t, result)
	})

	t.Run("only whitespace", func(t *testing.T) {
		result := extractor.ExtractStrings("   \n\t\r\n  ", 0)
		assert.Empty(t, result)
	})

	t.Run("unclosed double quote", func(t *testing.T) {
		result := extractor.ExtractStrings(`var x = "unclosed`, 0)
		assert.Empty(t, result)
	})

	t.Run("unclosed single quote", func(t *testing.T) {
		result := extractor.ExtractStrings(`var x = 'unclosed`, 0)
		assert.Empty(t, result)
	})

	t.Run("unclosed block comment", func(t *testing.T) {
		result := extractor.ExtractStrings(`/* unclosed comment "string"`, 0)
		assert.Empty(t, result)
	})

	t.Run("string at very end", func(t *testing.T) {
		result := extractor.ExtractStrings(`"test"`, 0)
		assert.Len(t, result, 1)
		assert.Equal(t, "test", result[0].Value)
	})

	t.Run("escape at end of string", func(t *testing.T) {
		// This is malformed JS but we should handle it gracefully
		result := extractor.ExtractStrings(`"test\`, 0)
		assert.Empty(t, result) // String not properly closed
	})
}

func TestJavaScriptStringExtractor_ParserCompatibility(t *testing.T) {
	extractor := NewJavaScriptStringExtractor(nil, nil)

	t.Run("mode detection", func(t *testing.T) {
		// Test that we correctly identify string/comment delimiters

		tests := []struct {
			code     string
			expected int // Number of strings
		}{
			{`"double"`, 1},
			{`'single'`, 1},
			{`"d1" 's1' "d2"`, 3},
			{`// comment`, 0},
			{`/* comment */`, 0},
		}

		for _, tt := range tests {
			result := extractor.ExtractStrings(tt.code, 0)
			assert.Len(t, result, tt.expected, "Code: %s", tt.code)
		}
	})

	t.Run("escape handling", func(t *testing.T) {
		// Parser skips backslash + next char
		result := extractor.ExtractStrings(`"test\"quote"`, 0)
		assert.Len(t, result, 1)
		assert.Equal(t, `test\"quote`, result[0].Value)
	})

	t.Run("position tracking", func(t *testing.T) {
		// Position should point to first char after opening quote
		result := extractor.ExtractStrings(`var x = "test";`, 0)
		assert.Len(t, result, 1)
		assert.Equal(t, 9, result[0].Position) // Position of 't' in "test"
	})

	t.Run("block comment end", func(t *testing.T) {
		// Block comment ends with */ and position advances by 2
		result := extractor.ExtractStrings(`/* comment */ "after"`, 0)
		assert.Len(t, result, 1)
		assert.Equal(t, "after", result[0].Value)
	})
}

func TestJavaScriptStringExtractor_HTMLInJavaScript(t *testing.T) {
	// Test case to verify HTML-in-JS parsing feature
	resolver := NewURLResolver()

	inlineScanner := NewInlineURLScanner(resolver)
	htmlExtractor := NewHTMLAttributeExtractor(resolver)
	extractor := NewJavaScriptStringExtractor(inlineScanner, htmlExtractor)

	baseURL, _ := url.Parse("https://example.com")

	tests := []struct {
		name          string
		jsCode        string
		expectedLinks []expectedLink
	}{
		{
			name:   "JavaScript string containing HTML with anchor link",
			jsCode: `var html = "<a href='/test'>Link</a>";`,
			expectedLinks: []expectedLink{
				{
					url:          "https://example.com/test",
					rawURL:       "/test",
					sourceType:   SourceHTMLAttribute,
					resourceType: ResourceHTML,
					element:      "a",
					attribute:    "href",
				},
			},
		},
		{
			name:   "JavaScript string with multiple HTML links",
			jsCode: `var content = "<div><a href='/page1'>Page 1</a><a href='/page2'>Page 2</a></div>";`,
			expectedLinks: []expectedLink{
				{
					url:          "https://example.com/page1",
					rawURL:       "/page1",
					sourceType:   SourceHTMLAttribute,
					resourceType: ResourceHTML,
					element:      "a",
					attribute:    "href",
				},
				{
					url:          "https://example.com/page2",
					rawURL:       "/page2",
					sourceType:   SourceHTMLAttribute,
					resourceType: ResourceHTML,
					element:      "a",
					attribute:    "href",
				},
			},
		},
		{
			name:   "JavaScript string with image tag",
			jsCode: `var img = "<img src='/logo.png' />";`,
			expectedLinks: []expectedLink{
				{
					url:          "https://example.com/logo.png",
					rawURL:       "/logo.png",
					sourceType:   SourceHTMLAttribute,
					resourceType: ResourcePNG,
					element:      "img",
					attribute:    "src",
				},
			},
		},
		{
			name:   "JavaScript string with script tag",
			jsCode: `var script = "<script src='/app.js'></script>";`,
			expectedLinks: []expectedLink{
				{
					url:          "https://example.com/app.js",
					rawURL:       "/app.js",
					sourceType:   SourceHTMLAttribute,
					resourceType: ResourceScript,
					element:      "script",
					attribute:    "src",
				},
			},
		},
		{
			name:          "JavaScript string without HTML",
			jsCode:        `var text = "This is just plain text";`,
			expectedLinks: []expectedLink{},
		},
		{
			name:          "Short HTML string (skipped by length check)",
			jsCode:        `var s = "<a>x</a>";`,
			expectedLinks: []expectedLink{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := &HTTPResponse{
				URL:       baseURL,
				Body:      []byte(tt.jsCode),
				BodyStart: 0,
			}

			ctx := context.Background()
			var discoveredLinks []*DiscoveredLink
			err := extractor.Extract(ctx, baseURL, response, func(link *DiscoveredLink) {
				discoveredLinks = append(discoveredLinks, link)
			})

			require.NoError(t, err)
			require.Len(t, discoveredLinks, len(tt.expectedLinks), "Expected %d links, got %d", len(tt.expectedLinks), len(discoveredLinks))

			for i, expected := range tt.expectedLinks {
				actual := discoveredLinks[i]
				assert.Equal(t, expected.url, actual.URL.String(), "Link %d URL mismatch", i)
				assert.Equal(t, expected.rawURL, actual.RawURL, "Link %d RawURL mismatch", i)
				assert.Equal(t, expected.sourceType, actual.SourceType, "Link %d SourceType mismatch", i)
				assert.Equal(t, expected.resourceType, actual.ResourceType, "Link %d ResourceType mismatch", i)
				assert.Equal(t, expected.element, actual.Element, "Link %d Element mismatch", i)
				assert.Equal(t, expected.attribute, actual.Attribute, "Link %d Attribute mismatch", i)
			}
		})
	}
}

// Expected link structure for validation
type expectedLink struct {
	url          string
	rawURL       string
	sourceType   LinkSourceType
	resourceType ResourceType
	position     int
	element      string
	attribute    string
}
