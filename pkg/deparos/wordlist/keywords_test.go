package wordlist

import (
	"testing"
)

func TestKeywordFilter_HTML(t *testing.T) {
	filter := NewKeywordFilter()

	// Should be keywords (filtered)
	htmlKeywords := []string{
		"div", "span", "html", "body", "head",
		"script", "style", "form", "input", "button",
		"table", "tr", "td", "th",
		"class", "id", "href", "src",
		"DIV", "SPAN", // Case insensitive
	}

	for _, kw := range htmlKeywords {
		if !filter.IsKeyword(kw, ContentTypeHTML) {
			t.Errorf("%q should be an HTML keyword", kw)
		}
	}

	// Should NOT be keywords
	nonKeywords := []string{
		"admin", "user", "config", "dashboard",
		"api", "endpoint", "settings",
	}

	for _, word := range nonKeywords {
		if filter.IsKeyword(word, ContentTypeHTML) {
			t.Errorf("%q should NOT be an HTML keyword", word)
		}
	}
}

func TestKeywordFilter_CSS(t *testing.T) {
	filter := NewKeywordFilter()

	// Should be keywords
	cssKeywords := []string{
		"display", "position", "width", "height",
		"margin", "padding", "border", "color",
		"flex", "grid", "block", "none",
		"px", "em", "rem", "vh", "vw",
		"hover", "active", "focus",
	}

	for _, kw := range cssKeywords {
		if !filter.IsKeyword(kw, ContentTypeCSS) {
			t.Errorf("%q should be a CSS keyword", kw)
		}
	}

	// Should NOT be keywords
	nonKeywords := []string{
		"container", "sidebar", "navbar",
		"custom-class", "main-content",
	}

	for _, word := range nonKeywords {
		if filter.IsKeyword(word, ContentTypeCSS) {
			t.Errorf("%q should NOT be a CSS keyword", word)
		}
	}
}

func TestKeywordFilter_JavaScript(t *testing.T) {
	filter := NewKeywordFilter()

	// Should be keywords
	jsKeywords := []string{
		"function", "var", "let", "const", "return",
		"if", "else", "for", "while", "switch",
		"class", "extends", "constructor", "this",
		"async", "await", "promise",
		"document", "window", "console", "log",
		"push", "pop", "map", "filter", "reduce",
	}

	for _, kw := range jsKeywords {
		if !filter.IsKeyword(kw, ContentTypeJavaScript) {
			t.Errorf("%q should be a JavaScript keyword", kw)
		}
	}

	// Should NOT be keywords
	nonKeywords := []string{
		"apiEndpoint", "userConfig", "customHandler",
		"myFunction", "getData", "setUser",
	}

	for _, word := range nonKeywords {
		if filter.IsKeyword(word, ContentTypeJavaScript) {
			t.Errorf("%q should NOT be a JavaScript keyword", word)
		}
	}
}

func TestKeywordFilter_JSON(t *testing.T) {
	filter := NewKeywordFilter()

	// JSON has minimal keywords
	jsonKeywords := []string{"true", "false", "null"}

	for _, kw := range jsonKeywords {
		if !filter.IsKeyword(kw, ContentTypeJSON) {
			t.Errorf("%q should be a JSON keyword", kw)
		}
	}

	// Most words should NOT be keywords in JSON
	nonKeywords := []string{
		"user", "name", "email", "config",
		"endpoint", "data", "response",
	}

	for _, word := range nonKeywords {
		if filter.IsKeyword(word, ContentTypeJSON) {
			t.Errorf("%q should NOT be a JSON keyword", word)
		}
	}
}

func TestKeywordFilter_XML(t *testing.T) {
	filter := NewKeywordFilter()

	// Should be keywords
	xmlKeywords := []string{
		"xml", "xmlns", "xsi", "xsd",
		"schema", "element", "attribute",
		"cdata", "entity",
	}

	for _, kw := range xmlKeywords {
		if !filter.IsKeyword(kw, ContentTypeXML) {
			t.Errorf("%q should be an XML keyword", kw)
		}
	}

	// Should NOT be keywords
	nonKeywords := []string{
		"user", "config", "settings",
		"custom-element", "my-data",
	}

	for _, word := range nonKeywords {
		if filter.IsKeyword(word, ContentTypeXML) {
			t.Errorf("%q should NOT be an XML keyword", word)
		}
	}
}

func TestKeywordFilter_UnknownContentType(t *testing.T) {
	filter := NewKeywordFilter()

	// For unknown content types, nothing should be filtered
	words := []string{"div", "function", "display", "true"}

	for _, word := range words {
		if filter.IsKeyword(word, ContentTypeUnknown) {
			t.Errorf("%q should NOT be filtered for unknown content type", word)
		}
		if filter.IsKeyword(word, ContentTypeText) {
			t.Errorf("%q should NOT be filtered for plain text", word)
		}
	}
}

func TestKeywordFilter_CaseInsensitive(t *testing.T) {
	filter := NewKeywordFilter()

	variations := []string{
		"div", "DIV", "Div", "dIv",
		"function", "FUNCTION", "Function",
		"display", "DISPLAY", "Display",
	}

	contentTypes := []ContentType{ContentTypeHTML, ContentTypeJavaScript, ContentTypeCSS}

	for _, word := range variations {
		for _, ct := range contentTypes {
			// At least one content type should recognize each base word
			found := false
			baseWord := word
			if filter.IsKeyword(baseWord, ct) {
				found = true
				break
			}
			if found {
				break
			}
		}
	}

	// More specific test
	if !filter.IsKeyword("DIV", ContentTypeHTML) {
		t.Error("DIV should be filtered for HTML (case insensitive)")
	}
	if !filter.IsKeyword("FUNCTION", ContentTypeJavaScript) {
		t.Error("FUNCTION should be filtered for JavaScript (case insensitive)")
	}
	if !filter.IsKeyword("DISPLAY", ContentTypeCSS) {
		t.Error("DISPLAY should be filtered for CSS (case insensitive)")
	}
}

func BenchmarkKeywordFilter_IsKeyword(b *testing.B) {
	filter := NewKeywordFilter()
	words := []string{
		"div", "admin", "function", "customFunction",
		"display", "container", "true", "apiEndpoint",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, word := range words {
			filter.IsKeyword(word, ContentTypeHTML)
			filter.IsKeyword(word, ContentTypeJavaScript)
			filter.IsKeyword(word, ContentTypeCSS)
		}
	}
}
