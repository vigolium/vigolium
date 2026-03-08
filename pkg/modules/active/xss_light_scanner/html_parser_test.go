package xss_light_scanner

import (
	"testing"
)

func TestNewHtmlParser(t *testing.T) {
	data := []byte("<div>test</div>")
	parser := NewHtmlParser(data)

	if parser == nil {
		t.Fatal("NewHtmlParser returned nil")
	}
	if parser.pos != 0 {
		t.Errorf("pos = %d, want 0", parser.pos)
	}
	if parser.end != len(data) {
		t.Errorf("end = %d, want %d", parser.end, len(data))
	}
}

func TestParseHTML_SimpleText(t *testing.T) {
	html := []byte("Hello World")
	elements := ParseHTML(html)

	if len(elements) != 1 {
		t.Fatalf("ParseHTML returned %d elements, want 1", len(elements))
	}

	elem := elements[0]
	if elem.Type != ElementText {
		t.Errorf("Type = %v, want ElementText", elem.Type)
	}
	if string(elem.Content) != "Hello World" {
		t.Errorf("Content = %s, want 'Hello World'", elem.Content)
	}
}

func TestParseHTML_SimpleTag(t *testing.T) {
	html := []byte("<div></div>")
	elements := ParseHTML(html)

	if len(elements) != 2 {
		t.Fatalf("ParseHTML returned %d elements, want 2", len(elements))
	}

	openTag := elements[0]
	if openTag.Type != ElementOpenTag {
		t.Errorf("First element Type = %v, want ElementOpenTag", openTag.Type)
	}
	if openTag.TagName != "div" {
		t.Errorf("TagName = %s, want 'div'", openTag.TagName)
	}

	closeTag := elements[1]
	if closeTag.Type != ElementCloseTag {
		t.Errorf("Second element Type = %v, want ElementCloseTag", closeTag.Type)
	}
}

func TestParseHTML_SelfClosingTag(t *testing.T) {
	tests := []struct {
		name string
		html string
	}{
		{"explicit self-closing", "<br/>"},
		{"void tag", "<br>"},
		{"img tag", "<img src='test.png'>"},
		{"input tag", "<input type='text'>"},
		{"hr tag", "<hr>"},
		{"meta tag", "<meta charset='utf-8'>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elements := ParseHTML([]byte(tt.html))

			if len(elements) < 1 {
				t.Fatalf("ParseHTML returned %d elements, want >= 1", len(elements))
			}

			elem := elements[0]
			if elem.Type != ElementSelfClosing {
				t.Errorf("Type = %v, want ElementSelfClosing", elem.Type)
			}
		})
	}
}

func TestParseHTML_TagWithAttributes(t *testing.T) {
	html := []byte(`<div id="test" class='container' data-value=unquoted>`)
	elements := ParseHTML(html)

	if len(elements) < 1 {
		t.Fatalf("ParseHTML returned %d elements, want >= 1", len(elements))
	}

	elem := elements[0]
	if len(elem.Attributes) != 3 {
		t.Fatalf("Attributes count = %d, want 3", len(elem.Attributes))
	}

	// Check double-quoted attribute
	attr0 := elem.Attributes[0]
	if attr0.Name != "id" {
		t.Errorf("Attr[0].Name = %s, want 'id'", attr0.Name)
	}
	if attr0.Value != "test" {
		t.Errorf("Attr[0].Value = %s, want 'test'", attr0.Value)
	}
	if attr0.QuoteType != QuoteDouble {
		t.Errorf("Attr[0].QuoteType = %v, want QuoteDouble", attr0.QuoteType)
	}

	// Check single-quoted attribute
	attr1 := elem.Attributes[1]
	if attr1.Name != "class" {
		t.Errorf("Attr[1].Name = %s, want 'class'", attr1.Name)
	}
	if attr1.Value != "container" {
		t.Errorf("Attr[1].Value = %s, want 'container'", attr1.Value)
	}
	if attr1.QuoteType != QuoteSingle {
		t.Errorf("Attr[1].QuoteType = %v, want QuoteSingle", attr1.QuoteType)
	}

	// Check unquoted attribute
	attr2 := elem.Attributes[2]
	if attr2.Name != "data-value" {
		t.Errorf("Attr[2].Name = %s, want 'data-value'", attr2.Name)
	}
	if attr2.Value != "unquoted" {
		t.Errorf("Attr[2].Value = %s, want 'unquoted'", attr2.Value)
	}
	if attr2.QuoteType != QuoteNone {
		t.Errorf("Attr[2].QuoteType = %v, want QuoteNone", attr2.QuoteType)
	}
}

func TestParseHTML_BacktickQuotedAttribute(t *testing.T) {
	html := []byte("<div data=`value`>")
	elements := ParseHTML(html)

	if len(elements) < 1 {
		t.Fatalf("ParseHTML returned %d elements, want >= 1", len(elements))
	}

	elem := elements[0]
	if len(elem.Attributes) != 1 {
		t.Fatalf("Attributes count = %d, want 1", len(elem.Attributes))
	}

	attr := elem.Attributes[0]
	if attr.QuoteType != QuoteBacktick {
		t.Errorf("QuoteType = %v, want QuoteBacktick", attr.QuoteType)
	}
	if attr.Value != "value" {
		t.Errorf("Value = %s, want 'value'", attr.Value)
	}
}

func TestParseHTML_Comment(t *testing.T) {
	html := []byte("<!-- This is a comment -->")
	elements := ParseHTML(html)

	if len(elements) != 1 {
		t.Fatalf("ParseHTML returned %d elements, want 1", len(elements))
	}

	elem := elements[0]
	if elem.Type != ElementComment {
		t.Errorf("Type = %v, want ElementComment", elem.Type)
	}
	if elem.StartOffset != 0 {
		t.Errorf("StartOffset = %d, want 0", elem.StartOffset)
	}
}

func TestParseHTML_CommentUnclosed(t *testing.T) {
	html := []byte("<!-- This is unclosed")
	elements := ParseHTML(html)

	if len(elements) != 1 {
		t.Fatalf("ParseHTML returned %d elements, want 1", len(elements))
	}

	elem := elements[0]
	if elem.Type != ElementComment {
		t.Errorf("Type = %v, want ElementComment", elem.Type)
	}
	// Should extend to end of document
	if elem.EndOffset != len(html) {
		t.Errorf("EndOffset = %d, want %d", elem.EndOffset, len(html))
	}
}

func TestParseHTML_Doctype(t *testing.T) {
	html := []byte("<!DOCTYPE html>")
	elements := ParseHTML(html)

	if len(elements) != 1 {
		t.Fatalf("ParseHTML returned %d elements, want 1", len(elements))
	}

	elem := elements[0]
	if elem.Type != ElementDirective {
		t.Errorf("Type = %v, want ElementDirective", elem.Type)
	}
}

func TestParseHTML_CDATA(t *testing.T) {
	html := []byte("<![CDATA[some data]]>")
	elements := ParseHTML(html)

	if len(elements) != 1 {
		t.Fatalf("ParseHTML returned %d elements, want 1", len(elements))
	}

	elem := elements[0]
	if elem.Type != ElementCDATA {
		t.Errorf("Type = %v, want ElementCDATA", elem.Type)
	}
}

func TestParseHTML_ScriptTag(t *testing.T) {
	html := []byte("<script>var x = 1;</script>")
	elements := ParseHTML(html)

	// Should have: open script, text content, close script
	if len(elements) != 3 {
		t.Fatalf("ParseHTML returned %d elements, want 3", len(elements))
	}

	scriptOpen := elements[0]
	if scriptOpen.TagName != "script" {
		t.Errorf("First element TagName = %s, want 'script'", scriptOpen.TagName)
	}

	scriptContent := elements[1]
	if scriptContent.Type != ElementText {
		t.Errorf("Second element Type = %v, want ElementText", scriptContent.Type)
	}
	if !scriptContent.InScript {
		t.Error("Script content should have InScript = true")
	}
	if string(scriptContent.Content) != "var x = 1;" {
		t.Errorf("Script content = %s, want 'var x = 1;'", scriptContent.Content)
	}
}

func TestParseHTML_ScriptWithHTMLInside(t *testing.T) {
	// HTML inside script should not be parsed as tags
	html := []byte("<script>var x = '<div>';</script>")
	elements := ParseHTML(html)

	// Should have: open script, text content, close script
	if len(elements) != 3 {
		t.Fatalf("ParseHTML returned %d elements, want 3", len(elements))
	}

	scriptContent := elements[1]
	if scriptContent.Type != ElementText {
		t.Errorf("Script content Type = %v, want ElementText", scriptContent.Type)
	}
	if string(scriptContent.Content) != "var x = '<div>';" {
		t.Errorf("Script content = %s, want \"var x = '<div>';\"", scriptContent.Content)
	}
}

func TestParseHTML_NestedTags(t *testing.T) {
	html := []byte("<div><span>text</span></div>")
	elements := ParseHTML(html)

	// div open, span open, text, span close, div close
	if len(elements) != 5 {
		t.Fatalf("ParseHTML returned %d elements, want 5", len(elements))
	}

	// Check parent tracking
	spanOpen := elements[1]
	if spanOpen.ParentTag != "div" {
		t.Errorf("span's ParentTag = %s, want 'div'", spanOpen.ParentTag)
	}

	textElem := elements[2]
	if textElem.ParentTag != "span" {
		t.Errorf("text's ParentTag = %s, want 'span'", textElem.ParentTag)
	}
}

func TestParseHTML_AttributeOffsets(t *testing.T) {
	html := []byte(`<div id="test">`)
	elements := ParseHTML(html)

	if len(elements) < 1 || len(elements[0].Attributes) < 1 {
		t.Fatal("Missing expected elements/attributes")
	}

	attr := elements[0].Attributes[0]

	// Verify NameStart and NameEnd point to "id"
	if string(html[attr.NameStart:attr.NameEnd]) != "id" {
		t.Errorf("NameStart:NameEnd slice = %s, want 'id'", html[attr.NameStart:attr.NameEnd])
	}

	// Verify ValueStart and ValueEnd point to "test"
	if string(html[attr.ValueStart:attr.ValueEnd]) != "test" {
		t.Errorf("ValueStart:ValueEnd slice = %s, want 'test'", html[attr.ValueStart:attr.ValueEnd])
	}
}

func TestParseHTML_TagOffsets(t *testing.T) {
	html := []byte("<div>content</div>")
	elements := ParseHTML(html)

	if len(elements) < 3 {
		t.Fatalf("ParseHTML returned %d elements, want 3", len(elements))
	}

	openTag := elements[0]
	if openTag.StartOffset != 0 {
		t.Errorf("Open tag StartOffset = %d, want 0", openTag.StartOffset)
	}
	if openTag.EndOffset != 5 {
		t.Errorf("Open tag EndOffset = %d, want 5", openTag.EndOffset)
	}

	content := elements[1]
	if content.StartOffset != 5 {
		t.Errorf("Content StartOffset = %d, want 5", content.StartOffset)
	}
	if content.EndOffset != 12 {
		t.Errorf("Content EndOffset = %d, want 12", content.EndOffset)
	}

	closeTag := elements[2]
	if closeTag.StartOffset != 12 {
		t.Errorf("Close tag StartOffset = %d, want 12", closeTag.StartOffset)
	}
	if closeTag.EndOffset != 18 {
		t.Errorf("Close tag EndOffset = %d, want 18", closeTag.EndOffset)
	}
}

func TestParseHTML_EmptyInput(t *testing.T) {
	elements := ParseHTML([]byte(""))
	if len(elements) != 0 {
		t.Errorf("ParseHTML([]) returned %d elements, want 0", len(elements))
	}
}

func TestParseHTML_WhitespaceOnly(t *testing.T) {
	elements := ParseHTML([]byte("   \n\t  "))
	if len(elements) != 0 {
		t.Errorf("ParseHTML(whitespace) returned %d elements, want 0", len(elements))
	}
}

func TestParseHTML_MalformedTag(t *testing.T) {
	tests := []struct {
		name string
		html string
	}{
		{"unclosed tag", "<div"},
		{"no tag name", "<>"},
		{"only angle bracket", "<"},
		{"missing closing bracket", "<div id='test'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			elements := ParseHTML([]byte(tt.html))
			_ = elements // Just verify no panic
		})
	}
}

func TestParseHTML_TitleTag(t *testing.T) {
	html := []byte("<title>Page <Title></title>")
	elements := ParseHTML(html)

	// title open, text content, title close
	if len(elements) != 3 {
		t.Fatalf("ParseHTML returned %d elements, want 3", len(elements))
	}

	content := elements[1]
	// Content should include the literal <Title> text (not parsed as tag)
	if string(content.Content) != "Page <Title>" {
		t.Errorf("Title content = %s, want 'Page <Title>'", content.Content)
	}
}

func TestParseHTML_NoscriptTag(t *testing.T) {
	html := []byte("<noscript><img src='x'></noscript>")
	elements := ParseHTML(html)

	// noscript open, text (raw), noscript close
	if len(elements) != 3 {
		t.Fatalf("ParseHTML returned %d elements, want 3", len(elements))
	}

	content := elements[1]
	if content.ParentTag != "noscript" {
		t.Errorf("Content ParentTag = %s, want 'noscript'", content.ParentTag)
	}
}

func TestParseHTML_XmpTag(t *testing.T) {
	html := []byte("<xmp><b>bold</b></xmp>")
	elements := ParseHTML(html)

	// xmp open, text (raw), xmp close
	if len(elements) != 3 {
		t.Fatalf("ParseHTML returned %d elements, want 3", len(elements))
	}

	content := elements[1]
	// Content should include the literal <b>bold</b> text
	if string(content.Content) != "<b>bold</b>" {
		t.Errorf("XMP content = %s, want '<b>bold</b>'", content.Content)
	}
}

func TestParseHTML_CaseInsensitiveTags(t *testing.T) {
	html := []byte("<DIV></div>")
	elements := ParseHTML(html)

	if len(elements) != 2 {
		t.Fatalf("ParseHTML returned %d elements, want 2", len(elements))
	}

	// Tag names should be lowercased
	if elements[0].TagName != "div" {
		t.Errorf("TagName = %s, want 'div'", elements[0].TagName)
	}
}

func TestParseHTML_EventHandler(t *testing.T) {
	html := []byte(`<div onclick="alert(1)">`)
	elements := ParseHTML(html)

	if len(elements) < 1 || len(elements[0].Attributes) < 1 {
		t.Fatal("Missing expected elements/attributes")
	}

	attr := elements[0].Attributes[0]
	if attr.Name != "onclick" {
		t.Errorf("Attr name = %s, want 'onclick'", attr.Name)
	}
	if attr.Value != "alert(1)" {
		t.Errorf("Attr value = %s, want 'alert(1)'", attr.Value)
	}
}

func TestFindElementAtOffset(t *testing.T) {
	html := []byte("<div>content</div>")
	elements := ParseHTML(html)

	tests := []struct {
		offset       int
		expectedType HtmlElementType
		expectNil    bool
	}{
		{0, ElementOpenTag, false},   // In <div>
		{3, ElementOpenTag, false},   // In <div>
		{5, ElementText, false},      // In "content"
		{10, ElementText, false},     // In "content"
		{12, ElementCloseTag, false}, // In </div>
		{-1, 0, true},                // Before start
		{100, 0, true},               // After end
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			elem := FindElementAtOffset(elements, tt.offset)

			if tt.expectNil {
				if elem != nil {
					t.Errorf("FindElementAtOffset(%d) = %v, want nil", tt.offset, elem)
				}
			} else {
				if elem == nil {
					t.Fatalf("FindElementAtOffset(%d) = nil, want element", tt.offset)
				}
				if elem.Type != tt.expectedType {
					t.Errorf("FindElementAtOffset(%d).Type = %v, want %v", tt.offset, elem.Type, tt.expectedType)
				}
			}
		})
	}
}

func TestFindElementsInRange(t *testing.T) {
	html := []byte("<div><span>text</span></div>")
	elements := ParseHTML(html)

	tests := []struct {
		start    int
		end      int
		expected int
	}{
		{0, 5, 1},     // Just <div>
		{0, 28, 5},    // All elements
		{5, 22, 3},    // <span>, text, </span> (close tag ends at 22, so excluded by end < 22)
		{100, 200, 0}, // Out of range
	}

	for _, tt := range tests {
		result := FindElementsInRange(elements, tt.start, tt.end)
		if len(result) != tt.expected {
			t.Errorf("FindElementsInRange(%d, %d) returned %d elements, want %d",
				tt.start, tt.end, len(result), tt.expected)
		}
	}
}

func TestParseHTML_ComplexDocument(t *testing.T) {
	html := []byte(`<!DOCTYPE html>
<html>
<head>
	<title>Test Page</title>
	<meta charset="utf-8">
	<script>
		var x = '<div>';
	</script>
</head>
<body>
	<div id="main" class="container">
		<!-- Comment -->
		<span onclick="test()">Click me</span>
		<input type="text" value="default">
	</div>
</body>
</html>`)

	elements := ParseHTML(html)

	// Should not panic and should return elements
	if len(elements) == 0 {
		t.Error("ParseHTML returned no elements for complex document")
	}

	// Find specific elements
	var foundComment, foundScript, foundInput bool
	for _, elem := range elements {
		if elem.Type == ElementComment {
			foundComment = true
		}
		if elem.TagName == "script" && elem.Type == ElementOpenTag {
			foundScript = true
		}
		if elem.TagName == "input" {
			foundInput = true
			if elem.Type != ElementSelfClosing {
				t.Error("input tag should be self-closing")
			}
		}
	}

	if !foundComment {
		t.Error("Comment not found in parsed elements")
	}
	if !foundScript {
		t.Error("Script tag not found in parsed elements")
	}
	if !foundInput {
		t.Error("Input tag not found in parsed elements")
	}
}

func TestParseHTML_BooleanAttribute(t *testing.T) {
	html := []byte(`<input disabled readonly>`)
	elements := ParseHTML(html)

	if len(elements) < 1 {
		t.Fatal("No elements parsed")
	}

	attrs := elements[0].Attributes
	if len(attrs) != 2 {
		t.Fatalf("Expected 2 attributes, got %d", len(attrs))
	}

	// Boolean attributes should have empty value
	for _, attr := range attrs {
		if attr.Value != "" {
			t.Errorf("Boolean attribute %s has value %s, expected empty", attr.Name, attr.Value)
		}
	}
}

func TestParseHTML_AttributeWithoutValue(t *testing.T) {
	html := []byte(`<div data-flag>`)
	elements := ParseHTML(html)

	if len(elements) < 1 || len(elements[0].Attributes) < 1 {
		t.Fatal("Missing expected elements/attributes")
	}

	attr := elements[0].Attributes[0]
	if attr.Name != "data-flag" {
		t.Errorf("Attr name = %s, want 'data-flag'", attr.Name)
	}
	if attr.Value != "" {
		t.Errorf("Attr value = %s, want empty", attr.Value)
	}
}

func TestVoidTags(t *testing.T) {
	expectedVoid := []string{"img", "br", "hr", "meta", "input", "link", "area", "base", "col", "embed", "param", "source", "track", "wbr"}

	for _, tag := range expectedVoid {
		if !voidTags[tag] {
			t.Errorf("voidTags[%s] = false, want true", tag)
		}
	}
}

func TestRawTextTags(t *testing.T) {
	expectedRaw := []string{"script", "style", "xmp", "textarea", "title", "noscript", "plaintext"}

	for _, tag := range expectedRaw {
		if !rawTextTags[tag] {
			t.Errorf("rawTextTags[%s] = false, want true", tag)
		}
	}
}

func TestParseHTML_MultipleEventHandlers(t *testing.T) {
	html := []byte(`<button onclick="click()" onmouseover="hover()" onfocus="focus()">`)
	elements := ParseHTML(html)

	if len(elements) < 1 {
		t.Fatal("No elements parsed")
	}

	elem := elements[0]
	if len(elem.Attributes) != 3 {
		t.Fatalf("Expected 3 attributes, got %d", len(elem.Attributes))
	}

	expectedAttrs := []struct {
		name  string
		value string
	}{
		{"onclick", "click()"},
		{"onmouseover", "hover()"},
		{"onfocus", "focus()"},
	}

	for i, exp := range expectedAttrs {
		attr := elem.Attributes[i]
		if attr.Name != exp.name || attr.Value != exp.value {
			t.Errorf("Attr[%d] = {%s, %s}, want {%s, %s}", i, attr.Name, attr.Value, exp.name, exp.value)
		}
	}
}

func TestParseHTML_SpecialCharactersInAttribute(t *testing.T) {
	html := []byte(`<div data-json='{"key": "value"}'>`)
	elements := ParseHTML(html)

	if len(elements) < 1 || len(elements[0].Attributes) < 1 {
		t.Fatal("Missing expected elements/attributes")
	}

	attr := elements[0].Attributes[0]
	expected := `{"key": "value"}`
	if attr.Value != expected {
		t.Errorf("Attr value = %s, want %s", attr.Value, expected)
	}
}

func TestParseHTML_StyleTag(t *testing.T) {
	html := []byte("<style>body { color: red; }</style>")
	elements := ParseHTML(html)

	// style open, text content, style close
	if len(elements) != 3 {
		t.Fatalf("ParseHTML returned %d elements, want 3", len(elements))
	}

	content := elements[1]
	if string(content.Content) != "body { color: red; }" {
		t.Errorf("Style content = %s, want 'body { color: red; }'", content.Content)
	}
}
