package htmlutils

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// parseBody parses an HTML fragment and returns the <body> element.
func parseBody(t *testing.T, src string) *html.Node {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	bodies := GetElementsByTagName(doc, "body")
	if len(bodies) == 0 {
		t.Fatalf("no body element parsed from %q", src)
	}
	return bodies[0]
}

// parseFirst parses an HTML fragment and returns the first child of <body>.
func parseFirst(t *testing.T, src string) *html.Node {
	t.Helper()
	return parseBody(t, src).FirstChild
}

func TestQuerySelectorAllLocal(t *testing.T) {
	src := `<body>
		<p></p>
		<h1 id="heading"></h1>
		<p class="a"></p>
		<span class="a"></span>
		<div class="a b"></div>
	</body>`
	doc := parseBody(t, src)

	tests := map[string]int{
		"p":        2,
		"h1":       1,
		".a":       3,
		".a.b":     1,
		"#heading": 1,
		"#nope":    0,
		"p, span":  3,
	}
	for sel, want := range tests {
		t.Run(sel, func(t *testing.T) {
			if got := len(QuerySelectorAll(doc, sel)); got != want {
				t.Errorf("QuerySelectorAll(%q) = %d, want %d", sel, got, want)
			}
		})
	}

	// Invalid selector returns nil.
	if got := QuerySelectorAll(doc, ">>invalid<<"); got != nil {
		t.Errorf("QuerySelectorAll(invalid) = %v, want nil", got)
	}
}

func TestQuerySelectorLocal(t *testing.T) {
	doc := parseBody(t, `<body><h1 id="x"></h1><p class="c"></p></body>`)

	if n := QuerySelector(doc, "#x"); n == nil || TagName(n) != "h1" {
		t.Errorf("QuerySelector(#x) failed: %v", n)
	}
	if n := QuerySelector(doc, ".c"); n == nil || TagName(n) != "p" {
		t.Errorf("QuerySelector(.c) failed: %v", n)
	}
	if n := QuerySelector(doc, "article"); n != nil {
		t.Errorf("QuerySelector(article) = %v, want nil", n)
	}
	// Invalid selector returns nil.
	if n := QuerySelector(doc, ">>bad<<"); n != nil {
		t.Errorf("QuerySelector(invalid) = %v, want nil", n)
	}
}

func TestGetElementByIDLocal(t *testing.T) {
	doc := parseBody(t, `<div>
		<h1 id="heading"></h1>
		<p id="  spaced  "></p>
		<span></span>
	</div>`)

	tests := map[string]string{
		"heading": "h1",
		"spaced":  "p", // trimmed match
		"missing": "",
	}
	for id, wantTag := range tests {
		t.Run(id, func(t *testing.T) {
			n := GetElementByID(doc, id)
			got := ""
			if n != nil {
				got = TagName(n)
			}
			if got != wantTag {
				t.Errorf("GetElementByID(%q) = %q, want %q", id, got, wantTag)
			}
		})
	}

	// Empty id always returns nil.
	if n := GetElementByID(doc, ""); n != nil {
		t.Errorf("GetElementByID(empty) = %v, want nil", n)
	}
}

func TestGetElementsByClassNameLocal(t *testing.T) {
	doc := parseBody(t, `<div>
		<p class="a"></p>
		<p class="a"></p>
		<p class="b"></p>
		<p class="a b"></p>
		<p class="a b c"></p>
	</div>`)

	tests := map[string]int{
		"":      0, // no classes -> nil
		"a":     4,
		"b":     3,
		"a b":   2,
		"a b c": 1,
		"x":     0,
	}
	for cn, want := range tests {
		t.Run(cn, func(t *testing.T) {
			if got := len(GetElementsByClassName(doc, cn)); got != want {
				t.Errorf("GetElementsByClassName(%q) = %d, want %d", cn, got, want)
			}
		})
	}
}

func TestGetElementsByTagNameLocal(t *testing.T) {
	doc := parseFirst(t, `<div><p></p><p></p><span></span><img/></div>`)
	// GetElementsByTagName traverses the node's descendants (not the node itself),
	// so the wrapping <div> is not counted.
	tests := map[string]int{
		"p":    2,
		"span": 1,
		"img":  1,
		"*":    4, // 2p + span + img
		"none": 0,
	}
	for tag, want := range tests {
		t.Run(tag, func(t *testing.T) {
			if got := len(GetElementsByTagName(doc, tag)); got != want {
				t.Errorf("GetElementsByTagName(%q) = %d, want %d", tag, got, want)
			}
		})
	}
}

func TestGetElementsByElementNode(t *testing.T) {
	doc := parseFirst(t, `<div><p>text</p><!-- comment --><span></span></div>`)

	// Traversal covers descendants of the div, not the div itself: p and span.
	elements := GetElementsByElementNode(doc, html.ElementNode)
	if len(elements) != 2 {
		t.Errorf("element nodes = %d, want 2", len(elements))
	}
	texts := GetElementsByElementNode(doc, html.TextNode)
	if len(texts) != 1 {
		t.Errorf("text nodes = %d, want 1", len(texts))
	}
	comments := GetElementsByElementNode(doc, html.CommentNode)
	if len(comments) != 1 {
		t.Errorf("comment nodes = %d, want 1", len(comments))
	}
}

func TestCreateElementAndTextNode(t *testing.T) {
	el := CreateElement("section")
	if el.Type != html.ElementNode || el.Data != "section" {
		t.Errorf("CreateElement = %+v", el)
	}
	if got := OuterHTML(el); got != "<section></section>" {
		t.Errorf("OuterHTML(section) = %q", got)
	}

	txt := CreateTextNode("hello & <world>")
	if txt.Type != html.TextNode {
		t.Errorf("CreateTextNode type = %v", txt.Type)
	}
	// Rendered text node escapes special characters.
	if got := OuterHTML(txt); got != "hello &amp; &lt;world&gt;" {
		t.Errorf("OuterHTML(textnode) = %q", got)
	}
}

func TestTagNameLocal(t *testing.T) {
	if got := TagName(nil); got != "" {
		t.Errorf("TagName(nil) = %q, want empty", got)
	}
	if got := TagName(CreateTextNode("x")); got != "" {
		t.Errorf("TagName(text) = %q, want empty", got)
	}
	if got := TagName(CreateElement("p")); got != "p" {
		t.Errorf("TagName(p) = %q, want p", got)
	}
}

func TestGetAttributeLocal(t *testing.T) {
	node := parseFirst(t, `<p id="main" class="  big  "></p>`)
	if got := GetAttribute(node, "id"); got != "main" {
		t.Errorf("GetAttribute(id) = %q", got)
	}
	if got := GetAttribute(node, "missing"); got != "" {
		t.Errorf("GetAttribute(missing) = %q, want empty", got)
	}
	if got := GetAttributeTrimSpace(node, "class"); got != "big" {
		t.Errorf("GetAttributeTrimSpace(class) = %q, want big", got)
	}
}

func TestSetAttributeLocal(t *testing.T) {
	node := CreateElement("p")
	// Add new attribute.
	SetAttribute(node, "id", "x")
	if got := GetAttribute(node, "id"); got != "x" {
		t.Errorf("after add, id = %q", got)
	}
	// Replace existing attribute.
	SetAttribute(node, "id", "y")
	if got := GetAttribute(node, "id"); got != "y" {
		t.Errorf("after replace, id = %q", got)
	}
	if len(node.Attr) != 1 {
		t.Errorf("attr count = %d, want 1", len(node.Attr))
	}
}

func TestRemoveAttributeLocal(t *testing.T) {
	node := parseFirst(t, `<p id="main" class="big"></p>`)
	RemoveAttribute(node, "id")
	if HasAttribute(node, "id") {
		t.Error("id attribute still present after removal")
	}
	if !HasAttribute(node, "class") {
		t.Error("class attribute wrongly removed")
	}
	// Removing a non-existent attribute is a no-op.
	RemoveAttribute(node, "nope")
	if len(node.Attr) != 1 {
		t.Errorf("attr count = %d, want 1", len(node.Attr))
	}
}

func TestHasAttributeLocal(t *testing.T) {
	node := parseFirst(t, `<p data-x=""></p>`)
	if !HasAttribute(node, "data-x") {
		t.Error("HasAttribute(data-x) = false, want true")
	}
	if HasAttribute(node, "data-y") {
		t.Error("HasAttribute(data-y) = true, want false")
	}
}

func TestTextContentLocal(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{"plain text", "just text", "just text"},
		{"empty element", "<p></p>", ""},
		{"single", "<p>Hello</p>", "Hello"},
		{"nested", "<div><p>a<span>b</span>c</p></div>", "abc"},
		{"preserves spaces", "<p>  spaced  </p>", "  spaced  "},
		{"unicode", "<p>héllo 世界</p>", "héllo 世界"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := parseFirst(t, tt.src)
			if got := TextContent(node); got != tt.want {
				t.Errorf("TextContent() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInnerTextLocal(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{"simple", "<div>Hello world</div>", "Hello world"},
		{"collapses whitespace", "<div>  a   b\t c </div>", "a b c"},
		{"br to newline", "<div>line1<br>line2</div>", "line1\nline2"},
		{"hidden attribute skipped", `<div>visible<span hidden>secret</span></div>`, "visible"},
		{"display none skipped", `<div>shown<span style="display: none">hidden</span></div>`, "shown"},
		{"display none uppercase", `<div>shown<span style="DISPLAY:NONE">hidden</span></div>`, "shown"},
		{"visibility hidden skipped", `<div>shown<span style="visibility: hidden">gone</span></div>`, "shown"},
		{"visibility collapse skipped", `<div>shown<span style="visibility: collapse">gone</span></div>`, "shown"},
		{"punctuation spacing", "<div>hello , world .</div>", "hello, world. "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := parseFirst(t, tt.src)
			if got := InnerText(node); got != tt.want {
				t.Errorf("InnerText() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOuterHTMLLocal(t *testing.T) {
	if got := OuterHTML(nil); got != "" {
		t.Errorf("OuterHTML(nil) = %q, want empty", got)
	}
	node := parseFirst(t, "<div><p>Hi</p></div>")
	if got := OuterHTML(node); got != "<div><p>Hi</p></div>" {
		t.Errorf("OuterHTML() = %q", got)
	}
	// Escaping of text node content.
	txt := CreateTextNode("a<b>c")
	if got := OuterHTML(txt); got != "a&lt;b&gt;c" {
		t.Errorf("OuterHTML(escaped) = %q", got)
	}
}

func TestInnerHTMLLocal(t *testing.T) {
	if got := InnerHTML(nil); got != "" {
		t.Errorf("InnerHTML(nil) = %q, want empty", got)
	}
	tests := []struct {
		name string
		src  string
		want string
	}{
		{"text node has no inner", "plain text", ""},
		{"single", "<h1>Hello</h1>", "Hello"},
		{"nested", "<div><p>x</p></div>", "<p>x</p>"},
		{"mixed", "<div><p>x</p>tail</div>", "<p>x</p>tail"},
		{"trims surrounding space", "<div>  <p>x</p>  </div>", "<p>x</p>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := parseFirst(t, tt.src)
			if got := InnerHTML(node); got != tt.want {
				t.Errorf("InnerHTML() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDocumentElement(t *testing.T) {
	doc, err := html.Parse(strings.NewReader("<html><body><p>x</p></body></html>"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	root := DocumentElement(doc)
	if root == nil || TagName(root) != "html" {
		t.Errorf("DocumentElement = %v, want html element", root)
	}

	// A fragment without an <html> tag.
	fragment := CreateElement("div")
	if got := DocumentElement(fragment); got != nil {
		t.Errorf("DocumentElement(no html) = %v, want nil", got)
	}
}

func TestIDLocal(t *testing.T) {
	node := parseFirst(t, `<p id="  my-id  "></p>`)
	if got := ID(node); got != "my-id" {
		t.Errorf("ID() = %q, want my-id", got)
	}
	noID := parseFirst(t, `<p></p>`)
	if got := ID(noID); got != "" {
		t.Errorf("ID(none) = %q, want empty", got)
	}
}

func TestClassNameLocal(t *testing.T) {
	tests := []struct {
		src  string
		want string
	}{
		{`<p></p>`, ""},
		{`<p class="a"></p>`, "a"},
		{`<p class="a b"></p>`, "a b"},
		{`<p class="   a    b   "></p>`, "a b"},
	}
	for _, tt := range tests {
		node := parseFirst(t, tt.src)
		if got := ClassName(node); got != tt.want {
			t.Errorf("ClassName(%q) = %q, want %q", tt.src, got, tt.want)
		}
	}
}

func TestChildrenLocal(t *testing.T) {
	if got := Children(nil); got != nil {
		t.Errorf("Children(nil) = %v, want nil", got)
	}
	node := parseFirst(t, "<div><p>a</p>text<span>b</span></div>")
	children := Children(node)
	if len(children) != 2 { // text node excluded
		t.Fatalf("Children() = %d, want 2", len(children))
	}
	if TagName(children[0]) != "p" || TagName(children[1]) != "span" {
		t.Errorf("Children tags = %q,%q", TagName(children[0]), TagName(children[1]))
	}
}

func TestChildNodesLocal(t *testing.T) {
	node := parseFirst(t, "<div><p>a</p>text<span>b</span></div>")
	nodes := ChildNodes(node)
	if len(nodes) != 3 { // p, text, span
		t.Errorf("ChildNodes() = %d, want 3", len(nodes))
	}

	empty := parseFirst(t, "<div></div>")
	if got := ChildNodes(empty); got != nil {
		t.Errorf("ChildNodes(empty) = %v, want nil", got)
	}
}

func TestFirstElementChildLocal(t *testing.T) {
	node := parseFirst(t, "<div>text<p>first</p><span></span></div>")
	first := FirstElementChild(node)
	if first == nil || TagName(first) != "p" {
		t.Errorf("FirstElementChild = %v, want p", first)
	}

	empty := parseFirst(t, "<div>only text</div>")
	if got := FirstElementChild(empty); got != nil {
		t.Errorf("FirstElementChild(no element) = %v, want nil", got)
	}
}

func TestPreviousElementSiblingLocal(t *testing.T) {
	body := parseBody(t, "<p>before</p>text<div id='target'></div>")
	target := GetElementByID(body, "target")
	prev := PreviousElementSibling(target)
	if prev == nil || TagName(prev) != "p" {
		t.Errorf("PreviousElementSibling = %v, want p", prev)
	}

	first := parseFirst(t, "<div></div>")
	if got := PreviousElementSibling(first); got != nil {
		t.Errorf("PreviousElementSibling(first) = %v, want nil", got)
	}
}

func TestNextElementSiblingLocal(t *testing.T) {
	body := parseBody(t, "<div id='target'></div>text<p>after</p>")
	target := GetElementByID(body, "target")
	next := NextElementSibling(target)
	if next == nil || TagName(next) != "p" {
		t.Errorf("NextElementSibling = %v, want p", next)
	}

	body2 := parseBody(t, "<div id='last'></div>trailing text")
	last := GetElementByID(body2, "last")
	if got := NextElementSibling(last); got != nil {
		t.Errorf("NextElementSibling(last) = %v, want nil", got)
	}
}

func TestAppendChildLocal(t *testing.T) {
	parent := CreateElement("div")
	child := CreateElement("span")
	AppendChild(parent, child)
	if got := OuterHTML(parent); got != "<div><span></span></div>" {
		t.Errorf("AppendChild = %q", got)
	}

	// Appending into a void element is a no-op.
	br := CreateElement("br")
	AppendChild(br, CreateElement("span"))
	if got := OuterHTML(br); got != "<br/>" {
		t.Errorf("AppendChild(void) = %q, want <br/>", got)
	}

	// Re-appending an already-attached child moves it (detach path).
	body := parseFirst(t, "<div><p></p><span>moved</span></div>")
	p := GetElementsByTagName(body, "p")[0]
	span := GetElementsByTagName(body, "span")[0]
	AppendChild(p, span)
	if got := OuterHTML(body); got != "<div><p><span>moved</span></p></div>" {
		t.Errorf("AppendChild(move) = %q", got)
	}
}

func TestPrependChildLocal(t *testing.T) {
	parent := parseFirst(t, "<div><p>existing</p></div>")
	PrependChild(parent, CreateElement("span"))
	if got := OuterHTML(parent); got != "<div><span></span><p>existing</p></div>" {
		t.Errorf("PrependChild(with children) = %q", got)
	}

	// Prepend into empty parent falls back to append.
	empty := CreateElement("div")
	PrependChild(empty, CreateElement("b"))
	if got := OuterHTML(empty); got != "<div><b></b></div>" {
		t.Errorf("PrependChild(empty) = %q", got)
	}

	// Void parent is a no-op.
	br := CreateElement("br")
	PrependChild(br, CreateElement("span"))
	if got := OuterHTML(br); got != "<br/>" {
		t.Errorf("PrependChild(void) = %q", got)
	}
}

func TestReplaceChildLocal(t *testing.T) {
	t.Run("replaces existing child", func(t *testing.T) {
		parent := parseFirst(t, "<div><p>old</p></div>")
		old := GetElementsByTagName(parent, "p")[0]
		newChild := CreateElement("span")
		gotNew, gotOld := ReplaceChild(parent, newChild, old)
		if gotNew != newChild || gotOld != old {
			t.Error("ReplaceChild returned unexpected nodes")
		}
		if got := OuterHTML(parent); got != "<div><span></span></div>" {
			t.Errorf("ReplaceChild = %q", got)
		}
	})

	t.Run("nil parent is no-op", func(t *testing.T) {
		newChild := CreateElement("span")
		old := CreateElement("p")
		gotNew, gotOld := ReplaceChild(nil, newChild, old)
		if gotNew != newChild || gotOld != old {
			t.Error("ReplaceChild(nil parent) should return inputs unchanged")
		}
	})

	t.Run("void parent is no-op", func(t *testing.T) {
		br := CreateElement("br")
		newChild := CreateElement("span")
		old := CreateElement("p")
		ReplaceChild(br, newChild, old)
		if got := OuterHTML(br); got != "<br/>" {
			t.Errorf("ReplaceChild(void) = %q", got)
		}
	})

	t.Run("nil old child is no-op", func(t *testing.T) {
		parent := parseFirst(t, "<div><p>x</p></div>")
		before := OuterHTML(parent)
		ReplaceChild(parent, CreateElement("span"), nil)
		if after := OuterHTML(parent); after != before {
			t.Errorf("ReplaceChild(nil old) changed tree: %q", after)
		}
	})

	t.Run("old child not a child of parent is no-op", func(t *testing.T) {
		parent := parseFirst(t, "<div><p>x</p></div>")
		stranger := CreateElement("p") // not attached to parent
		before := OuterHTML(parent)
		ReplaceChild(parent, CreateElement("span"), stranger)
		if after := OuterHTML(parent); after != before {
			t.Errorf("ReplaceChild(stranger) changed tree: %q", after)
		}
	})
}

func TestIncludeNodeLocal(t *testing.T) {
	body := parseBody(t, "<p></p><span></span>")
	all := GetElementsByTagName(body, "*")
	p := GetElementsByTagName(body, "p")[0]
	if !IncludeNode(all, p) {
		t.Error("IncludeNode(p) = false, want true")
	}
	stranger := CreateElement("div")
	if IncludeNode(all, stranger) {
		t.Error("IncludeNode(stranger) = true, want false")
	}
	if IncludeNode(nil, p) {
		t.Error("IncludeNode(nil list) = true, want false")
	}
}

func TestCloneLocal(t *testing.T) {
	src := parseFirst(t, `<div id="x"><p>child</p></div>`)

	// Shallow clone has no children.
	shallow := Clone(src, false)
	if shallow.FirstChild != nil {
		t.Error("shallow Clone should not copy children")
	}
	if GetAttribute(shallow, "id") != "x" {
		t.Error("shallow Clone lost attributes")
	}

	// Deep clone copies the full subtree but is detached.
	deep := Clone(src, true)
	if got := OuterHTML(deep); got != `<div id="x"><p>child</p></div>` {
		t.Errorf("deep Clone = %q", got)
	}
	if deep.Parent != nil {
		t.Error("clone should be detached from parent")
	}
	// Mutating the clone must not affect the source.
	SetAttribute(deep, "id", "changed")
	if GetAttribute(src, "id") != "x" {
		t.Error("mutating clone affected source")
	}
}

func TestGetAllNodesWithTagLocal(t *testing.T) {
	doc := parseFirst(t, `<div><h1></h1><h2></h2><p></p><p></p></div>`)
	tests := []struct {
		tags []string
		want int
	}{
		{[]string{"h1"}, 1},
		{[]string{"h1", "h2"}, 2},
		{[]string{"p"}, 2},
		{[]string{"h1", "p"}, 3},
		{[]string{"span"}, 0},
		{nil, 0},
	}
	for _, tt := range tests {
		if got := len(GetAllNodesWithTag(doc, tt.tags...)); got != tt.want {
			t.Errorf("GetAllNodesWithTag(%v) = %d, want %d", tt.tags, got, tt.want)
		}
	}
}

func TestForEachNodeLocal(t *testing.T) {
	doc := parseFirst(t, `<div><p></p><span></span><b></b></div>`)
	nodes := Children(doc)

	var tags []string
	var indexes []int
	ForEachNode(nodes, func(n *html.Node, i int) {
		tags = append(tags, TagName(n))
		indexes = append(indexes, i)
	})
	if strings.Join(tags, ",") != "p,span,b" {
		t.Errorf("ForEachNode tags = %v", tags)
	}
	if len(indexes) != 3 || indexes[0] != 0 || indexes[2] != 2 {
		t.Errorf("ForEachNode indexes = %v", indexes)
	}

	// Empty list calls fn zero times.
	called := false
	ForEachNode(nil, func(*html.Node, int) { called = true })
	if called {
		t.Error("ForEachNode(nil) should not call fn")
	}
}

func TestRemoveNodesLocal(t *testing.T) {
	t.Run("remove all when filter nil", func(t *testing.T) {
		parent := parseFirst(t, "<div><h1></h1><p></p><img/></div>")
		// GetElementsByTagName returns the div's descendants (h1, p, img), not the div.
		els := GetElementsByTagName(parent, "*")
		RemoveNodes(els, nil)
		if got := OuterHTML(parent); got != "<div></div>" {
			t.Errorf("RemoveNodes(nil filter) = %q", got)
		}
	})

	t.Run("remove filtered", func(t *testing.T) {
		parent := parseFirst(t, "<div><h1></h1><p></p><img/></div>")
		els := GetElementsByTagName(parent, "*")
		RemoveNodes(els, func(n *html.Node) bool { return TagName(n) == "h1" })
		if got := OuterHTML(parent); got != "<div><p></p><img/></div>" {
			t.Errorf("RemoveNodes(filter) = %q", got)
		}
	})

	t.Run("node without parent is skipped", func(t *testing.T) {
		orphan := CreateElement("p")
		// Should not panic.
		RemoveNodes([]*html.Node{orphan}, nil)
	})
}

func TestSetTextContentLocal(t *testing.T) {
	node := parseFirst(t, "<div><p>old</p>more</div>")
	SetTextContent(node, "new & text")
	// Text content is escaped on render.
	if got := OuterHTML(node); got != "<div>new &amp; text</div>" {
		t.Errorf("SetTextContent = %q", got)
	}

	// Void element is a no-op.
	br := CreateElement("br")
	SetTextContent(br, "x")
	if got := OuterHTML(br); got != "<br/>" {
		t.Errorf("SetTextContent(void) = %q", got)
	}
}

func TestSetInnerHTMLLocal(t *testing.T) {
	node := parseFirst(t, "<div><p>old</p></div>")
	SetInnerHTML(node, "<b>bold</b> and <i>italic</i>")
	if got := OuterHTML(node); got != "<div><b>bold</b> and <i>italic</i></div>" {
		t.Errorf("SetInnerHTML = %q", got)
	}

	// Replacing into an empty node.
	empty := CreateElement("div")
	SetInnerHTML(empty, "<span>x</span>")
	if got := OuterHTML(empty); got != "<div><span>x</span></div>" {
		t.Errorf("SetInnerHTML(empty) = %q", got)
	}
}

func TestIsVoidElementLocal(t *testing.T) {
	voids := []string{"area", "base", "br", "col", "embed", "hr", "img", "input", "keygen", "link", "meta", "param", "source", "track", "wbr"}
	for _, tag := range voids {
		if !IsVoidElement(CreateElement(tag)) {
			t.Errorf("IsVoidElement(%q) = false, want true", tag)
		}
	}
	nonVoids := []string{"div", "p", "span", "a", "section"}
	for _, tag := range nonVoids {
		if IsVoidElement(CreateElement(tag)) {
			t.Errorf("IsVoidElement(%q) = true, want false", tag)
		}
	}
	// Non-element nodes are void.
	if !IsVoidElement(CreateTextNode("x")) {
		t.Error("IsVoidElement(text) = false, want true")
	}
}

func TestFastParse(t *testing.T) {
	node, err := FastParse(strings.NewReader("<html><body><p>hi</p></body></html>"))
	if err != nil {
		t.Fatalf("FastParse error: %v", err)
	}
	ps := GetElementsByTagName(node, "p")
	if len(ps) != 1 || TextContent(ps[0]) != "hi" {
		t.Errorf("FastParse produced unexpected tree")
	}
}

func TestParse(t *testing.T) {
	t.Run("utf8 content", func(t *testing.T) {
		node, err := Parse(strings.NewReader("<html><body><p>héllo</p></body></html>"))
		if err != nil {
			t.Fatalf("Parse error: %v", err)
		}
		ps := GetElementsByTagName(node, "p")
		if len(ps) != 1 || TextContent(ps[0]) != "héllo" {
			t.Errorf("Parse text = %q", TextContent(ps[0]))
		}
	})

	t.Run("declared charset", func(t *testing.T) {
		// Document declaring a non-default charset exercises the charset lookup path.
		src := `<html><head><meta charset="iso-8859-1"></head><body><p>plain ascii</p></body></html>`
		node, err := Parse(strings.NewReader(src))
		if err != nil {
			t.Fatalf("Parse error: %v", err)
		}
		ps := GetElementsByTagName(node, "p")
		if len(ps) != 1 || TextContent(ps[0]) != "plain ascii" {
			t.Errorf("Parse charset text = %q", TextContent(ps[0]))
		}
	})

	t.Run("soft hyphen removed", func(t *testing.T) {
		// U+00AD soft hyphen should be stripped by normalizeTextEncoding.
		src := "<html><body><p>soft\u00adhyphen</p></body></html>"
		node, err := Parse(strings.NewReader(src))
		if err != nil {
			t.Fatalf("Parse error: %v", err)
		}
		ps := GetElementsByTagName(node, "p")
		if got := TextContent(ps[0]); got != "softhyphen" {
			t.Errorf("Parse soft hyphen text = %q, want softhyphen", got)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if _, err := Parse(strings.NewReader("")); err != nil {
			t.Errorf("Parse(empty) error: %v", err)
		}
	})
}

func TestNormalizeTextEncoding(t *testing.T) {
	// NFD-decomposed "é" (e + combining acute) should normalize to NFC single rune,
	// and the soft hyphen should be dropped.
	input := "é\u00adx" // "é" decomposed + soft hyphen + x
	r := normalizeTextEncoding(strings.NewReader(input))
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("read: %v", err)
	}
	got := buf.String()
	if got != "éx" { // NFC "é" + x, soft hyphen removed
		t.Errorf("normalizeTextEncoding = %q, want %q", got, "éx")
	}
}

func TestDetachChildViaAppend(t *testing.T) {
	// Build a tree, then move a middle child elsewhere to exercise detachChild's
	// prev/next sibling rewiring (the indirect path through AppendChild).
	src := parseFirst(t, "<div><a>1</a><b>2</b><c>3</c></div>")
	dest := CreateElement("section")
	mid := GetElementsByTagName(src, "b")[0]

	AppendChild(dest, mid)
	if got := OuterHTML(src); got != "<div><a>1</a><c>3</c></div>" {
		t.Errorf("source after move = %q", got)
	}
	if got := OuterHTML(dest); got != "<section><b>2</b></section>" {
		t.Errorf("dest after move = %q", got)
	}
}
