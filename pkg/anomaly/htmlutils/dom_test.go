package htmlutils_test

import (
	"strings"
	"testing"

	"github.com/go-shiori/dom"
	"golang.org/x/net/html"
)

func TestQuerySelectorAll(t *testing.T) {
	htmlSource := `<body>
		<p></p>
		<h1 id="heading"></h1>
		<p id="paragraph"></p>
		<p class="class-a"></p>
		<span class="class-a"></span>
		<div class="class-a"></div>
		<p class="class-b"></p>
		<div class="class-b"></div>
		<span class="class-c"></span>
		<p class="class-a class-b"></p>
		<p class="class-a class-c"></p>
		<p class="class-a class-b class-c"></p>
	</body>`

	doc, err := parseHTMLSource(htmlSource)
	if err != nil {
		t.Errorf("QuerySelectorAll(), failed to parse: %v", err)
	}

	tests := map[string]int{
		"p":                                      7,
		"h1":                                     1,
		"div":                                    2,
		"span":                                   2,
		"#heading":                               1,
		"#paragraph":                             1,
		"#unknown-id":                            0,
		".class-a":                               6,
		".class-b":                               4,
		".class-c":                               3,
		".class-a.class-b":                       2,
		".class-a.class-c":                       2,
		".class-b.class-c":                       1,
		".class-a.class-b.class-c":               1,
		".class-a.class-b.class-d":               0,
		".class-a, .class-b":                     8,
		".class-a, .class-c":                     7,
		".class-b, .class-c":                     6,
		".class-a, .class-b, .class-c":           9,
		".class-a, .class-b, .class-c, .class-d": 9,
	}

	for selectors, count := range tests {
		t.Run(selectors, func(t *testing.T) {
			if got := len(dom.QuerySelectorAll(doc, selectors)); got != count {
				t.Errorf("QuerySelectorAll() = %v, want %v", got, count)
			}
		})
	}
}

func TestQuerySelector(t *testing.T) {
	htmlSource := `<body>
		<p></p>
		<h1 id="heading"></h1>
		<p id="paragraph"></p>
		<p class="class-a"></p>
		<span class="class-a"></span>
		<div class="class-a"></div>
		<p class="class-b"></p>
		<div class="class-b"></div>
		<span class="class-c"></span>
		<p class="class-a class-b"></p>
		<p class="class-a class-c"></p>
		<p class="class-a class-b class-c"></p>
	</body>`

	doc, err := parseHTMLSource(htmlSource)
	if err != nil {
		t.Errorf("QuerySelector(), failed to parse: %v", err)
	}

	tests := map[string]string{
		"p":                                      "p",
		"h1":                                     "h1",
		"div":                                    "div",
		"span":                                   "span",
		"#heading":                               "h1",
		"#paragraph":                             "p",
		"#unknown-id":                            "",
		".class-a":                               "p",
		".class-b":                               "p",
		".class-c":                               "span",
		".class-a.class-b":                       "p",
		".class-a.class-c":                       "p",
		".class-b.class-c":                       "p",
		".class-a.class-b.class-c":               "p",
		".class-a.class-b.class-d":               "",
		".class-a, .class-b":                     "p",
		".class-a, .class-c":                     "p",
		".class-b, .class-c":                     "p",
		".class-a, .class-b, .class-c":           "p",
		".class-a, .class-b, .class-c, .class-d": "p",
	}

	for selectors, tagName := range tests {
		t.Run(selectors, func(t *testing.T) {
			node := dom.QuerySelector(doc, selectors)

			result := ""
			if node != nil {
				result = dom.TagName(node)
			}

			if result != tagName {
				t.Errorf("QuerySelector() = %v, want %v", result, tagName)
			}
		})
	}
}

func TestGetElementByID(t *testing.T) {
	htmlSource := `<div>
		<h1 id="heading"></h1>
		<p id="paragraph"></p>
		<p id="paragraph"></p>
		<p></p>
	</div>`

	doc, err := parseHTMLSource(htmlSource)
	if err != nil {
		t.Errorf("GetElementByID(), failed to parse: %v", err)
	}

	tests := map[string]string{
		"heading":    "h1",
		"paragraph":  "p",
		"unknown-id": "",
	}

	for id, tagName := range tests {
		t.Run(id, func(t *testing.T) {
			node := dom.GetElementByID(doc, id)

			result := ""
			if node != nil {
				result = dom.TagName(node)
			}

			if result != tagName {
				t.Errorf("TestGetElementByID() = %v, want %v", result, tagName)
			}
		})
	}
}

func TestGetElementsByClassName(t *testing.T) {
	htmlSource := `<div>
		<p class="class-a"></p>
		<p class="class-a"></p>
		<p class="class-a"></p>
		<p class="class-b"></p>
		<p class="class-b"></p>
		<p class="class-c"></p>
		<p class="class-a class-b"></p>
		<p class="class-a class-c"></p>
		<p class="class-a class-b class-c"></p>
	</div>`

	doc, err := parseHTMLSource(htmlSource)
	if err != nil {
		t.Errorf("GetElementsByClassName(), failed to parse: %v", err)
	}

	tests := map[string]int{
		"":                        0,
		"class-a":                 6,
		"class-b":                 4,
		"class-c":                 3,
		"class-a class-b":         2,
		"class-a class-c":         2,
		"class-b class-c":         1,
		"class-a class-b class-c": 1,
	}

	for className, count := range tests {
		t.Run(className, func(t *testing.T) {
			if got := len(dom.GetElementsByClassName(doc, className)); got != count {
				t.Errorf("GetElementsByClassName() = %v, want %v", got, count)
			}
		})
	}
}

func TestGetElementsByTagName(t *testing.T) {
	htmlSource := `<div>
		<h1></h1>
		<h2></h2><h2></h2>
		<h3></h3><h3></h3><h3></h3>
		<p></p><p></p><p></p><p></p><p></p>
		<div></div><div></div><div></div><div></div><div></div>
		<div><p>Hey it's nested</p></div>
		<div></div>
		<img/><img/><img/><img/><img/><img/><img/><img/>
		<img/><img/><img/><img/>
	</div>`

	doc, err := parseHTMLSource(htmlSource)
	if err != nil {
		t.Errorf("GetElementsByTagName(), failed to parse: %v", err)
	}

	tests := map[string]int{
		"h1":  1,
		"h2":  2,
		"h3":  3,
		"p":   6,
		"div": 7,
		"img": 12,
		"*":   31,
	}

	mainDiv := doc.FirstChild
	for tagName, count := range tests {
		t.Run(tagName, func(t *testing.T) {
			if got := len(dom.GetElementsByTagName(mainDiv, tagName)); got != count {
				t.Errorf("GetElementsByTagName() = %v, want %v", got, count)
			}
		})
	}
}

func TestCreateElement(t *testing.T) {
	tests := []struct {
		name     string
		tagName  string
		tagCount int
	}{{
		name:     "3 headings1",
		tagName:  "h1",
		tagCount: 3,
	}, {
		name:     "4 headings2",
		tagName:  "h2",
		tagCount: 4,
	}, {
		name:     "5 headings3",
		tagName:  "h3",
		tagCount: 5,
	}, {
		name:     "10 paragraph",
		tagName:  "p",
		tagCount: 10,
	}, {
		name:     "6 div",
		tagName:  "div",
		tagCount: 6,
	}, {
		name:     "8 image",
		tagName:  "img",
		tagCount: 8,
	}, {
		name:     "22 custom tag",
		tagName:  "custom-tag",
		tagCount: 22,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := &html.Node{}
			for i := 0; i < tt.tagCount; i++ {
				doc.AppendChild(dom.CreateElement(tt.tagName))
			}

			if tags := dom.GetElementsByTagName(doc, tt.tagName); len(tags) != tt.tagCount {
				t.Errorf("CreateElement() = %v, want %v", len(tags), tt.tagCount)
			}
		})
	}
}

func TestCreateTextNode(t *testing.T) {
	tests := []string{
		"hello world",
		"this is awesome",
		"all cat is good boy",
		"all dog is good boy as well",
	}

	for _, text := range tests {
		t.Run(text, func(t *testing.T) {
			node := dom.CreateTextNode(text)
			if outerHTML := dom.OuterHTML(node); outerHTML != text {
				t.Errorf("CreateTextNode() = %v, want %v", outerHTML, text)
			}
		})
	}
}

func TestGetAttribute(t *testing.T) {
	tests := []struct {
		name       string
		htmlSource string
		attrName   string
		want       string
	}{{
		name:       "attr id from paragraph",
		htmlSource: `<p id="main-paragraph"></p>`,
		attrName:   "id",
		want:       "main-paragraph",
	}, {
		name:       "attr class from list",
		htmlSource: `<ul class="bullets"></ul>`,
		attrName:   "class",
		want:       "bullets",
	}, {
		name:       "attr style from paragraph",
		htmlSource: `<div style="display: none"></div>`,
		attrName:   "style",
		want:       "display: none",
	}, {
		name:       "attr doesn't exists",
		htmlSource: `<p id="main-paragraph"></p>`,
		attrName:   "class",
		want:       "",
	}, {
		name:       "node has no attributes",
		htmlSource: `<p></p>`,
		attrName:   "id",
		want:       "",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTMLSource(tt.htmlSource)
			if err != nil {
				t.Errorf("GetAttribute(), failed to parse: %v", err)
			}

			if got := dom.GetAttribute(doc.FirstChild, tt.attrName); got != tt.want {
				t.Errorf("GetAttribute() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetAttribute(t *testing.T) {
	tests := []struct {
		name       string
		htmlSource string
		attrName   string
		attrValue  string
		want       string
	}{{
		name:       "set id of paragraph",
		htmlSource: `<p id="main-paragraph"></p>`,
		attrName:   "id",
		attrValue:  "txt-main",
		want:       `<p id="txt-main"></p>`,
	}, {
		name:       "set id from paragraph with several attrs",
		htmlSource: `<p id="main-paragraph" class="title"></p>`,
		attrName:   "id",
		attrValue:  "txt-main",
		want:       `<p id="txt-main" class="title"></p>`,
	}, {
		name:       "set new attr for paragraph",
		htmlSource: `<p></p>`,
		attrName:   "class",
		attrValue:  "title",
		want:       `<p class="title"></p>`,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTMLSource(tt.htmlSource)
			if err != nil {
				t.Errorf("SetAttribute(), failed to parse: %v", err)
			}

			node := doc.FirstChild
			dom.SetAttribute(node, tt.attrName, tt.attrValue)
			if outerHTML := dom.OuterHTML(node); outerHTML != tt.want {
				t.Errorf("setAttribute() = %v, want %v", outerHTML, tt.want)
			}
		})
	}
}

func TestRemoveAttribute(t *testing.T) {
	tests := []struct {
		name       string
		htmlSource string
		attrName   string
		want       string
	}{{
		name:       "remove id of paragraph",
		htmlSource: `<p id="main-paragraph"></p>`,
		attrName:   "id",
		want:       `<p></p>`,
	}, {
		name:       "remove id from paragraph with several attrs",
		htmlSource: `<p id="main-paragraph" class="title"></p>`,
		attrName:   "id",
		want:       `<p class="title"></p>`,
	}, {
		name:       "remove inexist attr of paragraph",
		htmlSource: `<p id="main-paragraph"></p>`,
		attrName:   "class",
		want:       `<p id="main-paragraph"></p>`,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTMLSource(tt.htmlSource)
			if err != nil {
				t.Errorf("RemoveAttribute(), failed to parse: %v", err)
			}

			node := doc.FirstChild
			dom.RemoveAttribute(node, tt.attrName)
			if outerHTML := dom.OuterHTML(node); outerHTML != tt.want {
				t.Errorf("RemoveAttribute() = %v, want %v", outerHTML, tt.want)
			}
		})
	}
}

func TestHasAttribute(t *testing.T) {
	tests := []struct {
		name       string
		htmlSource string
		attrName   string
		want       bool
	}{{
		name:       "attribute is exist",
		htmlSource: `<p id="main-paragraph"></p>`,
		attrName:   "id",
		want:       true,
	}, {
		name:       "attribute is not exist",
		htmlSource: `<p id="main-paragraph"></p>`,
		attrName:   "class",
		want:       false,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTMLSource(tt.htmlSource)
			if err != nil {
				t.Errorf("HasAttribute(), failed to parse: %v", err)
			}

			if got := dom.HasAttribute(doc.FirstChild, tt.attrName); got != tt.want {
				t.Errorf("HasAttribute() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTextContent(t *testing.T) {
	tests := []struct {
		name       string
		htmlSource string
		want       string
	}{{
		name:       "ordinary text node",
		htmlSource: "this is an ordinary text",
		want:       "this is an ordinary text",
	}, {
		name:       "single empty node element",
		htmlSource: "<p></p>",
		want:       "",
	}, {
		name:       "single node with content",
		htmlSource: "<p>Hello all</p>",
		want:       "Hello all",
	}, {
		name:       "single node with content and unnecessary space",
		htmlSource: "<p>Hello all   </p>",
		want:       "Hello all   ",
	}, {
		name:       "nested element",
		htmlSource: "<div><p>Some nested element</p></div>",
		want:       "Some nested element",
	}, {
		name:       "nested element with unnecessary space",
		htmlSource: "<div><p>Some nested element</p>    </div>",
		want:       "Some nested element    ",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTMLSource(tt.htmlSource)
			if err != nil {
				t.Errorf("TextContent(), failed to parse: %v", err)
			}

			if got := dom.TextContent(doc.FirstChild); got != tt.want {
				t.Errorf("TextContent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOuterHTML(t *testing.T) {
	tests := []struct {
		name       string
		htmlSource string
	}{{
		name:       "text node",
		htmlSource: "this is an ordinary text",
	}, {
		name:       "single element",
		htmlSource: "<h1>Hello</h1>",
	}, {
		name:       "nested elements",
		htmlSource: "<div><p>Some nested element</p></div>",
	}, {
		name:       "triple nested elements",
		htmlSource: "<div><p>Some <a>nested</a> element</p></div>",
	}, {
		name:       "mixed nested elements",
		htmlSource: "<div><p>Some <a>nested</a> element</p><p>and more</p></div>",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTMLSource(tt.htmlSource)
			if err != nil {
				t.Errorf("dom.OuterHTML(), failed to parse: %v", err)
			}

			if got := dom.OuterHTML(doc.FirstChild); got != tt.htmlSource {
				t.Errorf("dom.OuterHTML() = %v, want %v", got, tt.htmlSource)
			}
		})
	}
}

func TestInnerHTML(t *testing.T) {
	tests := []struct {
		name       string
		htmlSource string
		want       string
	}{{
		name:       "text node",
		htmlSource: "this is an ordinary text",
		want:       "",
	}, {
		name:       "single element",
		htmlSource: "<h1>Hello</h1>",
		want:       "Hello",
	}, {
		name:       "nested elements",
		htmlSource: "<div><p>Some nested element</p></div>",
		want:       "<p>Some nested element</p>",
	}, {
		name:       "mixed text and element node",
		htmlSource: "<div><p>Some element</p>with text</div>",
		want:       "<p>Some element</p>with text",
	}, {
		name:       "triple nested elements",
		htmlSource: "<div><p>Some <a>nested</a> element</p></div>",
		want:       "<p>Some <a>nested</a> element</p>",
	}, {
		name:       "mixed nested elements",
		htmlSource: "<div><p>Some <a>nested</a> element</p><p>and more</p></div>",
		want:       "<p>Some <a>nested</a> element</p><p>and more</p>",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTMLSource(tt.htmlSource)
			if err != nil {
				t.Errorf("InnerHTML(), failed to parse: %v", err)
			}

			if got := dom.InnerHTML(doc.FirstChild); got != tt.want {
				t.Errorf("InnerHTML() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestId(t *testing.T) {
	tests := []struct {
		name       string
		htmlSource string
		want       string
	}{{
		name:       "id exists",
		htmlSource: `<p id="main-paragraph"></p>`,
		want:       "main-paragraph",
	}, {
		name:       "id doesn't exist",
		htmlSource: `<p></p>`,
		want:       "",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTMLSource(tt.htmlSource)
			if err != nil {
				t.Errorf("ID(), failed to parse: %v", err)
			}

			if got := dom.ID(doc.FirstChild); got != tt.want {
				t.Errorf("ID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClassName(t *testing.T) {
	tests := []struct {
		name       string
		htmlSource string
		want       string
	}{{
		name:       "class doesn't exist",
		htmlSource: `<p></p>`,
		want:       "",
	}, {
		name:       "class exist",
		htmlSource: `<p class="title"></p>`,
		want:       "title",
	}, {
		name:       "multiple class",
		htmlSource: `<p class="title heading"></p>`,
		want:       "title heading",
	}, {
		name:       "multiple class with unnecessary space",
		htmlSource: `<p class="    title heading    "></p>`,
		want:       "title heading",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTMLSource(tt.htmlSource)
			if err != nil {
				t.Errorf("ClassName(), failed to parse: %v", err)
			}

			if got := dom.ClassName(doc.FirstChild); got != tt.want {
				t.Errorf("ClassName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChildren(t *testing.T) {
	tests := []struct {
		name       string
		htmlSource string
		want       []string
	}{{
		name:       "has no children",
		htmlSource: "<div></div>",
		want:       []string{},
	}, {
		name:       "has one children",
		htmlSource: "<div><p>Hello</p></div>",
		want:       []string{"<p>Hello</p>"},
	}, {
		name:       "has many children",
		htmlSource: "<div><p>Hello</p><p>I'm</p><p>Happy</p></div>",
		want:       []string{"<p>Hello</p>", "<p>I&#39;m</p>", "<p>Happy</p>"},
	}, {
		name:       "has nested children",
		htmlSource: "<div><p>Hello I'm <span>Happy</span></p></div>",
		want:       []string{"<p>Hello I&#39;m <span>Happy</span></p>"},
	}, {
		name:       "mixed text and element node",
		htmlSource: "<div><p>Hello I'm</p>happy</div>",
		want:       []string{"<p>Hello I&#39;m</p>"},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTMLSource(tt.htmlSource)
			if err != nil {
				t.Errorf("Children(), failed to parse: %v", err)
			}

			div := doc.FirstChild
			nodes := dom.Children(div)
			if len(nodes) != len(tt.want) {
				t.Errorf("Children() count = %v, want = %v", len(nodes), len(tt.want))
			}

			for i, child := range nodes {
				wantHTML := tt.want[i]
				childHTML := dom.OuterHTML(child)
				if childHTML != wantHTML {
					t.Errorf("Children() = %v, want = %v", childHTML, wantHTML)
				}
			}
		})
	}
}

func TestChildNodes(t *testing.T) {
	tests := []struct {
		name       string
		htmlSource string
		want       []string
	}{{
		name:       "has no children",
		htmlSource: "<div></div>",
		want:       []string{},
	}, {
		name:       "has one children",
		htmlSource: "<div><p>Hello</p></div>",
		want:       []string{"<p>Hello</p>"},
	}, {
		name:       "has many children",
		htmlSource: "<div><p>Hello</p><p>I'm</p><p>Happy</p></div>",
		want:       []string{"<p>Hello</p>", "<p>I&#39;m</p>", "<p>Happy</p>"},
	}, {
		name:       "has nested children",
		htmlSource: "<div><p>Hello I'm <span>Happy</span></p></div>",
		want:       []string{"<p>Hello I&#39;m <span>Happy</span></p>"},
	}, {
		name:       "mixed text and element node",
		htmlSource: "<div><p>Hello I'm</p>happy</div>",
		want:       []string{"<p>Hello I&#39;m</p>", "happy"},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTMLSource(tt.htmlSource)
			if err != nil {
				t.Errorf("ChildNodes(), failed to parse: %v", err)
			}

			div := doc.FirstChild
			nodes := dom.ChildNodes(div)
			if len(nodes) != len(tt.want) {
				t.Errorf("ChildNodes() count = %v, want = %v", len(nodes), len(tt.want))
			}

			for i, child := range nodes {
				wantHTML := tt.want[i]
				childHTML := dom.OuterHTML(child)
				if child.Type == html.TextNode {
					childHTML = dom.TextContent(child)
				}

				if childHTML != wantHTML {
					t.Errorf("ChildNodes() = %v, want = %v", childHTML, wantHTML)
				}
			}
		})
	}
}

func TestFirstElementChild(t *testing.T) {
	tests := []struct {
		name       string
		htmlSource string
		want       string
	}{{
		name:       "has no children",
		htmlSource: "<div></div>",
		want:       "",
	}, {
		name:       "has one children",
		htmlSource: "<div><p>Hey</p></div>",
		want:       "<p>Hey</p>",
	}, {
		name:       "has several children",
		htmlSource: "<div><p>Hey</p><b>bro</b></div>",
		want:       "<p>Hey</p>",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTMLSource(tt.htmlSource)
			if err != nil {
				t.Errorf("FirstElementChild(), failed to parse: %v", err)
			}

			div := doc.FirstChild
			firstChild := dom.FirstElementChild(div)
			if got := dom.OuterHTML(firstChild); got != tt.want {
				t.Errorf("FirstElementChild() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPreviousElementSibling(t *testing.T) {
	tests := []struct {
		name       string
		htmlSource string
		want       string
	}{{
		name:       "has no sibling",
		htmlSource: "<div></div>",
		want:       "",
	}, {
		name:       "has directly element sibling",
		htmlSource: "<p>Hey</p><div></div>",
		want:       "<p>Hey</p>",
	}, {
		name:       "has no element sibling",
		htmlSource: "I'm your sibling, you know<div></div>",
		want:       "",
	}, {
		name:       "has distant element sibling",
		htmlSource: "<p>This is the one you want</p> not this one <div></div>",
		want:       "<p>This is the one you want</p>",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTMLSource(tt.htmlSource)
			if err != nil {
				t.Errorf("PreviousElementSibling(), failed to parse: %v", err)
			}

			div := dom.GetElementsByTagName(doc, "div")[0]
			prevSibling := dom.PreviousElementSibling(div)
			if got := dom.OuterHTML(prevSibling); got != tt.want {
				t.Errorf("PreviousElementSibling() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNextElementSibling(t *testing.T) {
	tests := []struct {
		name       string
		htmlSource string
		want       string
	}{{
		name:       "has no sibling",
		htmlSource: "<div></div>",
		want:       "",
	}, {
		name:       "has directly element sibling",
		htmlSource: "<div></div><p>Hey</p>",
		want:       "<p>Hey</p>",
	}, {
		name:       "has no element sibling",
		htmlSource: "<div></div>I'm your sibling, you know",
		want:       "",
	}, {
		name:       "has distant element sibling",
		htmlSource: "<div></div>I'm your sibling as well <p>only me matter</p>",
		want:       "<p>only me matter</p>",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTMLSource(tt.htmlSource)
			if err != nil {
				t.Errorf("NextElementSibling(), failed to parse: %v", err)
			}

			div := dom.GetElementsByTagName(doc, "div")[0]
			nextSibling := dom.NextElementSibling(div)
			if got := dom.OuterHTML(nextSibling); got != tt.want {
				t.Errorf("NextElementSibling() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAppendChild(t *testing.T) {
	// Child is from inside document
	t.Run("child from existing node", func(t *testing.T) {
		htmlSource := `<div><p>Lonely word</p><span>new friend</span></div>`
		want := `<div><p>Lonely word<span>new friend</span></p></div>`

		doc, err := parseHTMLSource(htmlSource)
		if err != nil {
			t.Errorf("AppendChild(), failed to parse: %v", err)
		}

		div := doc.FirstChild
		p := dom.GetElementsByTagName(div, "p")[0]
		span := dom.GetElementsByTagName(div, "span")[0]

		dom.AppendChild(p, span)
		if got := dom.OuterHTML(div); got != want {
			t.Errorf("AppendChild() = %v, want %v", got, want)
		}
	})

	// Child is new element
	t.Run("child is new element", func(t *testing.T) {
		htmlSource := `<div><p>Lonely word</p><span>new friend</span></div>`
		want := `<div><p>Lonely word<span></span></p><span>new friend</span></div>`

		doc, err := parseHTMLSource(htmlSource)
		if err != nil {
			t.Errorf("AppendChild(), failed to parse: %v", err)
		}

		div := doc.FirstChild
		p := dom.GetElementsByTagName(div, "p")[0]
		newChild := dom.CreateElement("span")

		dom.AppendChild(p, newChild)
		if got := dom.OuterHTML(div); got != want {
			t.Errorf("AppendChild() = %v, want %v", got, want)
		}
	})

	// Parent is void
	t.Run("parent is void", func(t *testing.T) {
		br := dom.CreateElement("br")
		span := dom.CreateElement("span")
		dom.AppendChild(br, span)

		want := "<br/>"
		if got := dom.OuterHTML(br); got != want {
			t.Errorf("AppendChild() = %v, want %v", got, want)
		}
	})
}

func TestPrependChild(t *testing.T) {
	// Child is from inside document
	t.Run("child from existing node", func(t *testing.T) {
		htmlSource := `<div><p>Lonely word</p><span>new friend</span></div>`
		want := `<div><p><span>new friend</span>Lonely word</p></div>`

		doc, err := parseHTMLSource(htmlSource)
		if err != nil {
			t.Errorf("PrependChild(), failed to parse: %v", err)
		}

		div := doc.FirstChild
		p := dom.GetElementsByTagName(div, "p")[0]
		span := dom.GetElementsByTagName(div, "span")[0]

		dom.PrependChild(p, span)
		if got := dom.OuterHTML(div); got != want {
			t.Errorf("PrependChild() = %v, want %v", got, want)
		}
	})

	// Child is new element
	t.Run("child is new element", func(t *testing.T) {
		htmlSource := `<div><p>Lonely word</p><span>new friend</span></div>`
		want := `<div><p><span></span>Lonely word</p><span>new friend</span></div>`

		doc, err := parseHTMLSource(htmlSource)
		if err != nil {
			t.Errorf("PrependChild(), failed to parse: %v", err)
		}

		div := doc.FirstChild
		p := dom.GetElementsByTagName(div, "p")[0]
		newChild := dom.CreateElement("span")

		dom.PrependChild(p, newChild)
		if got := dom.OuterHTML(div); got != want {
			t.Errorf("PrependChild() = %v, want %v", got, want)
		}
	})

	// Parent is void
	t.Run("parent is void", func(t *testing.T) {
		br := dom.CreateElement("br")
		span := dom.CreateElement("span")
		dom.PrependChild(br, span)

		want := "<br/>"
		if got := dom.OuterHTML(br); got != want {
			t.Errorf("PrependChild() = %v, want %v", got, want)
		}
	})
}

func TestReplaceChild(t *testing.T) {
	// new child is from existing element
	t.Run("new child from existing element", func(t *testing.T) {
		htmlSource := `<div><p>Lonely word</p><span>new friend</span></div>`
		want := `<div><span>new friend</span></div>`

		doc, err := parseHTMLSource(htmlSource)
		if err != nil {
			t.Errorf("ReplaceNode(), failed to parse: %v", err)
		}

		div := doc.FirstChild
		p := dom.GetElementsByTagName(div, "p")[0]
		span := dom.GetElementsByTagName(div, "span")[0]

		dom.ReplaceChild(div, span, p)
		if got := dom.OuterHTML(div); got != want {
			t.Errorf("ReplaceNode() = %v, want %v", got, want)
		}
	})

	// new child is new element
	t.Run("new node is new element", func(t *testing.T) {
		htmlSource := `<div><p>Lonely word</p><span>new friend</span></div>`
		want := `<div><span></span><span>new friend</span></div>`

		doc, err := parseHTMLSource(htmlSource)
		if err != nil {
			t.Errorf("ReplaceNode(), failed to parse: %v", err)
		}

		div := doc.FirstChild
		p := dom.GetElementsByTagName(div, "p")[0]
		newChild := dom.CreateElement("span")

		dom.ReplaceChild(div, newChild, p)
		if got := dom.OuterHTML(div); got != want {
			t.Errorf("ReplaceNode() = %v, want %v", got, want)
		}
	})
}

func TestIncludeNode(t *testing.T) {
	htmlSource := `<div>
		<h1></h1><h2></h2><h3></h3>
		<p></p><div></div><img/><img/>
	</div>`

	doc, err := parseHTMLSource(htmlSource)
	if err != nil {
		t.Errorf("IncludeNode(), failed to parse: %v", err)
	}

	allElements := dom.GetElementsByTagName(doc, "*")
	h1 := dom.GetElementsByTagName(doc, "h1")[0]
	h2 := dom.GetElementsByTagName(doc, "h2")[0]
	h3 := dom.GetElementsByTagName(doc, "h3")[0]
	p := dom.GetElementsByTagName(doc, "p")[0]
	div := dom.GetElementsByTagName(doc, "div")[0]
	img := dom.GetElementsByTagName(doc, "img")[0]
	span := dom.CreateElement("span")

	tests := []struct {
		name string
		node *html.Node
		want bool
	}{
		{"h1", h1, true},
		{"h2", h2, true},
		{"h3", h3, true},
		{"p", p, true},
		{"div", div, true},
		{"img", img, true},
		{"span", span, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dom.IncludeNode(allElements, tt.node); got != tt.want {
				t.Errorf("IncludeNode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCloneNode(t *testing.T) {
	tests := []struct {
		name       string
		htmlSource string
		want       string
	}{{
		name:       "single div",
		htmlSource: "<div></div>",
	}, {
		name:       "div with one children",
		htmlSource: "<div><p>Hello</p></div>",
	}, {
		name:       "div with many children",
		htmlSource: "<div><p>Hello</p><p>I'm</p><p>Happy</p></div>",
		want:       "<div><p>Hello</p><p>I&#39;m</p><p>Happy</p></div>",
	}, {
		name:       "div with nested children",
		htmlSource: "<div><p>Hello I'm <span>Happy</span></p></div>",
		want:       "<div><p>Hello I&#39;m <span>Happy</span></p></div>",
	}, {
		name:       "div with mixed text and element node",
		htmlSource: "<div><p>Hello I'm</p>happy</div>",
		want:       "<div><p>Hello I&#39;m</p>happy</div>",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.want
			if want == "" {
				want = tt.htmlSource
			}

			doc, err := parseHTMLSource(tt.htmlSource)
			if err != nil {
				t.Errorf("CloneNode(), failed to parse: %v", err)
			}

			clone := dom.Clone(doc.FirstChild, true)
			if got := dom.OuterHTML(clone); got != want {
				t.Errorf("CloneNode() = %v, want %v", got, want)
			}
		})
	}
}

func TestGetAllNodesWithTag(t *testing.T) {
	htmlSource := `<div>
		<h1></h1>
		<h2></h2><h2></h2>
		<h3></h3><h3></h3><h3></h3>
		<p></p><p></p><p></p><p></p><p></p>
		<div></div><div></div><div></div><div></div><div></div>
		<div><p>Hey it's nested</p></div>
		<div></div>
		<img/><img/><img/><img/><img/><img/><img/><img/>
		<img/><img/><img/><img/>
	</div>`

	doc, err := parseHTMLSource(htmlSource)
	if err != nil {
		t.Errorf("GetAllNodesWithTag(), failed to parse: %v", err)
	}

	tests := []struct {
		name string
		tags []string
		want int
	}{{
		name: "h1",
		tags: []string{"h1"},
		want: 1,
	}, {
		name: "h1,h2",
		tags: []string{"h1", "h2"},
		want: 3,
	}, {
		name: "h1,h2,h3",
		tags: []string{"h1", "h2", "h3"},
		want: 6,
	}, {
		name: "p",
		tags: []string{"p"},
		want: 6,
	}, {
		name: "p,span",
		tags: []string{"p", "span"},
		want: 6,
	}, {
		name: "div,img",
		tags: []string{"div", "img"},
		want: 19,
	}, {
		name: "span",
		tags: []string{"span"},
		want: 0,
	}}

	mainDiv := doc.FirstChild
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(dom.GetAllNodesWithTag(mainDiv, tt.tags...)); got != tt.want {
				t.Errorf("GetAllNodesWithTag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRemoveNodes(t *testing.T) {
	htmlSource := `<div><h1></h1><h1></h1><p></p><img/></div>`

	tests := []struct {
		name   string
		want   string
		filter func(*html.Node) bool
	}{{
		name:   "remove all",
		want:   "<div></div>",
		filter: nil,
	}, {
		name: "remove one tag",
		want: "<div><p></p><img/></div>",
		filter: func(n *html.Node) bool {
			return dom.TagName(n) == "h1"
		},
	}, {
		name: "remove several tags",
		want: "<div><img/></div>",
		filter: func(n *html.Node) bool {
			tag := dom.TagName(n)
			return tag == "h1" || tag == "p"
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTMLSource(htmlSource)
			if err != nil {
				t.Errorf("RemoveNodes(), failed to parse: %v", err)
			}

			mainDiv := doc.FirstChild
			elements := dom.GetElementsByTagName(mainDiv, "*")
			dom.RemoveNodes(elements, tt.filter)

			if got := dom.OuterHTML(mainDiv); got != tt.want {
				t.Errorf("RemoveNodes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetTextContent(t *testing.T) {
	textContent := "XXX"
	expectedResult := "<div>" + textContent + "</div>"

	tests := []struct {
		name       string
		htmlSource string
	}{{
		name:       "single div",
		htmlSource: "<div></div>",
	}, {
		name:       "div with one children",
		htmlSource: "<div><p>Hello</p></div>",
	}, {
		name:       "div with many children",
		htmlSource: "<div><p>Hello</p><p>I'm</p><p>Happy</p></div>",
	}, {
		name:       "div with nested children",
		htmlSource: "<div><p>Hello I'm <span>Happy</span></p></div>",
	}, {
		name:       "div with mixed text and element node",
		htmlSource: "<div><p>Hello I'm</p>happy</div>",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTMLSource(tt.htmlSource)
			if err != nil {
				t.Errorf("SetTextContent(), failed to parse: %v", err)
			}

			div := doc.FirstChild
			dom.SetTextContent(div, textContent)
			if got := dom.OuterHTML(div); got != expectedResult {
				t.Errorf("SetTextContent() = %v, want %v", got, expectedResult)
			}
		})
	}

	// Void element
	t.Run("node is void", func(t *testing.T) {
		br := dom.CreateElement("br")
		dom.SetTextContent(br, "XXX")

		want := "<br/>"
		if got := dom.OuterHTML(br); got != want {
			t.Errorf("SetTextContent() = %v, want %v", got, want)
		}
	})
}

func TestSetInnerHTML(t *testing.T) {
	newHTML := "<p><b>Taaake</b> oooon <em>meee</em></p>"
	expectedResult := "<div>" + newHTML + "</div>"

	tests := []struct {
		name       string
		htmlSource string
	}{{
		name:       "single div",
		htmlSource: "<div></div>",
	}, {
		name:       "div with one children",
		htmlSource: "<div><p>Hello</p></div>",
	}, {
		name:       "div with many children",
		htmlSource: "<div><p>Hello</p><p>I'm</p><p>Happy</p></div>",
	}, {
		name:       "div with nested children",
		htmlSource: "<div><p>Hello I'm <span>Happy</span></p></div>",
	}, {
		name:       "div with mixed text and element node",
		htmlSource: "<div><p>Hello I'm</p>happy</div>",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseHTMLSource(tt.htmlSource)
			if err != nil {
				t.Errorf("SetInnerHTML(), failed to parse: %v", err)
			}

			div := doc.FirstChild
			dom.SetInnerHTML(div, newHTML)
			if got := dom.OuterHTML(div); got != expectedResult {
				t.Errorf("SetInnerHTML() = %v, want %v", got, expectedResult)
			}
		})
	}
}

func parseHTMLSource(htmlSource string) (*html.Node, error) {
	doc, err := html.Parse(strings.NewReader(htmlSource))
	if err != nil {
		return nil, err
	}

	body := dom.GetElementsByTagName(doc, "body")[0]
	return body, nil
}
