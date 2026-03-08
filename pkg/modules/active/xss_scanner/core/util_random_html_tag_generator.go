package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// standardHtmlTagBlocklist corresponds to private static final List<String> a in d8v.java
var standardHtmlTagBlocklist = []string{
	"a", "abbr", "acronym", "address", "applet", "area", "article", "aside", "audio",
	"b", "base", "basefont", "bdi", "bdo", "bgsound", "big", "blink", "blockquote",
	"body", "br", "button", "canvas", "caption", "center", "cite", "code", "col",
	"colgroup", "command", "comment", "content", "custom", "data", "datalist", "dd",
	"decorator", "del", "details", "dfn", "dialog", "dir", "div", "dl", "dt",
	"element", "em", "embed", "fieldset", "figcaption", "figure", "font", "footer",
	"form", "frame", "frameset", "h1", "h2", "h3", "h4", "h5", "h6", "head",
	"header", "hgroup", "hn", "hr", "html", "i", "iframe", "img", "input", "ins",
	"isindex", "kbd", "keygen", "label", "legend", "li", "link", "listing", "main",
	"map", "mark", "marquee", "media", "menu", "menuitem", "meta", "meter", "nav",
	"noscript", "nobr", "noframes", "object", "ol", "optgroup", "option",
	"output", "p", "param", "picture", "plaintext", "pre", "progress", "q", "rp", "rt",
	"ruby", "s", "samp", "script", "section", "select", "shadow", "small", "source",
	"spacer", "span", "strike", "strong", "style", "sub", "summary", "sup", "tbody",
	"tfoot", "thead", "table", "td", "template", "textarea", "th", "time", "title",
	"tr", "track", "tt", "u", "ul", "var", "video", "wbr", "xml", "xmp",
}

// RandomHTMLTagGenerator implements the Fen interface.
// Original Java class: d8v
type RandomHTMLTagGenerator struct {
	randomProvider *utils.RandomGenerator // Corresponds to private final net.portswigger.ou b;
}

// NewRandomHTMLTagGenerator creates a new instance of D8v.
// Original Java constructor: d8v(net.portswigger.ou var1)
func NewRandomHTMLTagGenerator(randomProvider *utils.RandomGenerator) *RandomHTMLTagGenerator {
	return &RandomHTMLTagGenerator{randomProvider: randomProvider}
}

// IsRandomTextProvider marker method for Fen interface.
func (d *RandomHTMLTagGenerator) IsRandomTextProvider() {}

// GenerateText is the Go equivalent of public String a(int var1) in d8v.java
func (d *RandomHTMLTagGenerator) GenerateText(length int) string {
	var generatedTagName string
	for {
		// var2 = this.b.b().c().a(var1);
		// this.b -> d.valBNetOu
		// .b() -> B_n7()
		// .c() -> C_useAlpha()
		// .a(var1) -> A_build(length)
		if d.randomProvider == nil || d.randomProvider.GetStringBuilder() == nil ||
			d.randomProvider.GetStringBuilder().WithAlphaChars() == nil {
			// Handle nil chain, perhaps return a default or panic based on desired strictness
			// For now, returning an empty string or a fixed default might be suitable for a stub
			generatedTagName = "defaulttag" // Fallback if ou chain is broken
		} else {
			generatedTagName = d.randomProvider.GetStringBuilder().WithAlphaChars().Build(length)
		}

		if !d.isStandardTag(generatedTagName) {
			break
		}
	}
	return generatedTagName
}

// isStandardTag is the Go equivalent of private boolean a(String var1) in d8v.java
func (d *RandomHTMLTagGenerator) isStandardTag(tagName string) bool {
	lowercaseTagName := strings.ToLower(tagName)
	for _, blockedTag := range standardHtmlTagBlocklist {
		if blockedTag == lowercaseTagName {
			return true
		}
	}
	return false
}
