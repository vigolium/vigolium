package core

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

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

// RandomHTMLTagGenerator implements the RandomTextProvider interface.
type RandomHTMLTagGenerator struct {
	randomProvider *utils.RandomGenerator
}

// NewRandomHTMLTagGenerator creates a new RandomHTMLTagGenerator instance.
func NewRandomHTMLTagGenerator(randomProvider *utils.RandomGenerator) *RandomHTMLTagGenerator {
	return &RandomHTMLTagGenerator{randomProvider: randomProvider}
}

// IsRandomTextProvider marker method for the RandomTextProvider interface.
func (d *RandomHTMLTagGenerator) IsRandomTextProvider() {}

func (d *RandomHTMLTagGenerator) GenerateText(length int) string {
	var generatedTagName string
	for {
		if d.randomProvider == nil || d.randomProvider.GetStringBuilder() == nil ||
			d.randomProvider.GetStringBuilder().WithAlphaChars() == nil {
			// Handle nil chain, perhaps return a default or panic based on desired strictness
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

func (d *RandomHTMLTagGenerator) isStandardTag(tagName string) bool {
	lowercaseTagName := strings.ToLower(tagName)
	for _, blockedTag := range standardHtmlTagBlocklist {
		if blockedTag == lowercaseTagName {
			return true
		}
	}
	return false
}
