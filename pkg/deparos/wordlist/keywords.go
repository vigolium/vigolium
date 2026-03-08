package wordlist

import "strings"

// KeywordFilter filters out common keywords per content type.
type KeywordFilter struct {
	htmlKeywords map[string]struct{}
	cssKeywords  map[string]struct{}
	jsKeywords   map[string]struct{}
	jsonKeywords map[string]struct{}
	xmlKeywords  map[string]struct{}
}

// NewKeywordFilter creates a new KeywordFilter with built-in blacklists.
func NewKeywordFilter() *KeywordFilter {
	return &KeywordFilter{
		htmlKeywords: toSet(htmlBlacklist),
		cssKeywords:  toSet(cssBlacklist),
		jsKeywords:   toSet(jsBlacklist),
		jsonKeywords: toSet(jsonBlacklist),
		xmlKeywords:  toSet(xmlBlacklist),
	}
}

// IsKeyword returns true if the word is a keyword for the given content type.
func (f *KeywordFilter) IsKeyword(word string, contentType ContentType) bool {
	lower := strings.ToLower(word)

	switch contentType {
	case ContentTypeHTML:
		_, ok := f.htmlKeywords[lower]
		return ok
	case ContentTypeCSS:
		_, ok := f.cssKeywords[lower]
		return ok
	case ContentTypeJavaScript:
		_, ok := f.jsKeywords[lower]
		return ok
	case ContentTypeJSON:
		_, ok := f.jsonKeywords[lower]
		return ok
	case ContentTypeXML:
		_, ok := f.xmlKeywords[lower]
		return ok
	default:
		return false
	}
}

func toSet(words []string) map[string]struct{} {
	set := make(map[string]struct{}, len(words))
	for _, w := range words {
		set[strings.ToLower(w)] = struct{}{}
	}
	return set
}

// HTML blacklist - common tags, attributes, and values
var htmlBlacklist = []string{
	// Document structure
	"html", "head", "body", "title", "meta", "link", "base",
	// Sectioning
	"header", "footer", "nav", "main", "section", "article", "aside",
	"div", "span", "p", "br", "hr",
	// Headings
	"h1", "h2", "h3", "h4", "h5", "h6",
	// Text content
	"pre", "code", "blockquote", "cite", "abbr", "address",
	"strong", "em", "small", "mark", "del", "ins", "sub", "sup",
	// Lists
	"ul", "ol", "li", "dl", "dt", "dd",
	// Tables
	"table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption", "colgroup", "col",
	// Forms
	"form", "input", "button", "select", "option", "optgroup", "textarea", "label", "fieldset", "legend", "datalist", "output",
	// Media
	"img", "picture", "figure", "figcaption", "video", "audio", "source", "track", "canvas", "svg", "iframe",
	// Scripting
	"script", "noscript", "template", "style",
	// Interactive
	"details", "summary", "dialog", "menu",
	// Common attributes
	"class", "id", "href", "src", "alt", "title", "name", "value", "type", "placeholder",
	"action", "method", "target", "rel", "role", "aria",
	"width", "height", "style", "data",
	// Event handlers
	"onclick", "onload", "onsubmit", "onchange", "onmouseover", "onmouseout", "onfocus", "onblur", "onerror",
	// Common values
	"true", "false", "null", "undefined",
	"submit", "reset", "button", "text", "password", "email", "number", "checkbox", "radio", "file", "hidden",
	"get", "post",
	// ARIA
	"aria-label", "aria-hidden", "aria-expanded", "aria-controls", "aria-describedby",
}

// CSS blacklist - properties, values, and units
var cssBlacklist = []string{
	// Box model
	"display", "position", "float", "clear",
	"width", "height", "min-width", "max-width", "min-height", "max-height",
	"margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
	"padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
	"border", "border-top", "border-right", "border-bottom", "border-left",
	"border-width", "border-style", "border-color", "border-radius",
	// Positioning
	"top", "right", "bottom", "left", "z-index",
	"absolute", "relative", "fixed", "sticky", "static",
	// Flexbox
	"flex", "flex-direction", "flex-wrap", "flex-flow", "flex-grow", "flex-shrink", "flex-basis",
	"justify-content", "align-items", "align-content", "align-self",
	// Grid
	"grid", "grid-template", "grid-template-columns", "grid-template-rows", "grid-area", "grid-gap",
	// Typography
	"font", "font-family", "font-size", "font-weight", "font-style",
	"text", "text-align", "text-decoration", "text-transform", "text-indent",
	"line-height", "letter-spacing", "word-spacing", "white-space",
	// Colors and background
	"color", "background", "background-color", "background-image", "background-position", "background-size", "background-repeat",
	"opacity", "visibility",
	// Display values
	"none", "block", "inline", "inline-block", "flex", "grid", "table", "table-cell", "table-row",
	// Common values
	"auto", "inherit", "initial", "unset", "normal", "hidden", "visible", "scroll", "nowrap",
	"solid", "dashed", "dotted", "double",
	"center", "left", "right", "justify", "start", "end",
	"bold", "italic", "underline", "uppercase", "lowercase", "capitalize",
	// Units (often appear as words)
	"px", "em", "rem", "vh", "vw", "vmin", "vmax", "pt", "pc", "cm", "mm", "in", "ch", "ex",
	// Functions
	"rgb", "rgba", "hsl", "hsla", "url", "calc", "var", "linear-gradient", "radial-gradient",
	// Pseudo-classes/elements
	"hover", "active", "focus", "visited", "before", "after", "first-child", "last-child", "nth-child",
	// Vendor prefixes
	"webkit", "moz", "ms", "o",
	// Transitions and animations
	"transition", "transform", "animation", "keyframes",
	// Other common
	"overflow", "cursor", "pointer", "content", "important", "media", "screen", "print",
}

// JavaScript blacklist - keywords, built-ins, and common patterns
var jsBlacklist = []string{
	// Keywords
	"function", "var", "let", "const", "return", "if", "else", "for", "while", "do",
	"switch", "case", "break", "continue", "default", "throw", "try", "catch", "finally",
	"new", "delete", "typeof", "instanceof", "void", "in", "of", "with",
	// Class-related
	"class", "extends", "constructor", "super", "this", "static", "get", "set",
	// Modules
	"import", "export", "from", "as", "default",
	// Async
	"async", "await", "yield", "promise",
	// Literals
	"true", "false", "null", "undefined", "nan", "infinity",
	// Built-in objects
	"object", "array", "string", "number", "boolean", "symbol", "bigint",
	"function", "math", "date", "regexp", "error", "map", "set", "weakmap", "weakset",
	"promise", "proxy", "reflect", "json", "intl", "arraybuffer", "dataview",
	"uint8array", "int8array", "uint16array", "int16array", "uint32array", "int32array",
	"float32array", "float64array",
	// Global functions
	"parseint", "parsefloat", "isnan", "isfinite", "eval", "decodeuri", "encodeuri",
	"decodeuricomponent", "encodeuricomponent",
	// Console
	"console", "log", "error", "warn", "info", "debug", "trace", "assert", "table", "dir",
	// DOM/Browser
	"document", "window", "navigator", "location", "history", "screen", "event",
	"element", "node", "nodelist", "htmlelement", "htmlcollection",
	"getelementbyid", "getelementsbytagname", "getelementsbyclassname",
	"queryselector", "queryselectorall", "createelement", "appendchild", "removechild",
	"addeventlistener", "removeeventlistener", "dispatchevent",
	"innerhtml", "outerhtml", "innertext", "textcontent", "classlist", "dataset",
	"style", "getattribute", "setattribute", "removeattribute", "hasattribute",
	// Timers
	"settimeout", "setinterval", "cleartimeout", "clearinterval", "requestanimationframe",
	// Array methods
	"prototype", "length", "push", "pop", "shift", "unshift", "slice", "splice", "concat",
	"join", "reverse", "sort", "indexof", "lastindexof", "includes", "find", "findindex",
	"filter", "map", "reduce", "reduceright", "foreach", "some", "every", "flat", "flatmap",
	"fill", "copywithin", "entries", "keys", "values",
	// Object methods
	"tostring", "valueof", "hasownproperty", "isprototypeof", "propertyisenumerable",
	"assign", "create", "defineproperties", "defineproperty", "freeze", "seal",
	"getownpropertydescriptor", "getownpropertynames", "getownpropertysymbols",
	"getprototypeof", "setprototypeof", "isextensible", "isfrozen", "issealed",
	// String methods
	"charat", "charcodeat", "codePointat", "concat", "endswith", "startswith",
	"includes", "indexof", "lastindexof", "localecompare", "match", "matchall",
	"normalize", "padend", "padstart", "repeat", "replace", "replaceall", "search",
	"slice", "split", "substring", "substr", "tolocalelowercase", "tolocaleuppercase",
	"tolowercase", "touppercase", "trim", "trimend", "trimstart",
	// Common variable names
	"data", "result", "response", "request", "callback", "handler", "options", "config",
	"params", "args", "props", "state", "context", "value", "index", "item", "key",
	"name", "type", "id", "url", "path", "body", "headers", "method", "status",
	// Common function names
	"init", "setup", "start", "stop", "run", "execute", "process", "handle",
	"fetch", "send", "receive", "load", "save", "update", "render", "display",
	"click", "submit", "change", "input", "focus", "blur", "resize", "scroll",
}

// JSON blacklist - minimal since JSON keys/values are usually meaningful
var jsonBlacklist = []string{
	"true", "false", "null",
}

// XML blacklist - common elements and attributes
var xmlBlacklist = []string{
	"xml", "version", "encoding", "standalone",
	"xmlns", "xsi", "xsd", "type", "nil",
	"schema", "element", "attribute", "complextype", "simpletype", "sequence", "choice", "all",
	"annotation", "documentation", "appinfo",
	"restriction", "extension", "enumeration", "pattern", "minlength", "maxlength",
	"mininclusive", "maxinclusive", "minexclusive", "maxexclusive",
	"cdata", "pcdata", "entity", "notation",
}
