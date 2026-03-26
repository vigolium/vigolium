package core

import "fmt"

// ReflectionContext defines the specific context where a reflection occurs,
type ReflectionContext byte

const (
	// HTML Contexts
	ReflectionContextHTMLGeneric           ReflectionContext = 0  // General HTML, often implies direct tag injection
	ReflectionContextXMLGeneric            ReflectionContext = 19 // General XML context
	ReflectionContextHTMLTagCloseAndInject ReflectionContext = 2  // Closing an open tag and injecting new HTML/JS, also if canary in tag name

	ReflectionContextHTMLAttributeName                  ReflectionContext = 3  // Canary in HTML attribute name
	ReflectionContextHTMLAttributeValueDQBreakout       ReflectionContext = 4  // Breaking out of a double-quoted HTML attribute value
	ReflectionContextHTMLAttributeValueSQBreakout       ReflectionContext = 5  // Breaking out of a single-quoted HTML attribute value
	ReflectionContextHTMLAttributeValueBTBreakout       ReflectionContext = 6  // Breaking out of a backtick-quoted HTML attribute value
	ReflectionContextHTMLAttributeValueUnquotedBreakout ReflectionContext = 7  // Injecting into an unquoted HTML attribute value
	ReflectionContextHTMLCommentBreakout                ReflectionContext = 23 // Breaking out of an HTML comment

	// JavaScript in HTML Attribute Contexts (e.g., href="javascript:...")
	ReflectionContextJSInURLAttributeDQ       ReflectionContext = 8  // JS in double-quoted URL-like attribute
	ReflectionContextJSInURLAttributeSQ       ReflectionContext = 9  // JS in single-quoted URL-like attribute
	ReflectionContextJSInURLAttributeBT       ReflectionContext = 10 // JS in backtick-quoted URL-like attribute
	ReflectionContextJSInUnquotedURLAttribute ReflectionContext = 11 // JS in unquoted URL-like attribute

	// JavaScript in on-event Handlers / General Attribute JS context
	ReflectionContextJSInEventHandlerDQ ReflectionContext = 12 // JS in double-quoted event handler
	ReflectionContextJSInEventHandlerSQ ReflectionContext = 13 // JS in single-quoted event handler
	ReflectionContextJSInEventHandlerBT ReflectionContext = 14 // JS in backtick-quoted event handler
	ReflectionContextJSInHTMLTagGeneric ReflectionContext = 15 // JS injection in a generic HTML tag context

	// JavaScript String/Literal Contexts
	ReflectionContextJSStringDQBreakout ReflectionContext = 16 // Breaking out of a JS double-quoted string
	ReflectionContextJSStringSQBreakout ReflectionContext = 17 // Breaking out of a JS single-quoted string

	// JavaScript Code Context
	ReflectionContextJSCodeStatement ReflectionContext = 18 // Injecting a new JS statement

	// Special HTML Tag Contexts (for breaking out)
	ReflectionContextHTMLAfterXMPClose      ReflectionContext = 20 // Injection after </xmp>
	ReflectionContextHTMLAfterNoscriptClose ReflectionContext = 21 // Injection after </noscript>
	ReflectionContextHTMLAfterTitleClose    ReflectionContext = 22 // Injection after </title>

	// JavaScript Comment Contexts
	ReflectionContextJSLineComment  ReflectionContext = 24 // JS line comment (//)
	ReflectionContextJSBlockComment ReflectionContext = 25 // JS block comment (/* */)

	// ReflectionContextUndefined is for any byte value not explicitly mapped.
	ReflectionContextUndefined ReflectionContext = 255 // Using a distinct value for unmapped cases
)

// String returns a string representation of the ReflectionContext.
func (rc ReflectionContext) String() string {
	switch rc {
	case ReflectionContextHTMLGeneric:
		return "Html General"
	case ReflectionContextXMLGeneric:
		return "Xml General"
	case ReflectionContextHTMLTagCloseAndInject:
		return "Html Tag Close And Inject Or In Tag Name"
	case ReflectionContextHTMLAttributeName:
		return "Html Attribute Name"
	case ReflectionContextHTMLAttributeValueDQBreakout:
		return "Html Attribute Value Double Quote Breakout"
	case ReflectionContextHTMLAttributeValueSQBreakout:
		return "Html Attribute Value Single Quote Breakout"
	case ReflectionContextHTMLAttributeValueBTBreakout:
		return "Html Attribute Value Backtick Breakout"
	case ReflectionContextHTMLAttributeValueUnquotedBreakout:
		return "Html Attribute Value Unquoted Breakout"
	case ReflectionContextHTMLCommentBreakout:
		return "Html Comment Breakout"
	case ReflectionContextJSInURLAttributeDQ:
		return "Javascript In Url Attribute Double Quote"
	case ReflectionContextJSInURLAttributeSQ:
		return "Javascript In Url Attribute Single Quote"
	case ReflectionContextJSInURLAttributeBT:
		return "Javascript In Url Attribute Backtick"
	case ReflectionContextJSInUnquotedURLAttribute:
		return "Javascript In Unquoted Url Attribute"
	case ReflectionContextJSInEventHandlerDQ:
		return "Javascript In Event Handler Double Quote"
	case ReflectionContextJSInEventHandlerSQ:
		return "Javascript In Event Handler Single Quote"
	case ReflectionContextJSInEventHandlerBT:
		return "Javascript In Event Handler Backtick"
	case ReflectionContextJSInHTMLTagGeneric:
		return "Javascript In Html Tag Generic"
	case ReflectionContextJSStringDQBreakout:
		return "Javascript String Double Quote Breakout"
	case ReflectionContextJSStringSQBreakout:
		return "Javascript String Single Quote Breakout"
	case ReflectionContextJSCodeStatement:
		return "Javascript Code Statement"
	case ReflectionContextHTMLAfterXMPClose:
		return "Html After Xmp Close"
	case ReflectionContextHTMLAfterNoscriptClose:
		return "Html After Noscript Close"
	case ReflectionContextHTMLAfterTitleClose:
		return "Html After Title Close"
	case ReflectionContextJSLineComment:
		return "Javascript Line Comment"
	case ReflectionContextJSBlockComment:
		return "Javascript Block Comment"
	default:
		return fmt.Sprintf("Unknown Reflection Context Byte %d", byte(rc))
	}
}
