package xss_light_scanner

// ReflectionContext represents the context where user input is reflected
type ReflectionContext int

const (
	HTMLGeneric ReflectionContext = iota // 0: Reflection in HTML text node
	// ID 1 skipped
	HTMLTagCloseAndInject              // 2: Reflection in tag name
	HTMLAttributeName                  // 3: Reflection in attribute name
	HTMLAttributeValueDQBreakout       // 4: Reflection in double-quoted attribute
	HTMLAttributeValueSQBreakout       // 5: Reflection in single-quoted attribute
	HTMLAttributeValueBTBreakout       // 6: Reflection in backtick-quoted attribute
	HTMLAttributeValueUnquotedBreakout // 7: Reflection in unquoted attribute
	JSInURLAttributeDQ                 // 8: JS in double-quoted URL attribute
	JSInURLAttributeSQ                 // 9: JS in single-quoted URL attribute
	JSInURLAttributeBT                 // 10: JS in backtick-quoted URL attribute
	JSInUnquotedURLAttribute           // 11: JS in unquoted URL attribute
	JSInEventHandlerDQ                 // 12: JS in double-quoted event handler
	JSInEventHandlerSQ                 // 13: JS in single-quoted event handler
	JSInEventHandlerBT                 // 14: JS in backtick-quoted event handler
	JSInEventHandlerUnquoted           // 15: JS in unquoted event handler
	JSStringDQBreakout                 // 16: Reflection in double-quoted JS string
	JSStringSQBreakout                 // 17: Reflection in single-quoted JS string
	JSCodeStatement                    // 18: Reflection directly in JS code
	XMLGeneric                         // 19: Reflection in XML text node
	HTMLAfterXMPClose                  // 20: Reflection inside <xmp> tag
	HTMLAfterNoscriptClose             // 21: Reflection inside <noscript> tag
	HTMLAfterTitleClose                // 22: Reflection inside <title> tag
	HTMLCommentBreakout                // 23: Reflection in HTML comment
	JSLineComment                      // 24: Reflection in JS line comment
	JSBlockComment                     // 25: Reflection in JS block comment
	JSTemplateLiteral                  // 26: Reflection in template literal
)

// RiskLevel represents the severity of the context
type RiskLevel int

const (
	RiskMedium RiskLevel = iota
	RiskHigh
	RiskCritical
)

func (r RiskLevel) String() string {
	switch r {
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	case RiskCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ContextInfo contains metadata about a reflection context
type ContextInfo struct {
	ID          int
	DisplayName string
	RiskLevel   RiskLevel
	Description string
}

var contextInfoMap = map[ReflectionContext]ContextInfo{
	HTMLGeneric:                        {0, "HTML Body", RiskHigh, "Reflection in HTML text node"},
	HTMLTagCloseAndInject:              {2, "HTML Tag Name", RiskHigh, "Reflection in tag name"},
	HTMLAttributeName:                  {3, "HTML Attribute Name", RiskHigh, "Reflection in attribute name"},
	HTMLAttributeValueDQBreakout:       {4, "HTML Attribute Value (Double Quote)", RiskHigh, "Reflection in double-quoted attribute"},
	HTMLAttributeValueSQBreakout:       {5, "HTML Attribute Value (Single Quote)", RiskHigh, "Reflection in single-quoted attribute"},
	HTMLAttributeValueBTBreakout:       {6, "HTML Attribute Value (Backtick)", RiskHigh, "Reflection in backtick-quoted attribute"},
	HTMLAttributeValueUnquotedBreakout: {7, "HTML Attribute Value (Unquoted)", RiskHigh, "Reflection in unquoted attribute"},
	JSInURLAttributeDQ:                 {8, "JavaScript in URL Attribute (Double Quote)", RiskHigh, "Reflection in double-quoted URL attribute"},
	JSInURLAttributeSQ:                 {9, "JavaScript in URL Attribute (Single Quote)", RiskHigh, "Reflection in single-quoted URL attribute"},
	JSInURLAttributeBT:                 {10, "JavaScript in URL Attribute (Backtick)", RiskHigh, "Reflection in backtick-quoted URL attribute"},
	JSInUnquotedURLAttribute:           {11, "JavaScript in URL Attribute (Unquoted)", RiskHigh, "Reflection in unquoted URL attribute"},
	JSInEventHandlerDQ:                 {12, "JavaScript in Event Handler (Double Quote)", RiskHigh, "Reflection in double-quoted event handler"},
	JSInEventHandlerSQ:                 {13, "JavaScript in Event Handler (Single Quote)", RiskHigh, "Reflection in single-quoted event handler"},
	JSInEventHandlerBT:                 {14, "JavaScript in Event Handler (Backtick)", RiskHigh, "Reflection in backtick-quoted event handler"},
	JSInEventHandlerUnquoted:           {15, "JavaScript in Event Handler (Unquoted)", RiskHigh, "Reflection in unquoted event handler"},
	JSStringDQBreakout:                 {16, "JavaScript String (Double Quote)", RiskHigh, "Reflection in double-quoted JS string"},
	JSStringSQBreakout:                 {17, "JavaScript String (Single Quote)", RiskHigh, "Reflection in single-quoted JS string"},
	JSCodeStatement:                    {18, "JavaScript Code", RiskCritical, "Reflection directly in JavaScript code"},
	XMLGeneric:                         {19, "XML Body", RiskMedium, "Reflection in XML text node"},
	HTMLAfterXMPClose:                  {20, "HTML After </xmp> Close", RiskHigh, "Reflection inside <xmp> tag"},
	HTMLAfterNoscriptClose:             {21, "HTML After </noscript> Close", RiskHigh, "Reflection inside <noscript> tag"},
	HTMLAfterTitleClose:                {22, "HTML After </title> Close", RiskHigh, "Reflection inside <title> tag"},
	HTMLCommentBreakout:                {23, "HTML Comment", RiskMedium, "Reflection in HTML comment"},
	JSLineComment:                      {24, "JavaScript Line Comment", RiskMedium, "Reflection in JS line comment"},
	JSBlockComment:                     {25, "JavaScript Block Comment", RiskMedium, "Reflection in JS block comment"},
	JSTemplateLiteral:                  {26, "JavaScript Template Literal", RiskHigh, "Reflection in template literal"},
}

// GetInfo returns the metadata for this context
func (c ReflectionContext) GetInfo() ContextInfo {
	if info, ok := contextInfoMap[c]; ok {
		return info
	}
	return ContextInfo{
		ID:          -1,
		DisplayName: "Unknown",
		RiskLevel:   RiskMedium,
		Description: "Unknown context",
	}
}

func (c ReflectionContext) String() string {
	return c.GetInfo().DisplayName
}

// FromID returns the ReflectionContext for a given ID
func FromID(id int) ReflectionContext {
	for ctx, info := range contextInfoMap {
		if info.ID == id {
			return ctx
		}
	}
	return HTMLGeneric
}
