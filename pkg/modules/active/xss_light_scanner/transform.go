package xss_light_scanner

// TransformType classifies how input was modified in response
type TransformType string

const (
	TransformPassed          TransformType = "passed"           // Input appears unchanged
	TransformRemoved         TransformType = "removed"          // Input character is gone
	TransformBackslashEsc    TransformType = "backslash_esc"    // ' → \'
	TransformDoubleBackslash TransformType = "double_backslash" // \' → \\' (exploitable!)
	TransformTripleBackslash TransformType = "triple_backslash" // \' → \\\'
	TransformHTMLEncoded     TransformType = "html_encoded"     // ' → &#39; or &apos;
	TransformURLEncoded      TransformType = "url_encoded"      // ' → %27
	TransformUnknown         TransformType = "unknown"          // Unrecognized transformation
)

// IsExploitable returns true if this transform allows breakout
func (t TransformType) IsExploitable() bool {
	switch t {
	case TransformPassed, TransformDoubleBackslash:
		return true
	default:
		return false
	}
}

// CharTransform records how a specific character/sequence was transformed
type CharTransform struct {
	InputChar byte          // Original char we sent (e.g., ')
	InputSeq  string        // Full input sequence if multi-char (e.g., "\'")
	OutputSeq string        // What appeared in response (e.g., "\\'")
	Transform TransformType // Classification of the transformation
	SegBefore string        // Segment before the char for pattern matching
	SegAfter  string        // Segment after the char for pattern matching
}

// EscapeAnalysis aggregates all transform data for a reflection point
type EscapeAnalysis struct {
	Context         ReflectionContext         // Detected context
	Transforms      map[string]*CharTransform // Key is InputSeq (e.g., "'" or "\'")
	ResponseSnippet string                    // Relevant portion of response
	PayloadSent     string                    // The payload that produced this analysis
	Offset          int                       // Offset in response where reflection found
	IsAtURLStart    bool                      // True if reflection is at start of URL attribute value
}

// NewEscapeAnalysis creates a new EscapeAnalysis
func NewEscapeAnalysis(ctx ReflectionContext, offset int) *EscapeAnalysis {
	return &EscapeAnalysis{
		Context:    ctx,
		Transforms: make(map[string]*CharTransform),
		Offset:     offset,
	}
}

// GetTransform returns transform for a specific input sequence
func (ea *EscapeAnalysis) GetTransform(inputSeq string) *CharTransform {
	return ea.Transforms[inputSeq]
}

// GetCharTransform returns transform for a single character
func (ea *EscapeAnalysis) GetCharTransform(ch byte) *CharTransform {
	return ea.Transforms[string(ch)]
}

// SetTransform sets the transform for an input sequence
func (ea *EscapeAnalysis) SetTransform(inputSeq string, transform *CharTransform) {
	ea.Transforms[inputSeq] = transform
}

// HasUnescaped returns true if char passed through unchanged
func (ea *EscapeAnalysis) HasUnescaped(ch byte) bool {
	t := ea.GetCharTransform(ch)
	return t != nil && t.Transform == TransformPassed
}

// HasBackslashEscaped returns true if char was backslash-escaped
func (ea *EscapeAnalysis) HasBackslashEscaped(ch byte) bool {
	t := ea.GetCharTransform(ch)
	return t != nil && t.Transform == TransformBackslashEsc
}

// HasDoubleBackslash returns true if backslash-escape was itself escaped
func (ea *EscapeAnalysis) HasDoubleBackslash(inputSeq string) bool {
	t := ea.GetTransform(inputSeq)
	return t != nil && t.Transform == TransformDoubleBackslash
}

// HasScriptBreakout returns true if </script> sequence can pass through
// This allows breaking out of any JS context inside <script> tags
func (ea *EscapeAnalysis) HasScriptBreakout() bool {
	return ea.HasUnescaped('<') && ea.HasUnescaped('/') && ea.HasUnescaped('>')
}

// HasHTMLEncodedQuote returns true if the context quote was HTML-encoded
// This is exploitable in event handlers because browser decodes HTML entities
func (ea *EscapeAnalysis) HasHTMLEncodedQuote(quoteChar byte) bool {
	t := ea.GetCharTransform(quoteChar)
	return t != nil && t.Transform == TransformHTMLEncoded
}

// IsExploitable checks if this reflection point is exploitable based on context and transforms
func (ea *EscapeAnalysis) IsExploitable() bool {
	switch ea.Context {
	// Event handlers: Browser decodes HTML entities before JS execution
	// So HTML-encoded quotes ARE exploitable in this context
	case JSInEventHandlerDQ:
		if ea.HasUnescaped('"') || ea.HasHTMLEncodedQuote('"') {
			return true
		}
		return ea.HasScriptBreakout()

	case JSInEventHandlerSQ:
		if ea.HasUnescaped('\'') || ea.HasHTMLEncodedQuote('\'') {
			return true
		}
		return ea.HasScriptBreakout()

	case JSInEventHandlerBT:
		if ea.HasUnescaped('`') || ea.HasHTMLEncodedQuote('`') {
			return true
		}
		return ea.HasScriptBreakout()

	case JSInEventHandlerUnquoted:
		return ea.HasUnescaped(' ') || ea.HasUnescaped('>') || ea.HasScriptBreakout()

	// Direct code execution
	case JSCodeStatement:
		return true

	// URL attributes - exploitable only if at URL start OR can break out of quote
	case JSInURLAttributeDQ, JSInURLAttributeSQ, JSInURLAttributeBT, JSInUnquotedURLAttribute:
		// At URL start -> can inject javascript: protocol
		if ea.IsAtURLStart {
			return true
		}
		// Not at start -> need quote breakout
		return ea.hasURLAttributeBreakout()

	// JS string contexts - exploitable via:
	// 1. Quote breakout: '-alert(1)-'
	// 2. Double-backslash bypass: \' → \\' (quote unescaped)
	// 3. Script tag breakout: </script><svg/onload=...>
	case JSStringSQBreakout:
		if ea.HasUnescaped('\'') {
			return true
		}
		if ea.HasDoubleBackslash("\\'") {
			return true
		}
		// Script tag breakout - close script and inject HTML
		if ea.HasScriptBreakout() {
			return true
		}
		return false

	case JSStringDQBreakout:
		if ea.HasUnescaped('"') {
			return true
		}
		if ea.HasDoubleBackslash("\\\"") {
			return true
		}
		if ea.HasScriptBreakout() {
			return true
		}
		return false

	case JSTemplateLiteral:
		// Backtick breakout
		if ea.HasUnescaped('`') {
			return true
		}
		if ea.HasDoubleBackslash("\\`") {
			return true
		}
		// Template injection: ${...}
		if ea.HasUnescaped('$') && ea.HasUnescaped('{') && ea.HasUnescaped('}') {
			return true
		}
		// Script tag breakout
		if ea.HasScriptBreakout() {
			return true
		}
		return false

	// HTML contexts
	case HTMLGeneric, HTMLTagCloseAndInject, HTMLAfterXMPClose, HTMLAfterNoscriptClose, HTMLAfterTitleClose, XMLGeneric:
		return ea.HasUnescaped('<') && ea.HasUnescaped('>')

	case HTMLAttributeValueDQBreakout:
		return ea.HasUnescaped('"')

	case HTMLAttributeValueSQBreakout:
		return ea.HasUnescaped('\'')

	case HTMLAttributeValueBTBreakout:
		return ea.HasUnescaped('`')

	case HTMLAttributeValueUnquotedBreakout:
		return ea.HasUnescaped(' ') || ea.HasUnescaped('>')

	case HTMLAttributeName:
		return ea.HasUnescaped('=') && (ea.HasUnescaped(' ') || ea.HasUnescaped('>'))

	case HTMLCommentBreakout:
		return ea.HasUnescaped('>') && ea.HasUnescaped('-')

	case JSLineComment:
		return ea.HasUnescaped('\n') || ea.HasUnescaped('\r')

	case JSBlockComment:
		return ea.HasUnescaped('*') && ea.HasUnescaped('/')

	default:
		return false
	}
}

// hasURLAttributeBreakout checks for quote breakout in URL attributes
func (ea *EscapeAnalysis) hasURLAttributeBreakout() bool {
	switch ea.Context {
	case JSInURLAttributeDQ:
		return ea.HasUnescaped('"')
	case JSInURLAttributeSQ:
		return ea.HasUnescaped('\'')
	case JSInURLAttributeBT:
		return ea.HasUnescaped('`')
	case JSInUnquotedURLAttribute:
		return ea.HasUnescaped(' ') || ea.HasUnescaped('>')
	}
	return false
}
