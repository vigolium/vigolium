package httpmsg

// xml_parser.go - XML parameter extraction

import (
	"bytes"
	"strings"
)

// XMLElementType represents the type of XML element during parsing.
const (
	XMLElementTypeOpen      byte = 0 // Opening tag: <tag>
	XMLElementTypeClose     byte = 1 // Closing tag: </tag>
	XMLElementTypeComment   byte = 2 // Comment: <!-- -->
	XMLElementTypeText      byte = 3 // Text content between tags
	XMLElementTypeSelfClose byte = 4 // Self-closing tag: <tag/> or <?xml?>
)

// XMLQuoteType represents the type of quote used for attribute values.
const (
	XMLQuoteDouble   byte = 0 // Double quote: "
	XMLQuoteSingle   byte = 1 // Single quote: '
	XMLQuoteBacktick byte = 2 // Backtick: `
	XMLQuoteNone     byte = 3 // No quote (unquoted value)
)

// XMLElement represents a parsed XML element with its attributes.
type XMLElement struct {
	Type       byte           // Element type (open, close, text, etc.)
	TagName    string         // Element tag name (lowercase)
	TagStart   int            // Byte offset where tag name starts
	TagEnd     int            // Byte offset where tag name ends
	Start      int            // Byte offset where element starts (at '<')
	End        int            // Byte offset where element ends (after '>')
	Text       string         // Text content (for text nodes)
	Attributes []XMLAttribute // Element attributes
}

// XMLAttribute represents an XML attribute with its value and position.
type XMLAttribute struct {
	Name       string // Attribute name
	Value      string // Attribute value (decoded)
	NameStart  int    // Byte offset where name starts
	NameEnd    int    // Byte offset where name ends
	ValueStart int    // Byte offset where value starts (excluding quotes)
	ValueEnd   int    // Byte offset where value ends (excluding quotes)
	QuoteType  byte   // Quote type used (0=", 1=', 2=`, 3=none)
}

// ParseXMLBody parses XML body and extracts parameters.
//
// Algorithm:
//  1. Parse XML structure using iterative parser
//  2. Walk through XML elements maintaining current tag context
//  3. For each element:
//     a. If OPEN/SELF_CLOSE: extract all attributes as ParamXMLAttr
//     b. If TEXT: extract text content as ParamXML (using current tag path)
//     c. If CLOSE after OPEN with no content: create empty ParamXML
//  4. Build hierarchical parameter names (e.g., "root.user.name")
//  5. Track byte offsets for all parameters
//
// Example:
//
//	request := []byte(`POST / HTTP/1.1
//	Content-Type: application/xml
//
//	<root>
//	  <user id="123">
//	    <name>John</name>
//	  </user>
//	</root>`)
//
//	bodyOffset := FindBodyOffset(request)
//	params, err := ParseXMLBody(request, bodyOffset)
//	// Returns:
//	//   [0] = {Type: ParamXMLAttr, Name: "root.user@id", Value: "123", ...}
//	//   [1] = {Type: ParamXML, Name: "root.user.name", Value: "John", ...}
//
// Parameters:
//   - request: Full HTTP request bytes
//   - bodyOffset: Byte offset where HTTP body starts
//
// Returns:
//   - List of Param objects (ParamXML and ParamXMLAttr types)
//   - Error if XML parsing fails (returns empty list, no error for compatibility)
func ParseXMLBody(request []byte, bodyOffset int) ([]*Param, error) {
	if request == nil || bodyOffset < 0 || bodyOffset >= len(request) {
		return []*Param{}, nil
	}

	body := request[bodyOffset:]
	if len(body) == 0 {
		return []*Param{}, nil
	}

	// Parse XML structure using iterative parser
	// Mode 1 = strict XML parsing (not lenient HTML mode)
	elements := parseXMLElements(body, 0, len(body), 1)
	if len(elements) == 0 {
		return []*Param{}, nil
	}

	// Extract parameters from XML elements
	params := []*Param{}
	var currentTag = ""            // Current tag name context
	var lastElementType byte = 255 // Track previous element type

	for _, elem := range elements {
		switch elem.Type {
		case XMLElementTypeOpen, XMLElementTypeSelfClose:
			// Update current tag context
			currentTag = elem.TagName

			// Extract attributes (ParamXMLAttr)
			for _, attr := range elem.Attributes {
				// Build attribute name: "tagname@attrname"
				// Attribute path format not explicitly shown in source, but inferred from usage
				attrName := currentTag + "@" + attr.Name
				param := createXMLAttrParameter(attrName, attr.Value, attr.ValueStart+bodyOffset, attr.ValueEnd+bodyOffset)
				params = append(params, param)
			}

			// If previous element was OPEN and this is CLOSE, create empty param
			if lastElementType == XMLElementTypeOpen && elem.Type == XMLElementTypeClose {
				param := createXMLParameter(currentTag, "", elem.Start+bodyOffset, elem.Start+bodyOffset)
				params = append(params, param)
			}

		case XMLElementTypeText:
			// Extract text content (ParamXML)
			text := strings.TrimSpace(elem.Text)
			if len(text) > 0 {
				param := createXMLParameter(currentTag, elem.Text, elem.Start+bodyOffset, elem.End+bodyOffset)
				params = append(params, param)
			}
		}

		lastElementType = elem.Type
	}

	return params, nil
}

// createXMLParameter creates a parameter for XML element text content (ParamXML type).
func createXMLParameter(name, value string, valueStart, valueEnd int) *Param {
	return NewParsedParam(
		ParamXML,
		name,
		value,
		-1, // Not tracked for XML elements
		-1, // Not tracked for XML elements
		valueStart,
		valueEnd,
	)
}

// createXMLAttrParameter creates a parameter for XML attribute (ParamXMLAttr type).
func createXMLAttrParameter(name, value string, valueStart, valueEnd int) *Param {
	return NewParsedParam(
		ParamXMLAttr,
		name,
		value,
		-1, // Name offsets would need separate tracking - simplified for now
		-1,
		valueStart,
		valueEnd,
	)
}

// parseXMLElements parses XML structure into a list of elements.
//
// Algorithm:
// 1. Initialize parser state with start/end positions
// 2. Loop through bytes looking for '<' characters
// 3. When '<' found:
//   - Check next char to determine element type (!, /, letter, ?)
//   - Parse tag name and attributes
//   - Create XMLElement with offsets and metadata
//
// 4. Between tags, capture text content as TEXT elements
// 5. Handle special cases: comments (<!--), CDATA (<![CDATA[), self-closing tags
// 6. Return list of all parsed elements
//
// Parameters:
//   - data: XML data bytes
//   - start: Start position in data
//   - end: End position in data
//   - mode: Parsing mode (1=strict XML, 0=lenient HTML)
//
// Returns:
//   - List of XMLElement objects representing the parsed structure
func parseXMLElements(data []byte, start, end int, mode byte) []XMLElement {
	elements := []XMLElement{}
	pos := start

	// Skip XML declaration if present
	// Skip XML declaration if present
	pos = skipXMLDeclaration(data, pos, end)

	for pos < end {
		// Find next '<' character
		// Find next tag start
		textStart := pos
		pos = findNextTag(data, pos, end)

		// If we found text before the tag, add it as TEXT element
		if pos > textStart {
			text := string(data[textStart:pos])
			if len(strings.TrimSpace(text)) > 0 {
				elements = append(elements, XMLElement{
					Type:  XMLElementTypeText,
					Start: textStart,
					End:   pos,
					Text:  text,
				})
			}
		}

		// Check if we're at end
		if pos >= end-1 {
			break
		}

		// Parse tag starting at '<'
		// Parse tag
		elem := parseTag(data, &pos, end, mode)
		if elem != nil {
			elements = append(elements, *elem)
		}
	}

	return elements
}

// skipXMLDeclaration skips the <?xml...?> declaration if present.
func skipXMLDeclaration(data []byte, pos, end int) int {
	// Skip leading whitespace
	for pos < end && data[pos] <= ' ' {
		pos++
	}

	// Check for <?xml prefix
	if pos+5 < end && bytes.HasPrefix(data[pos:], []byte("<?xml")) {
		// Find closing ?>
		closePos := bytes.Index(data[pos:end], []byte("?>"))
		if closePos > 0 {
			return pos + closePos + 2
		}
	}

	return pos
}

// findNextTag finds the next '<' character that starts a tag.
func findNextTag(data []byte, pos, end int) int {
	for pos < end {
		if data[pos] == '<' && pos+1 < end {
			nextChar := data[pos+1]
			// Check if it's a valid tag start
			if nextChar > 32 && nextChar != '.' || nextChar == '/' || nextChar == '!' || nextChar == '?' {
				return pos
			}
		}
		pos++
	}
	return pos
}

// parseTag parses a single XML tag starting at '<'.
func parseTag(data []byte, pos *int, end int, mode byte) *XMLElement {
	if *pos >= end || data[*pos] != '<' {
		return nil
	}

	elemStart := *pos
	*pos++ // Skip '<'

	// Check for comment or special tag
	if *pos < end && data[*pos] == '!' {
		// Handle comment: <!--...-->
		return parseComment(data, pos, end, elemStart)
	}

	// Determine element type
	elemType := XMLElementTypeOpen
	if *pos < end && data[*pos] == '/' {
		// Closing tag: </tag>
		elemType = XMLElementTypeClose
		*pos++ // Skip '/'
	}

	// Parse tag name
	tagStart := *pos
	tagName := parseTagName(data, pos, end)
	tagEnd := *pos

	if *pos >= end {
		return nil
	}

	// Check for PI tag: <?...?>
	if data[tagStart] == '?' {
		elemType = XMLElementTypeSelfClose
	}

	// Parse attributes (only for open/self-closing tags)
	var attributes []XMLAttribute
	if elemType != XMLElementTypeClose {
		// Parse attributes for open/self-closing tags
		attributes = parseAttributes(data, pos, end, &elemType, tagName, mode)
	} else {
		// For closing tags, skip to '>'
		skipToTagEnd(data, pos, end)
	}

	// Find closing '>'
	if *pos < end && data[*pos] == '>' {
		*pos++ // Skip '>'
	}

	return &XMLElement{
		Type:       elemType,
		TagName:    tagName,
		TagStart:   tagStart,
		TagEnd:     tagEnd,
		Start:      elemStart,
		End:        *pos,
		Attributes: attributes,
	}
}

// parseComment parses an XML comment.
func parseComment(data []byte, pos *int, end, elemStart int) *XMLElement {
	commentStart := *pos - 1 // Include '<'

	// Check for <!-- comment -->
	if *pos+2 < end && data[*pos] == '!' && data[*pos+1] == '-' && data[*pos+2] == '-' {
		// Find closing -->
		closePos := bytes.Index(data[*pos+3:end], []byte("-->"))
		if closePos >= 0 {
			*pos = *pos + 3 + closePos + 3
			return &XMLElement{
				Type:  XMLElementTypeComment,
				Start: commentStart,
				End:   *pos,
			}
		}
	}

	// Not a valid comment, skip to '>'
	for *pos < end && data[*pos] != '>' {
		*pos++
	}
	if *pos < end {
		*pos++ // Skip '>'
	}

	return &XMLElement{
		Type:  XMLElementTypeComment,
		Start: elemStart,
		End:   *pos,
	}
}

// parseTagName parses an XML tag name.
func parseTagName(data []byte, pos *int, end int) string {
	start := *pos
	for *pos < end && data[*pos] > 32 && data[*pos] != '>' && data[*pos] != '/' {
		*pos++
	}
	return strings.ToLower(string(data[start:*pos]))
}

// skipToTagEnd skips whitespace and content until '>' for closing tags.
func skipToTagEnd(data []byte, pos *int, end int) {
	for *pos < end {
		// Skip whitespace
		// Skip whitespace
		for *pos < end && data[*pos] <= 32 {
			*pos++
		}

		if *pos >= end || data[*pos] == '>' {
			break
		}

		// Skip any remaining content until '>'
		for *pos < end && data[*pos] > 32 && data[*pos] != '>' {
			*pos++
		}
	}
}

// parseAttributes parses XML attributes from a tag.
func parseAttributes(data []byte, pos *int, end int, elemType *byte, tagName string, mode byte) []XMLAttribute {
	attributes := []XMLAttribute{}

	// Check for self-closing void elements in HTML mode
	if mode == 0 && *elemType == XMLElementTypeOpen {
		if tagName == "img" || tagName == "br" || tagName == "hr" || tagName == "meta" ||
			tagName == "input" || tagName == "link" {
			*elemType = XMLElementTypeSelfClose
		}
	}

	for *pos < end {
		// Skip whitespace
		skipWhitespace(data, pos, end)

		if *pos >= end || data[*pos] == '>' {
			break
		}

		// Check for self-closing marker: />
		if data[*pos] == '/' {
			*elemType = XMLElementTypeSelfClose
			*pos++
			continue
		}

		// Parse attribute name
		nameStart := *pos
		for *pos < end && data[*pos] > 32 && data[*pos] != '=' && data[*pos] != '/' && data[*pos] != '>' {
			*pos++
		}

		if *pos >= end {
			break
		}

		nameEnd := *pos
		attrName := strings.ToLower(string(data[nameStart:nameEnd]))

		// Skip whitespace after name
		skipWhitespace(data, pos, end)

		if *pos >= end {
			break
		}

		// Parse attribute value (if '=' present)
		attrValue := ""
		valueStart := *pos
		valueEnd := *pos
		quoteType := XMLQuoteNone

		if data[*pos] == '=' {
			*pos++ // Skip '='
			skipWhitespace(data, pos, end)

			if *pos >= end {
				break
			}

			// Determine quote type
			quoteType = detectQuoteType(data, pos)
			valueStart = *pos

			// Parse quoted/unquoted value
			parseAttributeValue(data, pos, end, quoteType)
			valueEnd = *pos
			attrValue = strings.ToLower(string(data[valueStart:valueEnd]))

			// Skip closing quote if present
			if quoteType == XMLQuoteDouble || quoteType == XMLQuoteSingle || quoteType == XMLQuoteBacktick {
				if *pos < end {
					*pos++ // Skip closing quote
				}
			}
		}

		// Skip <?...?> attributes (PI tags)
		if data[nameStart] != '?' {
			attributes = append(attributes, XMLAttribute{
				Name:       attrName,
				Value:      attrValue,
				NameStart:  nameStart,
				NameEnd:    nameEnd,
				ValueStart: valueStart,
				ValueEnd:   valueEnd,
				QuoteType:  quoteType,
			})
		}
	}

	return attributes
}

// skipWhitespace skips whitespace characters.
func skipWhitespace(data []byte, pos *int, end int) {
	for *pos < end && data[*pos] <= 32 {
		*pos++
	}
}

// detectQuoteType detects the quote type for an attribute value.
func detectQuoteType(data []byte, pos *int) byte {
	if *pos >= len(data) {
		return XMLQuoteNone
	}

	switch data[*pos] {
	case '"':
		*pos++ // Skip opening quote
		return XMLQuoteDouble
	case '\'':
		*pos++ // Skip opening quote
		return XMLQuoteSingle
	case '`':
		*pos++ // Skip opening quote
		return XMLQuoteBacktick
	default:
		return XMLQuoteNone
	}
}

// parseAttributeValue parses an attribute value based on quote type.
func parseAttributeValue(data []byte, pos *int, end int, quoteType byte) {
	switch quoteType {
	case XMLQuoteDouble:
		// Parse until closing "
		for *pos < end && data[*pos] != '"' {
			*pos++
		}
	case XMLQuoteSingle:
		// Parse until closing '
		for *pos < end && data[*pos] != '\'' {
			*pos++
		}
	case XMLQuoteBacktick:
		// Parse until closing `
		for *pos < end && data[*pos] != '`' {
			*pos++
		}
	case XMLQuoteNone:
		// Parse until whitespace or '>'
		for *pos < end && data[*pos] > 32 && data[*pos] != '>' {
			*pos++
		}
	}
}
