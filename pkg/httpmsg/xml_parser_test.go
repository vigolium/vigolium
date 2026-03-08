package httpmsg

import (
	"strings"
	"testing"
)

func TestParseXMLBody_SimpleElements(t *testing.T) {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

<root>
  <name>John</name>
  <age>30</age>
</root>`)

	bodyOffset := findBodyStart(request)
	params, err := ParseXMLBody(request, bodyOffset)

	if err != nil {
		t.Fatalf("ParseXMLBody() error = %v", err)
	}

	// Should extract 2 parameters (name and age text content)
	if len(params) < 2 {
		t.Errorf("Expected at least 2 parameters, got %d", len(params))
	}

	// Check for name parameter
	foundName := false
	foundAge := false
	for _, p := range params {
		if p.Type() == ParamXML {
			if strings.Contains(p.Name(), "name") && strings.TrimSpace(p.Value()) == "John" {
				foundName = true
			}
			if strings.Contains(p.Name(), "age") && strings.TrimSpace(p.Value()) == "30" {
				foundAge = true
			}
		}
	}

	if !foundName {
		t.Errorf("Expected to find parameter with name containing 'name' and value 'John'")
	}
	if !foundAge {
		t.Errorf("Expected to find parameter with name containing 'age' and value '30'")
	}
}

func TestParseXMLBody_WithAttributes(t *testing.T) {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

<user id="123" role="admin">
  <name>John</name>
</user>`)

	bodyOffset := findBodyStart(request)
	params, err := ParseXMLBody(request, bodyOffset)

	if err != nil {
		t.Fatalf("ParseXMLBody() error = %v", err)
	}

	// Should extract: user@id, user@role, name (text)
	if len(params) < 3 {
		t.Errorf("Expected at least 3 parameters, got %d", len(params))
	}

	// Check for attribute parameters
	foundIdAttr := false
	foundRoleAttr := false
	foundNameText := false

	for _, p := range params {
		if p.Type() == ParamXMLAttr {
			if strings.Contains(p.Name(), "@id") && p.Value() == "123" {
				foundIdAttr = true
			}
			if strings.Contains(p.Name(), "@role") && p.Value() == "admin" {
				foundRoleAttr = true
			}
		}
		if p.Type() == ParamXML && strings.Contains(p.Name(), "name") && strings.TrimSpace(p.Value()) == "John" {
			foundNameText = true
		}
	}

	if !foundIdAttr {
		t.Errorf("Expected to find XML_ATTR parameter for 'id' with value '123'")
	}
	if !foundRoleAttr {
		t.Errorf("Expected to find XML_ATTR parameter for 'role' with value 'admin'")
	}
	if !foundNameText {
		t.Errorf("Expected to find XML_PARAM parameter for 'name' with value 'John'")
	}
}

func TestParseXMLBody_NestedElements(t *testing.T) {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

<root>
  <user>
    <name>John</name>
    <email>john@example.com</email>
  </user>
</root>`)

	bodyOffset := findBodyStart(request)
	params, err := ParseXMLBody(request, bodyOffset)

	if err != nil {
		t.Fatalf("ParseXMLBody() error = %v", err)
	}

	if len(params) < 2 {
		t.Errorf("Expected at least 2 parameters for nested elements, got %d", len(params))
	}

	// Verify we got XML text parameters
	xmlParamCount := 0
	for _, p := range params {
		if p.Type() == ParamXML {
			xmlParamCount++
		}
	}

	if xmlParamCount < 2 {
		t.Errorf("Expected at least 2 XML text parameters, got %d", xmlParamCount)
	}
}

func TestParseXMLBody_MixedContent(t *testing.T) {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

<root>
  <user id="123" active="true">
    <name>John</name>
    <settings debug="false">
      <theme>dark</theme>
    </settings>
  </user>
</root>`)

	bodyOffset := findBodyStart(request)
	params, err := ParseXMLBody(request, bodyOffset)

	if err != nil {
		t.Fatalf("ParseXMLBody() error = %v", err)
	}

	// Count parameter types
	attrCount := 0
	textCount := 0
	for _, p := range params {
		switch p.Type() {
		case ParamXMLAttr:
			attrCount++
		case ParamXML:
			textCount++
		}
	}

	// Should have attributes: id, active, debug
	if attrCount < 3 {
		t.Errorf("Expected at least 3 XML attributes, got %d", attrCount)
	}

	// Should have text: name, theme
	if textCount < 2 {
		t.Errorf("Expected at least 2 XML text elements, got %d", textCount)
	}
}

func TestParseXMLBody_SelfClosingTags(t *testing.T) {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

<root>
  <user id="123"/>
  <item name="test" value="data"/>
</root>`)

	bodyOffset := findBodyStart(request)
	params, err := ParseXMLBody(request, bodyOffset)

	if err != nil {
		t.Fatalf("ParseXMLBody() error = %v", err)
	}

	// Should extract attributes from self-closing tags
	attrCount := 0
	for _, p := range params {
		if p.Type() == ParamXMLAttr {
			attrCount++
		}
	}

	// Should have at least: id, name, value
	if attrCount < 3 {
		t.Errorf("Expected at least 3 attributes from self-closing tags, got %d", attrCount)
	}
}

func TestParseXMLBody_EmptyElements(t *testing.T) {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

<root>
  <empty></empty>
  <name>John</name>
</root>`)

	bodyOffset := findBodyStart(request)
	params, err := ParseXMLBody(request, bodyOffset)

	if err != nil {
		t.Fatalf("ParseXMLBody() error = %v", err)
	}

	// Should handle empty elements gracefully
	// Empty elements should not create text parameters (or create empty ones)
	for _, p := range params {
		if p.Type() == ParamXML && strings.Contains(p.Name(), "name") {
			if strings.TrimSpace(p.Value()) != "John" {
				t.Errorf("Expected 'name' parameter to have value 'John', got '%s'", p.Value())
			}
		}
	}
}

func TestParseXMLBody_WithXMLDeclaration(t *testing.T) {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<root>
  <name>John</name>
</root>`)

	bodyOffset := findBodyStart(request)
	params, err := ParseXMLBody(request, bodyOffset)

	if err != nil {
		t.Fatalf("ParseXMLBody() error = %v", err)
	}

	// Should skip XML declaration and parse content
	if len(params) == 0 {
		t.Errorf("Expected to find parameters after XML declaration")
	}

	foundName := false
	for _, p := range params {
		if p.Type() == ParamXML && strings.Contains(p.Name(), "name") {
			foundName = true
		}
	}

	if !foundName {
		t.Errorf("Expected to find 'name' parameter after XML declaration")
	}
}

func TestParseXMLBody_WithComments(t *testing.T) {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

<root>
  <!-- This is a comment -->
  <name>John</name>
  <!-- Another comment -->
</root>`)

	bodyOffset := findBodyStart(request)
	params, err := ParseXMLBody(request, bodyOffset)

	if err != nil {
		t.Fatalf("ParseXMLBody() error = %v", err)
	}

	// Comments should be ignored, only extract name
	foundName := false
	for _, p := range params {
		if p.Type() == ParamXML && strings.Contains(p.Name(), "name") && strings.TrimSpace(p.Value()) == "John" {
			foundName = true
		}
	}

	if !foundName {
		t.Errorf("Expected to find 'name' parameter, comments should be ignored")
	}
}

func TestParseXMLBody_ByteOffsets(t *testing.T) {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

<user id="123">
  <name>John</name>
</user>`)

	bodyOffset := findBodyStart(request)
	params, err := ParseXMLBody(request, bodyOffset)

	if err != nil {
		t.Fatalf("ParseXMLBody() error = %v", err)
	}

	// Verify that offsets are within request bounds
	for _, p := range params {
		if p.ValueStart() < bodyOffset {
			t.Errorf("Parameter %s ValueStart (%d) is before body offset (%d)", p.Name(), p.ValueStart(), bodyOffset)
		}
		if p.ValueEnd() > len(request) {
			t.Errorf("Parameter %s ValueEnd (%d) exceeds request length (%d)", p.Name(), p.ValueEnd(), len(request))
		}
		if p.ValueStart() > p.ValueEnd() {
			t.Errorf("Parameter %s has ValueStart (%d) > ValueEnd (%d)", p.Name(), p.ValueStart(), p.ValueEnd())
		}
	}
}

func TestParseXMLBody_DifferentQuoteTypes(t *testing.T) {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

<root id="123" name='test' data=unquoted>
  <item>value</item>
</root>`)

	bodyOffset := findBodyStart(request)
	params, err := ParseXMLBody(request, bodyOffset)

	if err != nil {
		t.Fatalf("ParseXMLBody() error = %v", err)
	}

	// Should handle different quote types
	foundDoubleQuote := false
	foundSingleQuote := false
	foundUnquoted := false

	for _, p := range params {
		if p.Type() == ParamXMLAttr {
			if strings.Contains(p.Name(), "@id") && p.Value() == "123" {
				foundDoubleQuote = true
			}
			if strings.Contains(p.Name(), "@name") && p.Value() == "test" {
				foundSingleQuote = true
			}
			if strings.Contains(p.Name(), "@data") && p.Value() == "unquoted" {
				foundUnquoted = true
			}
		}
	}

	if !foundDoubleQuote {
		t.Errorf("Expected to find attribute with double quotes")
	}
	if !foundSingleQuote {
		t.Errorf("Expected to find attribute with single quotes")
	}
	if !foundUnquoted {
		t.Errorf("Expected to find unquoted attribute")
	}
}

func TestParseXMLBody_EmptyBody(t *testing.T) {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

`)

	bodyOffset := findBodyStart(request)
	params, err := ParseXMLBody(request, bodyOffset)

	if err != nil {
		t.Fatalf("ParseXMLBody() error = %v", err)
	}

	if len(params) != 0 {
		t.Errorf("Expected 0 parameters for empty body, got %d", len(params))
	}
}

func TestParseXMLBody_InvalidOffset(t *testing.T) {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

<root>test</root>`)

	// Test with invalid offsets
	params, err := ParseXMLBody(request, -1)
	if err != nil {
		t.Fatalf("ParseXMLBody() error = %v", err)
	}
	if len(params) != 0 {
		t.Errorf("Expected 0 parameters for invalid offset, got %d", len(params))
	}

	params, err = ParseXMLBody(request, len(request)+100)
	if err != nil {
		t.Fatalf("ParseXMLBody() error = %v", err)
	}
	if len(params) != 0 {
		t.Errorf("Expected 0 parameters for offset beyond request, got %d", len(params))
	}
}

func TestParseXMLBody_NilRequest(t *testing.T) {
	params, err := ParseXMLBody(nil, 0)

	if err != nil {
		t.Fatalf("ParseXMLBody() error = %v", err)
	}

	if len(params) != 0 {
		t.Errorf("Expected 0 parameters for nil request, got %d", len(params))
	}
}

func TestParseXMLBody_ComplexRealWorld(t *testing.T) {
	// Test with a more realistic SOAP-like XML
	request := []byte(`POST /api/endpoint HTTP/1.1
Host: example.com
Content-Type: application/xml

<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <UserRequest id="12345" type="query">
      <Username>admin</Username>
      <Password>secret123</Password>
      <Options debug="true" verbose="false"/>
    </UserRequest>
  </soap:Body>
</soap:Envelope>`)

	bodyOffset := findBodyStart(request)
	params, err := ParseXMLBody(request, bodyOffset)

	if err != nil {
		t.Fatalf("ParseXMLBody() error = %v", err)
	}

	// Should extract multiple parameters
	if len(params) < 5 {
		t.Errorf("Expected at least 5 parameters from complex XML, got %d", len(params))
		for _, p := range params {
			t.Logf("  %s: %s = %s", p.Type(), p.Name(), p.Value())
		}
	}

	// Verify we got both attributes and text content
	hasAttrs := false
	hasText := false
	for _, p := range params {
		if p.Type() == ParamXMLAttr {
			hasAttrs = true
		}
		if p.Type() == ParamXML {
			hasText = true
		}
	}

	if !hasAttrs {
		t.Errorf("Expected to find XML attributes in complex document")
	}
	if !hasText {
		t.Errorf("Expected to find XML text content in complex document")
	}
}

func TestParseXMLBody_ParamTypes(t *testing.T) {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

<root id="123">
  <name>John</name>
</root>`)

	bodyOffset := findBodyStart(request)
	params, err := ParseXMLBody(request, bodyOffset)

	if err != nil {
		t.Fatalf("ParseXMLBody() error = %v", err)
	}

	// Verify parameter types are correct
	for _, p := range params {
		if strings.Contains(p.Name(), "@") {
			// Attribute should be ParamXMLAttr
			if p.Type() != ParamXMLAttr {
				t.Errorf("Attribute parameter %s has wrong type: got %d, want %d (ParamXMLAttr)",
					p.Name(), p.Type(), ParamXMLAttr)
			}
		} else {
			// Element text should be ParamXML
			if p.Type() != ParamXML {
				t.Errorf("Element parameter %s has wrong type: got %d, want %d (ParamXML)",
					p.Name(), p.Type(), ParamXML)
			}
		}
	}
}

func TestParseXMLBody_WhitespaceHandling(t *testing.T) {
	request := []byte(`POST / HTTP/1.1
Content-Type: application/xml

<root>
  <name>   John   </name>
  <age>30</age>
</root>`)

	bodyOffset := findBodyStart(request)
	params, err := ParseXMLBody(request, bodyOffset)

	if err != nil {
		t.Fatalf("ParseXMLBody() error = %v", err)
	}

	// Check that text values are captured (whitespace may be preserved or trimmed)
	foundName := false
	for _, p := range params {
		if p.Type() == ParamXML && strings.Contains(p.Name(), "name") {
			foundName = true
			// Value should contain "John" (may have surrounding whitespace)
			if !strings.Contains(p.Value(), "John") {
				t.Errorf("Expected name value to contain 'John', got '%s'", p.Value())
			}
		}
	}

	if !foundName {
		t.Errorf("Expected to find 'name' parameter")
	}
}

// Helper function to find body start in HTTP request
func findBodyStart(request []byte) int {
	// Find \r\n\r\n or \n\n
	for i := 0; i < len(request)-3; i++ {
		if request[i] == '\r' && request[i+1] == '\n' &&
			request[i+2] == '\r' && request[i+3] == '\n' {
			return i + 4
		}
	}
	for i := 0; i < len(request)-1; i++ {
		if request[i] == '\n' && request[i+1] == '\n' {
			return i + 2
		}
	}
	return 0
}
