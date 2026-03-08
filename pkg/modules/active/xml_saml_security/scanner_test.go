package xml_saml_security

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestDecodeSAML_PlainXML(t *testing.T) {
	input := "<saml>test</saml>"
	decoded, err := DecodeSAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decoded.XMLContent != input {
		t.Errorf("expected %q, got %q", input, decoded.XMLContent)
	}
	if decoded.IsCompressed || decoded.IsBase64 {
		t.Error("expected no encoding flags")
	}
}

func TestDecodeSAML_Base64Only(t *testing.T) {
	xml := "<saml>test</saml>"
	input := base64.StdEncoding.EncodeToString([]byte(xml))

	decoded, err := DecodeSAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decoded.XMLContent != xml {
		t.Errorf("expected %q, got %q", xml, decoded.XMLContent)
	}
	if decoded.IsCompressed {
		t.Error("expected IsCompressed=false")
	}
	if !decoded.IsBase64 {
		t.Error("expected IsBase64=true")
	}
}

func TestDecodeSAML_CompressedBase64(t *testing.T) {
	xml := "<saml>test</saml>"
	compressed, err := DeflateCompress([]byte(xml))
	if err != nil {
		t.Fatalf("compression failed: %v", err)
	}
	input := base64.StdEncoding.EncodeToString(compressed)

	decoded, err := DecodeSAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decoded.XMLContent != xml {
		t.Errorf("expected %q, got %q", xml, decoded.XMLContent)
	}
	if !decoded.IsCompressed || !decoded.IsBase64 {
		t.Error("expected both encoding flags true")
	}
}

func TestDecodeSAML_URLEncoded(t *testing.T) {
	xml := "<saml>test</saml>"
	compressed, _ := DeflateCompress([]byte(xml))
	b64 := base64.StdEncoding.EncodeToString(compressed)
	// Simulate URL encoding of + and = characters
	input := strings.ReplaceAll(b64, "+", "%2B")
	input = strings.ReplaceAll(input, "=", "%3D")

	decoded, err := DecodeSAML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decoded.XMLContent != xml {
		t.Errorf("expected %q, got %q", xml, decoded.XMLContent)
	}
}

func TestDecodeSAML_Invalid(t *testing.T) {
	tests := []string{
		"not-base64-and-not-xml",
		"aGVsbG8gd29ybGQ=", // base64 "hello world" - not XML
	}

	for _, input := range tests {
		_, err := DecodeSAML(input)
		if err == nil {
			t.Errorf("expected error for input %q", input)
		}
	}
}

func TestEncodeSAML_Roundtrip(t *testing.T) {
	original := &DecodedSAML{
		XMLContent:   "<saml>test</saml>",
		IsCompressed: true,
		IsBase64:     true,
	}

	encoded := EncodeSAML(original.XMLContent, original)
	decoded, err := DecodeSAML(encoded)
	if err != nil {
		t.Fatalf("roundtrip failed: %v", err)
	}
	if decoded.XMLContent != original.XMLContent {
		t.Errorf("roundtrip content mismatch: got %q, want %q", decoded.XMLContent, original.XMLContent)
	}
}

func TestEncodeSAML_NoCompression(t *testing.T) {
	original := &DecodedSAML{
		XMLContent:   "<saml>test</saml>",
		IsCompressed: false,
		IsBase64:     true,
	}

	encoded := EncodeSAML(original.XMLContent, original)
	decoded, err := DecodeSAML(encoded)
	if err != nil {
		t.Fatalf("roundtrip failed: %v", err)
	}
	if decoded.XMLContent != original.XMLContent {
		t.Errorf("content mismatch")
	}
	if decoded.IsCompressed {
		t.Error("should not be compressed")
	}
}

func TestParseXML_ValidXML(t *testing.T) {
	input := `<Response ID="abc123"><Assertion>test</Assertion></Response>`
	doc, err := ParseXML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc.HasDoctype {
		t.Error("expected HasDoctype=false")
	}
	if doc.IDAttrVal != "abc123" {
		t.Errorf("expected IDAttrVal='abc123', got %q", doc.IDAttrVal)
	}
}

func TestParseXML_WithDoctype(t *testing.T) {
	input := `<!DOCTYPE saml><Response ID="x"><test/></Response>`
	doc, err := ParseXML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !doc.HasDoctype {
		t.Error("expected HasDoctype=true")
	}
}

func TestParseXML_NoID(t *testing.T) {
	input := `<Response><Assertion>test</Assertion></Response>`
	doc, err := ParseXML(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc.IDAttrVal != "" {
		t.Errorf("expected empty IDAttrVal, got %q", doc.IDAttrVal)
	}
}

func TestParseXML_Invalid(t *testing.T) {
	_, err := ParseXML("not xml")
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}

func TestInjectDOCTYPE(t *testing.T) {
	xml := `<Response><test/></Response>`
	doc, _ := ParseXML(xml)
	decoded := &DecodedSAML{XMLContent: xml, IsBase64: false, IsCompressed: false}

	payload, err := InjectDOCTYPE(doc, decoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := `<!DOCTYPE root SYSTEM "example.dtd"><Response><test/></Response>`
	if payload != expected {
		t.Errorf("expected %q, got %q", expected, payload)
	}
}

func TestInjectDOCTYPE_WithXMLDeclaration(t *testing.T) {
	xml := `<?xml version="1.0"?><Response><test/></Response>`
	doc, _ := ParseXML(xml)
	decoded := &DecodedSAML{XMLContent: xml, IsBase64: false, IsCompressed: false}

	payload, err := InjectDOCTYPE(doc, decoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should remove XML declaration before DOCTYPE
	if strings.Contains(payload, "<?xml") {
		t.Error("should remove XML declaration")
	}
	if !strings.HasPrefix(payload, "<!DOCTYPE") {
		t.Error("should start with DOCTYPE")
	}
}

func TestInjectDOCTYPE_ExistingDoctype(t *testing.T) {
	xml := `<!DOCTYPE foo><Response><test/></Response>`
	doc, _ := ParseXML(xml)
	decoded := &DecodedSAML{XMLContent: xml, IsBase64: false, IsCompressed: false}

	_, err := InjectDOCTYPE(doc, decoded)
	if err == nil {
		t.Error("expected error for existing DOCTYPE")
	}
}

func TestInjectENTITY(t *testing.T) {
	xml := `<Response ID="uuid-123"><test/></Response>`
	doc, _ := ParseXML(xml)
	decoded := &DecodedSAML{XMLContent: xml, IsBase64: false, IsCompressed: false}

	payload, err := InjectENTITY(doc, decoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(payload, `<!DOCTYPE foo [ <!ENTITY uuid SYSTEM "uuid-123"> ]>`) {
		t.Errorf("missing DOCTYPE ENTITY declaration in %q", payload)
	}
	if !strings.Contains(payload, `ID="&uuid;"`) {
		t.Errorf("missing entity reference in %q", payload)
	}
}

func TestInjectENTITY_NoID(t *testing.T) {
	xml := `<Response><test/></Response>`
	doc, _ := ParseXML(xml)
	decoded := &DecodedSAML{XMLContent: xml, IsBase64: false, IsCompressed: false}

	_, err := InjectENTITY(doc, decoded)
	if err == nil {
		t.Error("expected error for missing ID attribute")
	}
}

func TestIsSAMLParam(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"SAMLRequest", true},
		{"samlrequest", true},
		{"SAMLREQUEST", true},
		{"SAMLResponse", true},
		{"samlresponse", true},
		{"SAMLRESPONSE", true},
		{"other", false},
		{"saml", false},
		{"SAMLRequest2", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isSAMLParam(tc.name)
			if result != tc.expected {
				t.Errorf("isSAMLParam(%q) = %v, want %v", tc.name, result, tc.expected)
			}
		})
	}
}

func TestDeflateCompressionRoundtrip(t *testing.T) {
	original := []byte("test data for compression")

	compressed, err := DeflateCompress(original)
	if err != nil {
		t.Fatalf("compression failed: %v", err)
	}

	decompressed, err := DeflateDecompress(compressed)
	if err != nil {
		t.Fatalf("decompression failed: %v", err)
	}

	if string(decompressed) != string(original) {
		t.Errorf("roundtrip mismatch: got %q, want %q", decompressed, original)
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"longer than limit", 10, "longer tha..."},
	}

	for _, tc := range tests {
		result := truncateString(tc.input, tc.maxLen)
		if result != tc.expected {
			t.Errorf("truncateString(%q, %d) = %q, want %q", tc.input, tc.maxLen, result, tc.expected)
		}
	}
}
