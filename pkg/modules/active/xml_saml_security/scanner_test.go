package xml_saml_security

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
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

	payload, err := InjectDOCTYPE(doc, decoded, "http://oast.example/x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := `<!DOCTYPE root SYSTEM "http://oast.example/x"><Response><test/></Response>`
	if payload != expected {
		t.Errorf("expected %q, got %q", expected, payload)
	}
}

func TestInjectDOCTYPE_WithXMLDeclaration(t *testing.T) {
	xml := `<?xml version="1.0"?><Response><test/></Response>`
	doc, _ := ParseXML(xml)
	decoded := &DecodedSAML{XMLContent: xml, IsBase64: false, IsCompressed: false}

	payload, err := InjectDOCTYPE(doc, decoded, "http://oast.example/x")
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

	_, err := InjectDOCTYPE(doc, decoded, "http://oast.example/x")
	if err == nil {
		t.Error("expected error for existing DOCTYPE")
	}
}

func TestInjectENTITY(t *testing.T) {
	xml := `<Response ID="uuid-123"><test/></Response>`
	doc, _ := ParseXML(xml)
	decoded := &DecodedSAML{XMLContent: xml, IsBase64: false, IsCompressed: false}

	payload, err := InjectENTITY(doc, decoded, "http://oast.example/x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(payload, `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://oast.example/x"> ]>`) {
		t.Errorf("missing DOCTYPE ENTITY declaration in %q", payload)
	}
	if !strings.Contains(payload, `ID="&xxe;"`) {
		t.Errorf("missing entity reference in %q", payload)
	}
}

func TestInjectENTITY_NoID(t *testing.T) {
	xml := `<Response><test/></Response>`
	doc, _ := ParseXML(xml)
	decoded := &DecodedSAML{XMLContent: xml, IsBase64: false, IsCompressed: false}

	_, err := InjectENTITY(doc, decoded, "http://oast.example/x")
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

// fakeOAST is a stand-in OAST provider that returns a fixed host and records the
// parameter names and injection types it was asked to generate URLs for.
type fakeOAST struct {
	host       string
	enabled    bool
	mu         sync.Mutex
	params     []string
	injections []string
}

func (f *fakeOAST) GenerateURL(_, paramName, injectionType, _, _ string) string {
	f.mu.Lock()
	f.params = append(f.params, paramName)
	f.injections = append(f.injections, injectionType)
	f.mu.Unlock()
	return f.host
}
func (f *fakeOAST) Enabled() bool { return f.enabled }

// samlParamValue is a small plain-XML SAML document (no DOCTYPE, with an ID
// attribute so the ENTITY probe applies). DecodeSAML accepts plain XML, so the
// module re-emits plain XML — keeping the injected OAST host literally visible on
// the wire instead of buried in base64.
func samlParamValue() string {
	return `<Response ID="abc123"><Assertion>x</Assertion></Response>`
}

// recordingSAMLServer captures each SAMLResponse value it receives (URL-decoded
// by Query().Get), so a test can assert the injected OAST host reached the wire.
func recordingSAMLServer(seen *[]string, mu *sync.Mutex) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.URL.Query().Get("SAMLResponse"); v != "" {
			mu.Lock()
			*seen = append(*seen, v)
			mu.Unlock()
		}
		_, _ = w.Write([]byte("ok"))
	}))
}

// TestScanPerInsertionPoint_OASTPlantsExternalEntity: with OAST enabled, the
// module fires SAML payloads whose decoded XML embeds the unique OAST host in an
// external DTD / external entity, and returns no synchronous finding (OAST is
// async). It also labels the injection type as XXE so the poller classifies the
// callback correctly.
func TestScanPerInsertionPoint_OASTPlantsExternalEntity(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := recordingSAMLServer(&seen, &mu)
	defer srv.Close()

	const host = "abc123unique.oast.example"
	oast := &fakeOAST{host: host, enabled: true}

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/acs?SAMLResponse="+url.QueryEscape(samlParamValue()))
	ip := modtest.InsertionPoint(t, rr, "SAMLResponse")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{OASTProvider: oast})
	if err != nil {
		t.Fatalf("ScanPerInsertionPoint: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected 0 synchronous findings (OAST is async), got %d", len(res))
	}

	mu.Lock()
	defer mu.Unlock()
	hostHits := 0
	for _, xmlDoc := range seen {
		if strings.Contains(xmlDoc, host) &&
			(strings.Contains(xmlDoc, "<!DOCTYPE") || strings.Contains(xmlDoc, "<!ENTITY")) {
			hostHits++
		}
	}
	if hostHits == 0 {
		t.Fatalf("expected a SAML payload embedding the OAST host in a DTD/entity; saw %v", seen)
	}
	if len(oast.params) == 0 || oast.params[0] != "SAMLResponse" {
		t.Errorf("expected GenerateURL called for SAMLResponse, got %v", oast.params)
	}
	for _, it := range oast.injections {
		if !strings.Contains(strings.ToLower(it), "xxe") {
			t.Errorf("expected XXE injection type, got %q", it)
		}
	}
}

// TestScanPerInsertionPoint_NoOAST_NoOp: without an OAST provider the module
// sends nothing — confirmation is out-of-band only, with no heuristic fallback.
func TestScanPerInsertionPoint_NoOAST_NoOp(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := recordingSAMLServer(&seen, &mu)
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/acs?SAMLResponse="+url.QueryEscape(samlParamValue()))
	ip := modtest.InsertionPoint(t, rr, "SAMLResponse")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerInsertionPoint: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(res))
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 0 {
		t.Fatalf("expected no requests with OAST disabled, saw %d", len(seen))
	}
}
