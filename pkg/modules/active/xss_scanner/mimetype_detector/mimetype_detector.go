package mimetype_detector

import (
	"net/http"
	"regexp"
	"strings"
)

// ContentType defines integer constants for various content types.
type ContentType int16

const (
	ContentType_NONE ContentType = iota
	ContentType_HTML
	ContentType_PLAIN_TEXT
	ContentType_CSS
	ContentType_SCRIPT
	ContentType_JSON
	ContentType_XML
	ContentType_RTF
	ContentType_YAML
	ContentType_SVG
	ContentType_UNRECOGNIZED_CONTENT
)

// MimetypeDetector helps in determining stated and inferred content types.
// It also gathers other related information from headers.
type MimetypeDetector struct {
	// Raw values from Content-Type headers
	rawContentTypeHeaderValues []string
	// Charsets parsed from Content-Type headers
	charsetHeaderValues []string
	// Stated type determined from the main Content-Type header
	statedType ContentType
	// Inferred type from body
	inferredType ContentType
	// From X-Content-Type-Options
	isNoSniff bool
	// From Content-Disposition
	isAttachment bool
}

// ExtractRawContentTypeHeaders collects all values for "Content-Type" headers, case-insensitively.
func ExtractRawContentTypeHeaders(headers map[string]string) string {
	var values []string
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Type") {
			values = append(values, v)
		}
	}
	return values[len(values)-1]
}

var charsetRegex = regexp.MustCompile(`(?i)charset\s*=\s*([\w-]+)`)

// ExtractCharsetFromSingleHeader extracts the charset from a single Content-Type header string.
func ExtractCharsetFromSingleHeader(headerValue string) string {
	matches := charsetRegex.FindStringSubmatch(headerValue)
	if len(matches) > 1 {
		return strings.ToLower(strings.TrimSpace(matches[1]))
	}
	return ""
}

// ExtractCharset extracts all unique, non-empty charsets from a list of raw Content-Type header strings.
func ExtractCharset(contentTypeHeader string) string {
	charset := ExtractCharsetFromSingleHeader(contentTypeHeader)
	if charset != "" {
		return charset
	}
	return ""
}

// GetStatedInferredContentType processes raw Content-Type headers to find the main type
func GetStatedInferredContentType(
	contentTypeHeaders string,
) (processedMimeValue string, typeShort ContentType) {
	if contentTypeHeaders == "" {
		return "", ContentType_NONE
	}

	// lastHeaderValue := contentTypeHeaders

	// Take part before ';', trim, lowercase
	processedMime := contentTypeHeaders
	if idx := strings.Index(processedMime, ";"); idx != -1 {
		processedMime = processedMime[:idx]
	}
	processedMime = strings.ToLower(strings.TrimSpace(processedMime))

	if processedMime == "" {
		return "", ContentType_NONE // Or UNRECOGNIZED if header was like "; charset=utf-8"
	}

	return processedMime, mapStringToContentType(processedMime)
}

// GetInferredContentType uses the mimetype library to detect content type from the body
func GetInferredContentType(body []byte) ContentType {
	if len(body) == 0 {
		return ContentType_NONE
	}

	// Use net/http standard library for MIME type detection
	// mime := mimetype.Detect(body)
	// mimeString := mime.String()

	mimeString := http.DetectContentType(body)

	if idx := strings.Index(mimeString, ";"); idx != -1 {
		mimeString = mimeString[:idx]
	}
	mimeString = strings.TrimSpace(mimeString)

	if mimeString == "" {
		return ContentType_UNRECOGNIZED_CONTENT
	}

	return mapStringToContentType(mimeString)
}

// ParseIsNoSniff checks for "X-Content-Type-Options: nosniff".
func ParseIsNoSniff(headers map[string]string) bool {
	for k, v := range headers {
		if strings.EqualFold(k, "X-Content-Type-Options") {
			if strings.Contains(strings.ToLower(v), "nosniff") {
				return true
			}
		}
	}
	return false
}

// ParseIsAttachment checks for "Content-Disposition: attachment".
func ParseIsAttachment(headers map[string]string) bool {
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Disposition") {
			// A simple check. RFC 6266 is more complex for parsing 'filename' etc.
			// We only care about the 'attachment' directive for now.
			if strings.Contains(strings.ToLower(v), "attachment") {
				return true
			}
		}
	}
	return false
}

// NewMimetypeDetector creates a new MimetypeDetector by analyzing headers and body.
// It determines various content type related information.
// func NewMimetypeDetector(headers map[string]string, body []byte) *MimetypeDetector {
// 	rawContentTypes := ExtractRawContentTypeHeaders(headers)
// 	_, statedShort := DetermineMainStatedType(rawContentTypes)
// 	charsets := ExtractAllCharsets(rawContentTypes)
// 	noSniff := ParseIsNoSniff(headers)
// 	attachment := ParseIsAttachment(headers)

// 	// getInferredContentTypeShort remains largely the same
// 	inferredShort := GetInferredContentType(body)

// 	return &MimetypeDetector{
// 		rawContentTypeHeaderValues: rawContentTypes,
// 		charsetHeaderValues:        charsets,
// 		statedType:                 statedShort,
// 		inferredType:               inferredShort,
// 		isNoSniff:                  noSniff,
// 		isAttachment:               attachment,
// 	}
// }

// GetStatedType returns the stated content type short code determined from headers.
func (md *MimetypeDetector) GetStatedType() ContentType {
	return md.statedType
}

// GetInferredType returns the inferred content type short code determined from the body.
func (md *MimetypeDetector) GetInferredType() ContentType {
	return md.inferredType
}

// GetRawContentTypeHeaderValues returns the raw Content-Type header values.
func (md *MimetypeDetector) GetRawContentTypeHeaderValues() []string {
	if md.rawContentTypeHeaderValues == nil {
		return []string{}
	}
	values := make([]string, len(md.rawContentTypeHeaderValues))
	copy(values, md.rawContentTypeHeaderValues)
	return values
}

// GetCharsetHeaderValues returns the parsed charset values from Content-Type headers.
func (md *MimetypeDetector) GetCharsetHeaderValues() []string {
	if md.charsetHeaderValues == nil {
		return []string{}
	}
	values := make([]string, len(md.charsetHeaderValues))
	copy(values, md.charsetHeaderValues)
	return values
}

// GetIsNoSniff returns whether the X-Content-Type-Options: nosniff header was present.
func (md *MimetypeDetector) GetIsNoSniff() bool {
	return md.isNoSniff
}

// GetIsAttachment returns whether the Content-Disposition: attachment header was present.
func (md *MimetypeDetector) GetIsAttachment() bool {
	return md.isAttachment
}

// mapStringToContentType maps a MIME type string to its corresponding ContentType constant.
func mapStringToContentType(mimeString string) ContentType {
	normalizedMime := strings.ToLower(strings.TrimSpace(mimeString))

	// Handle common full MIME types first for precision
	switch normalizedMime {
	case "text/html":
		return ContentType_HTML
	case "text/plain":
		return ContentType_PLAIN_TEXT
	case "text/css":
		return ContentType_CSS
	case "application/javascript", "text/javascript":
		return ContentType_SCRIPT
	case "application/json", "text/json":
		return ContentType_JSON
	case "application/xml", "text/xml":
		return ContentType_XML
	case "application/rtf", "text/rtf":
		return ContentType_RTF
	case "application/yaml", "text/yaml", "application/x-yaml", "text/x-yaml":
		return ContentType_YAML
	case "image/svg+xml":
		return ContentType_SVG
	}

	// Handle partial matches, similar to user's original Go snippet's getType
	// This order matters if a more generic string could match multiple types.
	if strings.Contains(normalizedMime, "html") {
		return ContentType_HTML
	}
	if strings.Contains(normalizedMime, "json") { // e.g. "application/problem+json"
		return ContentType_JSON
	}
	if strings.Contains(normalizedMime, "javascript") ||
		strings.Contains(normalizedMime, "ecmascript") ||
		strings.Contains(normalizedMime, "jscript") {
		return ContentType_SCRIPT
	}
	if strings.Contains(normalizedMime, "css") {
		return ContentType_CSS
	}
	// text/xml, application/xml, application/atom+xml, application/rss+xml etc.
	if strings.Contains(normalizedMime, "xml") {
		// Check if it's SVG, which has its own code but is treated as XML by elu
		if strings.Contains(
			normalizedMime,
			"svg",
		) { // A more specific check for SVG if not image/svg+xml
			return ContentType_SVG
		}
		return ContentType_XML
	}
	if strings.Contains(normalizedMime, "yaml") || strings.Contains(normalizedMime, "yml") {
		return ContentType_YAML
	}
	if strings.Contains(normalizedMime, "rtf") {
		return ContentType_RTF
	}
	// Plain text is often a fallback
	if strings.Contains(normalizedMime, "text/plain") || normalizedMime == "text" {
		return ContentType_PLAIN_TEXT
	}

	// Fallback for unrecognized types
	if normalizedMime == "" {
		return ContentType_NONE
	}

	return ContentType_UNRECOGNIZED_CONTENT
}
