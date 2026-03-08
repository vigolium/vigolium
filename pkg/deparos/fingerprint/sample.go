package fingerprint

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/html"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// Sample represents a fingerprint sample from a single HTTP response
// Maps to Burp's elz.java fingerprint sample (Lines 6-70)
// Contains CRC32 hashes for all 32 attributes
type Sample struct {
	attributes map[Attribute]uint32 // CRC32 hashes for each attribute
	debug      string               // Human-readable description for debugging
}

// NewSampleFromRC creates a fingerprint sample from ResponseChain.
// Uses ResponseChain's cached HTML parsing when available.
func NewSampleFromRC(rc *responsechain.ResponseChain) (*Sample, error) {
	if rc == nil || !rc.Has() {
		return nil, fmt.Errorf("invalid ResponseChain")
	}

	resp := rc.Response()
	body := rc.BodyBytes()

	var htmlParsed *html.HTMLParsed

	// Parse HTML if content type is HTML AND body is not empty
	contentType := resp.Header.Get("Content-Type")
	if len(body) > 0 && strings.Contains(strings.ToLower(contentType), "html") {
		// Use ResponseChain's cached HTML parsing
		node, err := rc.ParseHTML()
		if err == nil && node != nil {
			htmlParsed = html.ParseFromNode(node)
		}
		// On parse error, htmlParsed stays nil - skip HTML attributes
	}

	return newSampleInternal(resp, htmlParsed, body)
}

// newSampleInternal is the internal sample creation function.
func newSampleInternal(resp *http.Response, htmlParsed *html.HTMLParsed, body []byte) (*Sample, error) {
	debugStr := fmt.Sprintf("status=%d", resp.StatusCode)
	if resp.Request != nil && resp.Request.URL != nil {
		debugStr = fmt.Sprintf("%s %d", resp.Request.URL.Path, resp.StatusCode)
	}

	s := &Sample{
		attributes: make(map[Attribute]uint32),
		debug:      debugStr,
	}

	// Extract all attributes
	s.extractStatus(resp)
	s.extractHeaders(resp)

	if htmlParsed != nil {
		s.extractHTML(htmlParsed)
	}

	if body != nil {
		s.extractContent(body)
	}

	return s, nil
}

// GetHash returns the hash for a specific attribute
// Returns 0 if attribute not present
func (s *Sample) GetHash(attr Attribute) uint32 {
	return s.attributes[attr]
}

// HasAttribute returns true if the attribute is present
func (s *Sample) HasAttribute(attr Attribute) bool {
	_, ok := s.attributes[attr]
	return ok
}

// AllAttributes returns all attributes present in the sample
func (s *Sample) AllAttributes() map[Attribute]uint32 {
	result := make(map[Attribute]uint32, len(s.attributes))
	for k, v := range s.attributes {
		result[k] = v
	}
	return result
}

// Debug returns debug description
func (s *Sample) Debug() string {
	return s.debug
}

// extractStatus extracts status-related attributes
// Maps to ad1.java:extractStatusAttributes() (Lines 20-25)
func (s *Sample) extractStatus(resp *http.Response) {
	// Attribute 1: StatusCode (critical, non-maskable)
	s.attributes[StatusCode] = uint32(resp.StatusCode)
}

// extractHeaders extracts header-related attributes
// Maps to ad1.java:extractHeaderAttributes() (Lines 27-70)
func (s *Sample) extractHeaders(resp *http.Response) {
	header := resp.Header

	// Attribute 3: ETag header (CRC32 hash)
	if etag := header.Get("Etag"); etag != "" {
		s.attributes[ETagHeader] = HashString(etag)
	}

	// Attribute 4: Last-Modified header (CRC32 hash)
	if lastMod := header.Get("Last-Modified"); lastMod != "" {
		s.attributes[LastModifiedHeader] = HashString(lastMod)
	}

	// Attribute 5: Content-Type (without charset) - critical, non-maskable
	if ct := header.Get("Content-Type"); ct != "" {
		cleanCT := ParseContentType(ct)
		if cleanCT != "" {
			s.attributes[ContentType] = HashString(cleanCT)
		}
	}

	// Attribute 7: Content-Length
	if cl := header.Get("Content-Length"); cl != "" {
		if length, err := strconv.Atoi(cl); err == nil {
			s.attributes[ContentLength] = uint32(length)
		}
	}

	// Attribute 8: Cookie names (CRC32 accumulated, sorted)
	if cookies := header.Values("Set-Cookie"); len(cookies) > 0 {
		cookieNames := ExtractCookieNames(cookies)
		if len(cookieNames) > 0 {
			s.attributes[CookieNames] = HashStringSet(cookieNames)
		}
	}

	// Attribute 18: Canonical Link header
	if canonical := header.Get("Link"); canonical != "" && strings.Contains(canonical, "canonical") {
		s.attributes[CanonicalLink] = HashString(canonical)
	}

	// Attribute 31: Content-Location header
	if contentLoc := header.Get("Content-Location"); contentLoc != "" {
		s.attributes[ContentLocation] = HashString(contentLoc)
	}

	// Attribute 32: Location header (CRC32 hash)
	if location := header.Get("Location"); location != "" {
		s.attributes[Location] = HashString(location)
	}
}

// extractHTML extracts HTML structure attributes
// Maps to ad1.java:extractHTMLAttributes() (Lines 72-130)
func (s *Sample) extractHTML(htmlParsed *html.HTMLParsed) {
	// Attribute 9: Tag names (CRC32 accumulated)
	if len(htmlParsed.TagNames) > 0 {
		s.attributes[TagNames] = HashStrings(htmlParsed.TagNames)
	}

	// Attribute 10: Tag IDs (CRC32 accumulated)
	if len(htmlParsed.TagIDs) > 0 {
		s.attributes[TagIDs] = HashStrings(htmlParsed.TagIDs)
	}

	// Attribute 11: Div IDs (CRC32 accumulated)
	if len(htmlParsed.DivIDs) > 0 {
		s.attributes[DivIDs] = HashStrings(htmlParsed.DivIDs)
	}

	// Attribute 25: CSS Classes (CRC32 accumulated)
	if len(htmlParsed.CSSClasses) > 0 {
		s.attributes[CSSClasses] = HashStrings(htmlParsed.CSSClasses)
	}

	// Attribute 19: Page title (CRC32 hash)
	if htmlParsed.Title != "" {
		s.attributes[PageTitle] = HashString(htmlParsed.Title)
	}

	// Attribute 20: First header tag (h1-h6)
	if len(htmlParsed.HeaderTags) > 0 {
		s.attributes[FirstHeaderTag] = HashString(htmlParsed.HeaderTags[0])
	}

	// Attribute 21: All header tags (CRC32 accumulated)
	if len(htmlParsed.HeaderTags) > 0 {
		s.attributes[HeaderTags] = HashStrings(htmlParsed.HeaderTags)
	}

	// Attribute 16: HTML comments (CRC32 accumulated)
	if len(htmlParsed.Comments) > 0 {
		s.attributes[Comments] = HashStrings(htmlParsed.Comments)
	}

	// Attribute 22: Anchor labels (CRC32 accumulated)
	if len(htmlParsed.AnchorLabels) > 0 {
		s.attributes[AnchorLabels] = HashStrings(htmlParsed.AnchorLabels)
	}

	// Attribute 28: Outbound edge count
	if htmlParsed.OutboundLinkCount > 0 {
		s.attributes[OutboundEdgeCount] = uint32(htmlParsed.OutboundLinkCount)
	}

	// Attribute 29: Outbound edge tag names (CRC32 accumulated)
	if len(htmlParsed.OutboundTagNames) > 0 {
		s.attributes[OutboundEdgeTagNames] = HashStrings(htmlParsed.OutboundTagNames)
	}

	// Attribute 23: Input submit labels (CRC32 accumulated)
	if len(htmlParsed.InputSubmitLabels) > 0 {
		s.attributes[InputSubmitLabels] = HashStrings(htmlParsed.InputSubmitLabels)
	}

	// Attribute 24: Button submit labels (CRC32 accumulated)
	if len(htmlParsed.ButtonSubmitLabels) > 0 {
		s.attributes[ButtonSubmitLabels] = HashStrings(htmlParsed.ButtonSubmitLabels)
	}

	// Attribute 30: Input image labels (CRC32 accumulated)
	if len(htmlParsed.InputImageLabels) > 0 {
		s.attributes[InputImageLabels] = HashStrings(htmlParsed.InputImageLabels)
	}

	// Attribute 33: Non-hidden form input types (CRC32 accumulated)
	if len(htmlParsed.NonHiddenInputTypes) > 0 {
		s.attributes[NonHiddenFormInputTypes] = HashStrings(htmlParsed.NonHiddenInputTypes)
	}

	// Content attributes from HTML
	// Attribute 13: Visible text (CRC32 hash)
	if htmlParsed.VisibleText != "" {
		s.attributes[VisibleText] = HashString(htmlParsed.VisibleText)
	}

	// Attribute 14: Word count
	if htmlParsed.WordCount > 0 {
		s.attributes[WordCount] = uint32(htmlParsed.WordCount)
	}

	// Attribute 15: Visible word count (same as word count for now)
	if htmlParsed.WordCount > 0 {
		s.attributes[VisibleWordCount] = uint32(htmlParsed.WordCount)
	}

	// Attribute 26: Line count
	if htmlParsed.LineCount > 0 {
		s.attributes[LineCount] = uint32(htmlParsed.LineCount)
	}
}

// extractContent extracts content-based attributes from raw body
// Maps to ad1.java:extractContentAttributes() (Lines 132-158)
func (s *Sample) extractContent(body []byte) {
	if len(body) == 0 {
		return
	}

	// Attribute 12: Full body content (CRC32 hash)
	s.attributes[BodyContent] = HashBytes(body)

	// Attribute 17: Initial content (first 1KB, CRC32 hash)
	initial := TruncateBytes(body, InitialContentBytes)
	if len(initial) > 0 {
		s.attributes[InitialContent] = HashBytes(initial)
	}

	// Attribute 27: Limited body content (first 10KB, CRC32 hash)
	limited := TruncateBytes(body, LimitedContentBytes)
	if len(limited) > 0 {
		s.attributes[LimitedBodyContent] = HashBytes(limited)
	}

	// Attribute 16: Last content (last N bytes, CRC32 hash)
	if len(body) > LastContentBytes {
		s.attributes[LastContent] = HashBytes(body[len(body)-LastContentBytes:])
	} else {
		s.attributes[LastContent] = HashBytes(body)
	}
}

// NewSampleFromAttrs creates a Sample from pre-stored fingerprint attributes.
// Used for anomaly filtering where attributes are loaded directly from database.
func NewSampleFromAttrs(attrs map[uint8]uint32) *Sample {
	s := &Sample{
		attributes: make(map[Attribute]uint32, len(attrs)),
		debug:      "from-db",
	}
	for id, hash := range attrs {
		s.attributes[Attribute(id)] = hash
	}
	return s
}
