package fingerprint

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/html"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// Sample represents a fingerprint sample from a single HTTP response
// Contains CRC32 hashes for all 32 attributes
type Sample struct {
	attributes map[Attribute]uint32 // CRC32 hashes for each attribute
	debug      string               // Human-readable description for debugging
	// Live-response facts (zero for samples rebuilt from stored attributes).
	throttled bool // 429/503/edge block: the answer says nothing about the path
	bodyLen   int  // body length after normalization; -1 when unknown
}

// NewSampleFromRC creates a fingerprint sample from ResponseChain.
//
// When the response carries a request URL, the body is normalized via
// NormalizeBody before any hashing or HTML parsing. This stabilizes hashes
// across probes whose responses echo the requested URL (a common soft-404
// pattern, e.g. Juice Shop's /ftp returning the path in every 403 body).
//
// HTML parsing in this path uses a fresh parse of the normalized bytes
// rather than ResponseChain's cached parse, so HTML-derived attributes
// (Title, VisibleText, WordCount, LineCount) reflect the normalized body.
// The cached parse is left untouched for non-fingerprint consumers (spider).
func NewSampleFromRC(rc *responsechain.ResponseChain) (*Sample, error) {
	if rc == nil || !rc.Has() {
		return nil, fmt.Errorf("invalid ResponseChain")
	}

	// The sample is a pure (and expensive: HTML parse + full-body hashing)
	// function of the chain's current state, and the same chain is sampled by
	// both soft-404 analysis and fingerprint storage. Memoize on the chain so
	// the second consumer reuses the first's work.
	v, err := rc.CachedFingerprint(func() (any, error) {
		return computeSampleFromRC(rc)
	})
	if err != nil {
		return nil, err
	}
	s, _ := v.(*Sample)
	return s, nil
}

// computeSampleFromRC performs the actual (uncached) sample extraction.
func computeSampleFromRC(rc *responsechain.ResponseChain) (*Sample, error) {
	resp := rc.Response()
	body := rc.BodyBytes()

	// Apply path-aware normalization when the request URL is available.
	if resp.Request != nil && resp.Request.URL != nil && len(body) > 0 {
		if normalized := NormalizeBody(body, resp.Request.URL); !bytes.Equal(normalized, body) {
			body = normalized
		}
	}

	var htmlParsed *html.HTMLParsed

	// Parse HTML if content type is HTML AND body is not empty
	contentType := resp.Header.Get("Content-Type")
	if len(body) > 0 && strings.Contains(strings.ToLower(contentType), "html") {
		// Parse from normalized bytes when normalization changed the body;
		// otherwise reuse ResponseChain's cached parse for performance.
		if resp.Request != nil && resp.Request.URL != nil {
			parser := html.NewParser()
			if hp, err := parser.Parse(bytes.NewReader(body)); err == nil && hp != nil {
				htmlParsed = hp
			}
		} else {
			node, err := rc.ParseHTML()
			if err == nil && node != nil {
				htmlParsed = html.ParseFromNode(node)
			}
		}
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
		throttled:  IsThrottledResponse(resp.StatusCode, resp.Header, body),
		bodyLen:    len(body),
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

// Status is the sample's HTTP status code (0 when unknown).
func (s *Sample) Status() int { return int(s.attributes[StatusCode]) }

// Throttled reports a 429/503/edge-block answer: it carries no information
// about whether the probed path exists.
func (s *Sample) Throttled() bool { return s.throttled }

// Resembles reports whether two responses look like the same page: same status
// and content type, and either the same HTML tag structure or a body length
// within max(16 bytes, 2%). Soft-404 validation drops a hit only when a
// never-existent sibling resembles it.
func (s *Sample) Resembles(o *Sample) bool {
	if s == nil || o == nil {
		return false
	}
	if s.Status() != o.Status() || s.GetHash(ContentType) != o.GetHash(ContentType) {
		return false
	}
	if s.HasAttribute(TagNames) && o.HasAttribute(TagNames) && s.GetHash(TagNames) == o.GetHash(TagNames) {
		return true
	}
	if s.bodyLen < 0 || o.bodyLen < 0 {
		// A stored sample has no length: fall back to the full-body hash.
		return s.HasAttribute(BodyContent) && s.GetHash(BodyContent) == o.GetHash(BodyContent)
	}
	a, b := s.bodyLen, o.bodyLen
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	tol := max(a, b) / 50
	if tol < 16 {
		tol = 16
	}
	return diff <= tol
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
func (s *Sample) extractStatus(resp *http.Response) {
	// Attribute 1: StatusCode (critical, non-maskable)
	s.attributes[StatusCode] = uint32(resp.StatusCode)
}

// extractHeaders extracts header-related attributes
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
		bodyLen:    -1,
	}
	for id, hash := range attrs {
		s.attributes[Attribute(id)] = hash
	}
	return s
}
