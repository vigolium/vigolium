package spider

import (
	"bytes"
	"context"
	"net/url"
	"unicode"
)

// InlineURLScanner scans raw bytes for inline URL patterns.
// It searches for http://, https://, ws://, wss:// and extracts complete URLs.
//
// This is a SHARED component injected into multiple extractors:
// - JavaScript string parser
// - Event handler parser
// - Meta refresh parser
// - Script content parser
type InlineURLScanner struct {
	urlResolver *URLResolver
}

// URL protocol prefixes to scan for
var (
	protocolHTTPS = []byte("https://")
	protocolHTTP  = []byte("http://")
	protocolWSS   = []byte("wss://")
	protocolWS    = []byte("ws://")
	protocolAny   = []byte("://")

	// All protocols in scan order (longest first)
	protocols = [][]byte{protocolHTTPS, protocolHTTP, protocolWSS, protocolWS}

	// URL terminators (characters that end a URL)
	terminators = [][]byte{
		{'<'},
		{'>'},
		{'\''},
		{'"'},
		{'&', 'q', 'u', 'o', 't', ';'}, // &quot;
		{'&', 'g', 't', ';'},           // &gt;
		{')'},
		{']'},
		{'}'},
		{' '},
		{'\r'},
		{'\n'},
	}

	// Relative path prefixes
	relativeSlash     = []byte("/")
	relativeDotSlash  = []byte("./")
	relativeDotDot    = []byte("../")
	relativesPrefixes = [][]byte{relativeSlash, relativeDotSlash, relativeDotDot}
)

// NewInlineURLScanner creates a new inline URL scanner.
func NewInlineURLScanner(urlResolver *URLResolver) *InlineURLScanner {
	return &InlineURLScanner{
		urlResolver: urlResolver,
	}
}

// Extract scans the response body for inline URLs and reports them via callback.
func (s *InlineURLScanner) Extract(ctx context.Context, baseURL *url.URL, response *HTTPResponse, callback LinkCallback) error {
	// Scan for URLs in the body
	positions := s.findProtocolPositions(response.Body, 0)

	for _, pos := range positions {
		// Extract URL at this position
		urlStr, startPos, endPos := s.extractURLAt(response.Body, pos, response.BodyStart)

		if urlStr == "" {
			continue
		}

		// Resolve against base URL
		resolved, err := s.urlResolver.Resolve(baseURL, urlStr)
		if err != nil {
			continue
		}

		// Infer resource type from extension
		resourceType := s.inferResourceType(resolved.Path)

		// Report discovered link
		link := &DiscoveredLink{
			SourceType:   SourceInlineURL,
			URL:          resolved,
			RawURL:       urlStr,
			ResourceType: resourceType,
			StartPos:     startPos,
			EndPos:       endPos,
		}

		callback(link)
	}

	return nil
}

// ScanBytes scans a byte slice for an inline URL (absolute first, then relative)
// and reports whether one was found, WITHOUT emitting it. Used as a bool-only
// "does this string contain a URL?" check; ScanBytesRelativeEmit is the emitting
// variant.
func (s *InlineURLScanner) ScanBytes(ctx context.Context, baseURL *url.URL, data []byte, offset int) bool {
	if len(data) < 6 {
		return false
	}
	urlStr, startPos, endPos := s.findAbsoluteURL(data, offset)
	if urlStr == "" {
		urlStr, startPos, endPos = s.findRelativeURL(baseURL, data, offset)
	}
	return s.resolveAndEmit(baseURL, urlStr, startPos, endPos, nil)
}

// ScanBytesRelativeEmit scans a byte slice for a RELATIVE inline URL only,
// resolves it against baseURL, and — when callback is non-nil — emits the
// discovered link. Returns true when a relative URL was found and resolved.
//
// This closes a real coverage gap: the bool-only ScanBytes detected URL-like
// data but DROPPED it, so relative routes such as /admin or /api/users found
// inside JavaScript string literals were never surfaced as discovered links.
// It is deliberately relative-only: every caller also runs a whole-content pass
// that emits absolute (scheme) URLs, so per-string scanning contributes just the
// relative routes that pass would miss — without duplicating the absolute ones.
func (s *InlineURLScanner) ScanBytesRelativeEmit(ctx context.Context, baseURL *url.URL, data []byte, offset int, callback LinkCallback) bool {
	if len(data) < 6 {
		return false
	}
	urlStr, startPos, endPos := s.findRelativeURL(baseURL, data, offset)
	return s.resolveAndEmit(baseURL, urlStr, startPos, endPos, callback)
}

// resolveAndEmit resolves a raw URL string against baseURL and, when callback is
// non-nil and resolution succeeds, emits the discovered link. Returns true when
// the URL was found and resolved.
func (s *InlineURLScanner) resolveAndEmit(baseURL *url.URL, urlStr string, startPos, endPos int, callback LinkCallback) bool {
	if urlStr == "" {
		return false
	}

	// Reject malformed raw before resolving (urlResolver.Resolve may be more
	// lenient than url.Parse).
	if _, err := url.Parse(urlStr); err != nil {
		return false
	}

	resolved, err := s.urlResolver.Resolve(baseURL, urlStr)
	if err != nil {
		return false
	}

	if resolved == nil || endPos <= startPos {
		return false
	}

	if callback != nil {
		callback(&DiscoveredLink{
			SourceType:   SourceInlineURL,
			URL:          resolved,
			RawURL:       urlStr,
			ResourceType: s.inferResourceType(resolved.Path),
			StartPos:     startPos,
			EndPos:       endPos,
		})
	}

	return true
}

// findProtocolPositions finds all positions where :// appears in the data.
func (s *InlineURLScanner) findProtocolPositions(data []byte, offset int) []int {
	positions := []int{}
	searchStart := offset

	for searchStart < len(data) {
		// Find next occurrence of ://
		idx := bytes.Index(data[searchStart:], protocolAny)
		if idx == -1 {
			break
		}

		protoPos := searchStart + idx

		// Now find the actual protocol prefix (http://, https://, etc.)
		actualStart := s.findProtocolStart(data, offset, protoPos)
		if actualStart != -1 {
			positions = append(positions, actualStart)
		}

		searchStart = protoPos + len(protocolAny) + 2
	}

	return positions
}

// findProtocolStart finds the start of a protocol given the position of ://
func (s *InlineURLScanner) findProtocolStart(data []byte, offset int, colonSlashPos int) int {
	// Check https:// (5 bytes before ://)
	if colonSlashPos >= offset+5 && bytes.Equal(data[colonSlashPos-5:colonSlashPos+3], protocolHTTPS) {
		return colonSlashPos - 5
	}

	// Check http:// (4 bytes before ://)
	if colonSlashPos >= offset+4 && bytes.Equal(data[colonSlashPos-4:colonSlashPos+3], protocolHTTP) {
		return colonSlashPos - 4
	}

	// Check wss:// (3 bytes before ://)
	if colonSlashPos >= offset+3 && bytes.Equal(data[colonSlashPos-3:colonSlashPos+3], protocolWSS) {
		return colonSlashPos - 3
	}

	// Check ws:// (2 bytes before ://)
	if colonSlashPos >= offset+2 && bytes.Equal(data[colonSlashPos-2:colonSlashPos+3], protocolWS) {
		return colonSlashPos - 2
	}

	return -1
}

// extractURLAt extracts the URL starting at the given position.
func (s *InlineURLScanner) extractURLAt(data []byte, pos int, offset int) (string, int, int) {
	if len(data) < 6 {
		return "", 0, 0
	}

	// Determine protocol length
	protocolLen := s.getProtocolLength(data, pos)

	// Scan for URL terminator
	start := pos + protocolLen
	end := len(data)

	for i := start; i < len(data); i++ {
		if s.isTerminator(data, i) {
			end = i
			break
		}
	}

	// URL must have at least protocol + 3 chars (e.g., "http://a.b")
	urlLen := end - pos
	if urlLen < protocolLen+3 {
		return "", offset + pos, offset + end
	}

	// Extract and return
	urlStr := string(data[pos:end])
	return urlStr, offset + pos, offset + end
}

// getProtocolLength returns the length of the protocol at the given position.
func (s *InlineURLScanner) getProtocolLength(data []byte, pos int) int {
	for _, proto := range protocols {
		if bytes.HasPrefix(data[pos:], proto) {
			return len(proto)
		}
	}
	return 1
}

// isTerminator checks if the byte at pos is a URL terminator.
func (s *InlineURLScanner) isTerminator(data []byte, pos int) bool {
	for _, term := range terminators {
		if bytes.HasPrefix(data[pos:], term) {
			return true
		}
	}
	return false
}

// findAbsoluteURL finds the first absolute URL in the data.
func (s *InlineURLScanner) findAbsoluteURL(data []byte, offset int) (string, int, int) {
	if len(data) < 6 {
		return "", 0, 0
	}

	// Find first protocol
	minPos := len(data)
	for _, proto := range protocols {
		idx := bytes.Index(data, proto)
		if idx != -1 && idx < minPos {
			minPos = idx
		}
	}

	if minPos == len(data) {
		return "", 0, 0
	}

	return s.extractURLAt(data, minPos, offset)
}

// findRelativeURL attempts to extract a relative URL from the data.
//
// baseURL is accepted for API consistency with other extraction methods,
// though relative URL syntax validation requires only the data bytes.
// The caller must perform URL resolution against baseURL after extraction.
func (s *InlineURLScanner) findRelativeURL(baseURL *url.URL, data []byte, offset int) (string, int, int) {
	_ = baseURL // Accepted for API consistency, resolution handled by caller
	if len(data) < 6 {
		return "", 0, 0
	}

	// Find first non-whitespace character
	start := 0
	for start < len(data) && data[start] <= ' ' {
		start++
	}

	if start >= len(data) {
		return "", 0, 0
	}

	// Check if it starts with a relative path prefix
	if !s.startsWithRelativePrefix(data, start) {
		return "", 0, 0
	}

	// Scan the URL
	hasSlash := false
	hasDot := false
	inQueryOrFragment := false
	end := start + 1

	for end < len(data) {
		b := data[end]

		// Check for non-printable or non-ASCII
		if b <= 32 || b >= 127 {
			return "", 0, 0
		}

		if !inQueryOrFragment {
			switch b {
			case '/':
				hasSlash = true
			case '.':
				hasDot = true
			case '#':
				// Fragment - URL must have slash or dot and be at least 6 chars
				if (!hasDot && !hasSlash) || end < 6 {
					return "", 0, 0
				}
			case '?', ';':
				// Query - URL must have slash or dot and be at least 6 chars
				if (!hasDot && !hasSlash) || end < 6 {
					return "", 0, 0
				}
				inQueryOrFragment = true
			default:
				if !isValidURLChar(b) {
					return "", 0, 0
				}
			}
		}

		end++
	}

	urlStr := string(data[start:end])
	return urlStr, offset + start, offset + end
}

// startsWithRelativePrefix checks if data starts with /, ./, or ../
func (s *InlineURLScanner) startsWithRelativePrefix(data []byte, pos int) bool {
	for _, prefix := range relativesPrefixes {
		if bytes.HasPrefix(data[pos:], prefix) {
			return true
		}
	}
	return false
}

// isValidURLChar checks if a byte is valid in a URL path.
func isValidURLChar(b byte) bool {
	return unicode.IsLetter(rune(b)) || unicode.IsDigit(rune(b)) || b == '-' || b == '_'
}

// inferResourceType infers the resource type from the URL path extension.
func (s *InlineURLScanner) inferResourceType(path string) ResourceType {
	// Find the last dot
	lastDot := -1
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			lastDot = i
			break
		}
		// Stop at path separator
		if path[i] == '/' {
			break
		}
	}

	if lastDot == -1 {
		return ResourceUnknown
	}

	ext := path[lastDot:]

	switch ext {
	case ".jpg", ".jpeg":
		return ResourceJPEG
	case ".png":
		return ResourcePNG
	case ".gif":
		return ResourceGIF
	case ".bmp":
		return ResourceBMP
	case ".tiff", ".tif":
		return ResourceTIFF
	case ".js":
		return ResourceScript
	case ".html", ".htm":
		return ResourceHTML
	case ".mp3", ".wav", ".ogg":
		return ResourceAudio
	case ".mp4", ".avi", ".mov":
		return ResourceVideo
	default:
		return ResourceUnknown
	}
}

// Ensure InlineURLScanner implements spider.LinkExtractor
var _ LinkExtractor = (*InlineURLScanner)(nil)
