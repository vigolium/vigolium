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
//
// Burp mapping: uc.java (Inline URL scanner)
type InlineURLScanner struct {
	urlResolver *URLResolver
}

// URL protocol prefixes to scan for
var (
	// Burp mapping: uc.java lines 8-11
	protocolHTTPS = []byte("https://") // Line 9: {104, 116, 116, 112, 115, 58, 47, 47}
	protocolHTTP  = []byte("http://")  // Line 8: {104, 116, 116, 112, 58, 47, 47}
	protocolWSS   = []byte("wss://")   // Line 11: {119, 115, 115, 58, 47, 47}
	protocolWS    = []byte("ws://")    // Line 10: {119, 115, 58, 47, 47}
	protocolAny   = []byte("://")      // Line 12: {58, 47, 47}

	// All protocols in scan order (longest first)
	// Burp mapping: uc.java line 13: a = {j, l, k, d}
	protocols = [][]byte{protocolHTTPS, protocolHTTP, protocolWSS, protocolWS}

	// URL terminators (characters that end a URL)
	// Burp mapping: uc.java lines 17-19
	terminators = [][]byte{
		{'<'},                          // Line 17
		{'>'},                          // Line 17
		{'\''},                         // Line 17
		{'"'},                          // Line 17
		{'&', 'q', 'u', 'o', 't', ';'}, // &quot;
		{'&', 'g', 't', ';'},           // &gt;
		{')'},                          // Line 17
		{']'},                          // Line 17
		{'}'},                          // Line 17
		{' '},                          // Space
		{'\r'},                         // CR
		{'\n'},                         // LF
	}

	// Relative path prefixes
	// Burp mapping: uc.java lines 14-16
	relativeSlash     = []byte("/")   // Line 14
	relativeDotSlash  = []byte("./")  // Line 15
	relativeDotDot    = []byte("../") // Line 16
	relativesPrefixes = [][]byte{relativeSlash, relativeDotSlash, relativeDotDot}
)

// NewInlineURLScanner creates a new inline URL scanner.
func NewInlineURLScanner(urlResolver *URLResolver) *InlineURLScanner {
	return &InlineURLScanner{
		urlResolver: urlResolver,
	}
}

// Extract scans the response body for inline URLs and reports them via callback.
//
// Burp mapping: uc.a(byte[] var1, int var2, byte var3, fi3 var4) - Lines 42-56
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

// ScanBytes scans a byte slice for inline URLs and reports them.
// This is used by other extractors to scan string literals.
//
// Burp mapping: uc.a(hik var1, byte[] var2, int var3, byte var4, fi3 var5) - Lines 27-40
func (s *InlineURLScanner) ScanBytes(ctx context.Context, baseURL *url.URL, data []byte, offset int) bool {
	if len(data) < 6 {
		return false
	}

	// Try to find an absolute URL first
	// Burp mapping: uc.a(byte[] var1, int var2) - Lines 113-120
	urlStr, startPos, endPos := s.findAbsoluteURL(data, offset)

	if urlStr == "" {
		// Try to find a relative URL
		// Burp mapping: uc.a(hik var1, byte[] var2, int var3) - Lines 195-265
		urlStr, startPos, endPos = s.findRelativeURL(baseURL, data, offset)
	}

	if urlStr == "" {
		return false
	}

	// Parse and resolve
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	resolved, err := s.urlResolver.Resolve(baseURL, urlStr)
	if err != nil {
		return false
	}

	return resolved != nil && u != nil && endPos > startPos
}

// findProtocolPositions finds all positions where :// appears in the data.
//
// Burp mapping: uc.b(byte[] var1, int var2) - Lines 58-91
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
		// Burp mapping: uc.a(byte[] var1, int var2, int var3) - Lines 93-103
		actualStart := s.findProtocolStart(data, offset, protoPos)
		if actualStart != -1 {
			positions = append(positions, actualStart)
		}

		searchStart = protoPos + len(protocolAny) + 2
	}

	return positions
}

// findProtocolStart finds the start of a protocol given the position of ://
//
// Burp mapping: uc.a(byte[] var1, int var2, int var3) - Lines 93-103
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
//
// Burp mapping: uc.b(byte[] var1, int var2, int var3) - Lines 122-151
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
//
// Burp mapping: uc.e(byte[] var1, int var2) - Lines 153-173
func (s *InlineURLScanner) getProtocolLength(data []byte, pos int) int {
	for _, proto := range protocols {
		if bytes.HasPrefix(data[pos:], proto) {
			return len(proto)
		}
	}
	return 1
}

// isTerminator checks if the byte at pos is a URL terminator.
//
// Burp mapping: uc.d(byte[] var1, int var2) - Lines 271-291
func (s *InlineURLScanner) isTerminator(data []byte, pos int) bool {
	for _, term := range terminators {
		if bytes.HasPrefix(data[pos:], term) {
			return true
		}
	}
	return false
}

// findAbsoluteURL finds the first absolute URL in the data.
//
// Burp mapping: uc.a(byte[] var1, int var2) - Lines 113-120
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
//
// Burp mapping: uc.a(hik var1, byte[] var2, int var3) - Lines 195-265
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
	// Burp mapping: uc.c(byte[] var1, int var2) - Lines 267-269
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
//
// Burp mapping: uc.c(byte[] var1, int var2) - Lines 267-269
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
