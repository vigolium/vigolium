package burpraw

import (
	"fmt"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"go.uber.org/zap"
)

// Format implements formats.Format for raw Burp Suite request files.
// These are single request files exported via "Copy as raw" or "Save item",
// containing a request followed optionally by a *** separator and a response.
type Format struct {
	formatOpts formats.InputFormatOptions
}

// New creates a new burpraw Format parser.
func New() *Format {
	return &Format{}
}

var _ formats.Format = &Format{}

// Name returns the format name.
func (f *Format) Name() string {
	return "burpraw"
}

// SetOptions sets generic format options.
func (f *Format) SetOptions(options formats.InputFormatOptions) {
	f.formatOpts = options
}

// Parse reads a raw Burp request file and calls callback with the parsed request.
// The file contains a single HTTP request, optionally followed by *** separator and response.
func (f *Format) Parse(input string, callback formats.ParseReqRespCallback) error {
	data, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("failed to read burp raw file: %w", err)
	}

	content := string(data)

	// Split on *** separator to separate request from response
	requestPart := content
	if idx := findSeparator(content); idx >= 0 {
		requestPart = content[:idx]
	}

	// Trim trailing whitespace from the request part
	requestPart = strings.TrimRight(requestPart, "\r\n ")

	if requestPart == "" {
		return fmt.Errorf("empty request in burp raw file")
	}

	// Infer the full URL from request headers
	url := inferURL(requestPart)

	var rr *httpmsg.HttpRequestResponse
	if url != "" {
		rr, err = httpmsg.ParseRawRequestWithURL(requestPart, url)
	} else {
		rr, err = httpmsg.ParseRawRequest(requestPart)
	}
	if err != nil {
		return fmt.Errorf("failed to parse burp raw request: %w", err)
	}

	callback(rr)
	return nil
}

// Count returns 1 since a burp raw file contains a single request.
func (f *Format) Count(input string) (int64, error) {
	return 1, nil
}

// findSeparator finds the position of the *** separator between request and response.
// Returns -1 if not found.
func findSeparator(content string) int {
	// Try \n***\n first (Unix line endings)
	if idx := strings.Index(content, "\n***\n"); idx >= 0 {
		return idx
	}
	// Try \r\n***\r\n (Windows line endings)
	if idx := strings.Index(content, "\r\n***\r\n"); idx >= 0 {
		return idx
	}
	return -1
}

// inferURL builds a full URL from the request's Host header and method line.
// It checks Origin and Referer headers to determine the scheme, defaulting to https.
func inferURL(raw string) string {
	lines := strings.Split(raw, "\n")
	if len(lines) < 2 {
		return ""
	}

	// Extract path from method line (e.g., "POST /v4/cb/events/clientapp HTTP/2")
	methodLine := strings.TrimRight(lines[0], "\r")
	parts := strings.SplitN(methodLine, " ", 3)
	if len(parts) < 2 {
		return ""
	}
	path := parts[1]

	// Extract Host header value
	var host string
	var scheme string
	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break // End of headers
		}
		headerName, headerValue, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch strings.ToLower(headerName) {
		case "host":
			host = headerValue
		case "origin":
			scheme = extractSchemeForHost(headerValue, host)
		case "referer":
			if scheme == "" {
				scheme = extractSchemeForHost(headerValue, host)
			}
		}
	}

	if host == "" {
		return ""
	}

	if scheme == "" {
		scheme = "https" // Default to https for Burp captures
	}

	return scheme + "://" + host + path
}

// extractSchemeForHost extracts the scheme from a URL if it matches the given host.
func extractSchemeForHost(urlStr, host string) string {
	if host == "" {
		return ""
	}
	// Check if the URL starts with https:// or http:// and contains the host
	if strings.HasPrefix(urlStr, "https://") && strings.Contains(urlStr, host) {
		return "https"
	}
	if strings.HasPrefix(urlStr, "http://") && strings.Contains(urlStr, host) {
		return "http"
	}

	zap.L().Debug("burpraw: origin/referer does not match host",
		zap.String("url", urlStr),
		zap.String("host", host))
	return ""
}
