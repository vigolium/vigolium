package detect

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/curl"
)

// StdinFormat represents a detected stdin input format.
type StdinFormat string

const (
	FormatRawHTTP  StdinFormat = "raw_http"
	FormatBurpPair StdinFormat = "burp_pair"
	FormatCurl     StdinFormat = "curl"
	FormatURLs     StdinFormat = "urls"
)

// knownHTTPMethods is the set of standard HTTP methods used for raw HTTP detection.
var knownHTTPMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "HEAD": true, "OPTIONS": true, "TRACE": true,
	"CONNECT": true,
}

// DetectStdinFormat inspects the content and determines the input format.
// Detection heuristics (in order):
//  1. Burp pair: first non-empty line is raw HTTP AND content contains "***" separator
//  2. Raw HTTP: first non-empty line matches "METHOD /path HTTP/x.x"
//  3. Curl: first non-empty line starts with "curl " (after stripping leading "$ ")
//  4. Fallback: URLs
func DetectStdinFormat(content string) StdinFormat {
	firstLine := firstNonEmptyLine(content)
	if firstLine == "" {
		return FormatURLs
	}

	// Check raw HTTP: 3 fields, first is known method, third starts with "HTTP/"
	fields := strings.Fields(firstLine)
	if len(fields) >= 3 && knownHTTPMethods[fields[0]] && strings.HasPrefix(fields[2], "HTTP/") {
		// Upgrade to burp_pair when a Burp-style "***" separator is present.
		if idx, _, ok := FindBurpSeparator(content); ok && idx > 0 {
			return FormatBurpPair
		}
		return FormatRawHTTP
	}

	// Check curl: strip leading "$ " prompt, then check for "curl " prefix
	trimmed := strings.TrimPrefix(firstLine, "$ ")
	trimmed = strings.TrimSpace(trimmed)
	if strings.HasPrefix(trimmed, "curl ") || trimmed == "curl" {
		return FormatCurl
	}

	return FormatURLs
}

// ParseStdinContent parses the given content according to the specified format.
func ParseStdinContent(content string, format StdinFormat) ([]*httpmsg.HttpRequestResponse, error) {
	switch format {
	case FormatRawHTTP:
		rr, err := parseRawRequestWithInferredURL(content)
		if err != nil {
			return nil, fmt.Errorf("failed to parse raw HTTP request: %w", err)
		}
		return []*httpmsg.HttpRequestResponse{rr}, nil

	case FormatBurpPair:
		rr, err := ParseBurpPair(content)
		if err != nil {
			return nil, fmt.Errorf("failed to parse burp request/response pair: %w", err)
		}
		return []*httpmsg.HttpRequestResponse{rr}, nil

	case FormatCurl:
		// Strip leading "$ " prompt if present
		cmd := strings.TrimPrefix(strings.TrimSpace(content), "$ ")
		rr, err := curl.ParseSingleCommand(cmd)
		if err != nil {
			return nil, fmt.Errorf("failed to parse curl command: %w", err)
		}
		return []*httpmsg.HttpRequestResponse{rr}, nil

	case FormatURLs:
		var results []*httpmsg.HttpRequestResponse
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			rr, err := httpmsg.GetRawRequestFromURL(line)
			if err != nil {
				return nil, fmt.Errorf("failed to parse URL %q: %w", line, err)
			}
			results = append(results, rr)
		}
		if len(results) == 0 {
			return nil, fmt.Errorf("no valid URLs found in input")
		}
		return results, nil

	default:
		return nil, fmt.Errorf("unknown stdin format: %s", format)
	}
}

// firstNonEmptyLine returns the first non-empty, non-whitespace-only line.
func firstNonEmptyLine(content string) string {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}
