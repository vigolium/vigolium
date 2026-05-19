package detect

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// FindBurpSeparator locates the "***" line that separates request from response
// in a Burp-style raw capture. Returns the byte index of the separator, the
// separator length (so callers can slice the response body), and a boolean
// indicating whether the separator was found.
func FindBurpSeparator(content string) (int, int, bool) {
	if idx := strings.Index(content, "\n***\n"); idx >= 0 {
		return idx, len("\n***\n"), true
	}
	if idx := strings.Index(content, "\r\n***\r\n"); idx >= 0 {
		return idx, len("\r\n***\r\n"), true
	}
	return -1, 0, false
}

// SplitBurpPair splits Burp-style raw content into request and response halves
// at the "***" separator. The response part is empty when no separator is
// present. Trailing whitespace on the request part is trimmed.
func SplitBurpPair(content string) (request, response string, hasResponse bool) {
	idx, sepLen, ok := FindBurpSeparator(content)
	if !ok {
		return strings.TrimRight(content, "\r\n "), "", false
	}
	req := strings.TrimRight(content[:idx], "\r\n ")
	resp := strings.TrimLeft(content[idx+sepLen:], "\r\n")
	return req, resp, resp != ""
}

// ParseBurpPair parses a Burp-style raw capture (request followed by ***
// separator and response) into an HttpRequestResponse. When no separator is
// present, it returns a request-only HttpRequestResponse — equivalent to
// parseRawRequestWithInferredURL.
func ParseBurpPair(content string) (*httpmsg.HttpRequestResponse, error) {
	reqRaw, respRaw, hasResp := SplitBurpPair(content)
	if reqRaw == "" {
		return nil, fmt.Errorf("empty request in burp-style content")
	}

	rr, err := parseRawRequestWithInferredURL(reqRaw)
	if err != nil {
		return nil, err
	}

	if hasResp {
		resp := httpmsg.NewHttpResponse([]byte(respRaw))
		if resp != nil {
			rr = rr.WithResponse(resp)
		}
	}
	return rr, nil
}

// parseRawRequestWithInferredURL parses a raw HTTP request, attaching a Service
// derived from Origin/Referer/Host so downstream consumers see a fully-qualified
// URL (e.g. https://host/path) rather than the origin-form path alone.
func parseRawRequestWithInferredURL(raw string) (*httpmsg.HttpRequestResponse, error) {
	if url := inferRequestURL(raw); url != "" {
		return httpmsg.ParseRawRequestWithURL(raw, url)
	}
	return httpmsg.ParseRawRequest(raw)
}

// inferRequestURL builds a full URL from the raw request's first line + Host
// header, choosing the scheme from Origin/Referer when available and defaulting
// to https (consistent with Burp captures).
func inferRequestURL(raw string) string {
	lines := strings.Split(raw, "\n")
	if len(lines) < 2 {
		return ""
	}

	methodLine := strings.TrimRight(lines[0], "\r")
	parts := strings.SplitN(methodLine, " ", 3)
	if len(parts) < 2 {
		return ""
	}
	path := parts[1]

	var host, scheme string
	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "host":
			host = value
		case "origin":
			if s := schemeIfHostMatches(value, host); s != "" {
				scheme = s
			}
		case "referer":
			if scheme == "" {
				if s := schemeIfHostMatches(value, host); s != "" {
					scheme = s
				}
			}
		}
	}

	if host == "" {
		return ""
	}
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + host + path
}

func schemeIfHostMatches(urlStr, host string) string {
	if host == "" {
		return ""
	}
	if strings.HasPrefix(urlStr, "https://") && strings.Contains(urlStr, host) {
		return "https"
	}
	if strings.HasPrefix(urlStr, "http://") && strings.Contains(urlStr, host) {
		return "http"
	}
	return ""
}
