package curl

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

type header struct {
	key   string
	value string
}

// ParseSingleCommand parses a single curl command string into an HttpRequestResponse.
func ParseSingleCommand(cmd string) (*httpmsg.HttpRequestResponse, error) {
	tokens := tokenizeCurlCommand(cmd)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty curl command")
	}

	// Skip leading "curl" token if present
	start := 0
	if tokens[0] == "curl" {
		start = 1
	}

	var (
		method      string
		rawURL      string
		headers     []header
		dataParts   []string
		formFields  []string
		cookies     string
		basicAuth   string
		hasExplicit bool
	)

	for i := start; i < len(tokens); i++ {
		tok := tokens[i]

		switch tok {
		case "-X", "--request":
			i++
			if i < len(tokens) {
				method = strings.ToUpper(tokens[i])
				hasExplicit = true
			}

		case "-H", "--header":
			i++
			if i < len(tokens) {
				if k, v, ok := parseHeader(tokens[i]); ok {
					headers = append(headers, header{key: k, value: v})
				}
			}

		case "-d", "--data", "--data-raw", "--data-binary":
			i++
			if i < len(tokens) {
				dataParts = append(dataParts, tokens[i])
			}

		case "-F", "--form":
			i++
			if i < len(tokens) {
				formFields = append(formFields, tokens[i])
			}

		case "-b", "--cookie":
			i++
			if i < len(tokens) {
				cookies = tokens[i]
			}

		case "-u", "--user":
			i++
			if i < len(tokens) {
				basicAuth = tokens[i]
			}

		// Flags that consume an argument (ignore)
		case "-o", "--output", "--url":
			i++
			if tok == "--url" && i < len(tokens) {
				rawURL = tokens[i]
			}

		// Flags that are standalone (ignore)
		case "-s", "--silent",
			"-k", "--insecure",
			"--compressed",
			"-v", "--verbose",
			"-L", "--location",
			"-i", "--include",
			"-S", "--show-error",
			"-f", "--fail",
			"-g", "--globoff":
			// no-op

		default:
			// Positional argument: URL (skip flags we don't recognize that start with -)
			if !strings.HasPrefix(tok, "-") && rawURL == "" {
				rawURL = tok
			}
		}
	}

	if rawURL == "" {
		return nil, fmt.Errorf("no URL found in curl command")
	}

	// Build body
	var body string
	if len(formFields) > 0 {
		body = buildFormBody(formFields)
		if method == "" && !hasExplicit {
			method = "POST"
		}
		// Add Content-Type for form data if not explicitly set
		if !hasHeader(headers, "Content-Type") {
			headers = append(headers, header{key: "Content-Type", value: "multipart/form-data"})
		}
	} else if len(dataParts) > 0 {
		body = strings.Join(dataParts, "&")
		if method == "" && !hasExplicit {
			method = "POST"
		}
	}

	if method == "" {
		method = "GET"
	}

	// Add Cookie header
	if cookies != "" {
		headers = append(headers, header{key: "Cookie", value: cookies})
	}

	// Add Authorization header for basic auth
	if basicAuth != "" {
		encoded := base64.StdEncoding.EncodeToString([]byte(basicAuth))
		headers = append(headers, header{key: "Authorization", value: "Basic " + encoded})
	}

	return buildRawHTTPRequest(method, rawURL, headers, body)
}

// tokenizeCurlCommand splits a curl command string into tokens, handling single/double
// quotes and backslash escapes.
func tokenizeCurlCommand(cmd string) []string {
	var tokens []string
	var current strings.Builder
	inSingle := false
	inDouble := false
	escaped := false

	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]

		if escaped {
			// In double quotes, only certain chars are special after backslash
			if inDouble && ch != '"' && ch != '\\' && ch != '$' && ch != '`' {
				current.WriteByte('\\')
			}
			current.WriteByte(ch)
			escaped = false
			continue
		}

		switch {
		case ch == '\\' && !inSingle:
			// Check if this is a line continuation (backslash at end of line)
			if i+1 < len(cmd) && (cmd[i+1] == '\n' || cmd[i+1] == '\r') {
				// Skip the backslash and newline (line continuation)
				i++
				if i+1 < len(cmd) && cmd[i] == '\r' && cmd[i+1] == '\n' {
					i++ // skip \r\n
				}
				continue
			}
			escaped = true

		case ch == '\'' && !inDouble:
			inSingle = !inSingle

		case ch == '"' && !inSingle:
			inDouble = !inDouble

		case (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') && !inSingle && !inDouble:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}

		default:
			current.WriteByte(ch)
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

// buildRawHTTPRequest assembles a raw HTTP request string and calls httpmsg.ParseRawRequestWithURL.
func buildRawHTTPRequest(method, fullURL string, headers []header, body string) (*httpmsg.HttpRequestResponse, error) {
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", fullURL, err)
	}

	path := parsedURL.RequestURI()
	host := parsedURL.Host

	var headerLines []string
	headerLines = append(headerLines, fmt.Sprintf("Host: %s", host))

	hasContentType := false
	for _, h := range headers {
		headerLines = append(headerLines, fmt.Sprintf("%s: %s", h.key, h.value))
		if strings.EqualFold(h.key, "Content-Type") {
			hasContentType = true
		}
	}

	// Auto-add Content-Type if body present but no explicit Content-Type
	if body != "" && !hasContentType {
		headerLines = append(headerLines, "Content-Type: application/json")
	}

	// Add Content-Length for requests with body
	if body != "" {
		headerLines = append(headerLines, fmt.Sprintf("Content-Length: %d", len(body)))
	}

	// Assemble raw HTTP request
	var raw strings.Builder
	fmt.Fprintf(&raw, "%s %s HTTP/1.1\r\n", method, path)
	for _, h := range headerLines {
		raw.WriteString(h)
		raw.WriteString("\r\n")
	}
	raw.WriteString("\r\n")
	if body != "" {
		raw.WriteString(body)
	}

	return httpmsg.ParseRawRequestWithURL(raw.String(), fullURL)
}

// parseHeader splits a "Key: Value" string into key and value.
func parseHeader(s string) (string, string, bool) {
	key, value, ok := strings.Cut(s, ":")
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(key), strings.TrimSpace(value), true
}

// hasHeader checks if a header with the given name exists (case-insensitive).
func hasHeader(headers []header, name string) bool {
	for _, h := range headers {
		if strings.EqualFold(h.key, name) {
			return true
		}
	}
	return false
}

// buildFormBody constructs a form body from -F fields.
// File references (@path) have the @ stripped as a placeholder.
func buildFormBody(fields []string) string {
	var parts []string
	for _, f := range fields {
		k, v, ok := parseFormField(f)
		if !ok {
			continue
		}
		// Strip @ prefix for file uploads (placeholder)
		v = strings.TrimPrefix(v, "@")
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
	}
	return strings.Join(parts, "&")
}

// parseFormField splits a "key=value" form field.
func parseFormField(s string) (string, string, bool) {
	key, value, ok := strings.Cut(s, "=")
	if !ok {
		return s, "", true
	}
	return key, value, true
}
