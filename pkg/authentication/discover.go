package authentication

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// knownTokenFields are JSON field names commonly used for auth tokens, ordered by priority.
var knownTokenFields = []string{
	"token",
	"access_token",
	"accessToken",
	"jwt",
	"id_token",
	"idToken",
	"auth_token",
	"authToken",
	"session_token",
	"sessionToken",
	"bearer",
	"api_token",
	"apiToken",
	"api_key",
	"apiKey",
}

// knownAuthResponseHeaders are response headers that may carry auth tokens.
var knownAuthResponseHeaders = []string{
	"Authorization",
	"X-Auth-Token",
	"X-Access-Token",
	"X-Session-Token",
	"X-Api-Key",
	"X-JWT-Token",
}

// DiscoverResult holds the output of auto-discovery.
type DiscoverResult struct {
	Session      *Session
	StatusCode   int
	TokenSources []string // human-readable descriptions of where tokens were found
	RawResponse  string   // raw response for storage in login_response
}

// DiscoverLogin sends the given login request and auto-discovers auth tokens
// from the response. It checks JSON body fields, Set-Cookie headers, and
// auth response headers. Returns a Session with a LoginFlow populated with
// auto-generated ExtractRules.
func DiscoverLogin(loginReq *LoginRequest) (*DiscoverResult, error) {
	if loginReq == nil {
		return nil, fmt.Errorf("nil login request")
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	var body io.Reader
	if loginReq.Body != "" {
		body = strings.NewReader(loginReq.Body)
	}

	req, err := http.NewRequest(strings.ToUpper(loginReq.Method), loginReq.URL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Apply headers from the raw request.
	for k, v := range loginReq.Headers {
		if strings.EqualFold(k, "host") {
			continue // Host is set from URL
		}
		req.Header.Set(k, v)
	}

	// Auto-detect content type if not set.
	if req.Header.Get("Content-Type") == "" && loginReq.Body != "" {
		if strings.HasPrefix(strings.TrimSpace(loginReq.Body), "{") {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	result := &DiscoverResult{
		StatusCode: resp.StatusCode,
	}

	// Build raw response for storage.
	var rawResp strings.Builder
	fmt.Fprintf(&rawResp, "%s %s\r\n", resp.Proto, resp.Status)
	for k, vals := range resp.Header {
		for _, v := range vals {
			fmt.Fprintf(&rawResp, "%s: %s\r\n", k, v)
		}
	}
	rawResp.WriteString("\r\n")
	rawResp.Write(respBody)
	result.RawResponse = rawResp.String()

	// Only auto-discover on success responses.
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return result, fmt.Errorf("login returned status %d", resp.StatusCode)
	}

	// Discover tokens from the response.
	var extractRules []ExtractRule
	headers := make(map[string]string)

	// 1. JSON body: look for known token fields.
	if isJSONResponse(resp) && len(respBody) > 0 {
		jsonRules, jsonHeaders := discoverJSONTokens(respBody)
		extractRules = append(extractRules, jsonRules...)
		for k, v := range jsonHeaders {
			headers[k] = v
		}
		for _, r := range jsonRules {
			result.TokenSources = append(result.TokenSources,
				fmt.Sprintf("json body: %s -> %s", r.Path, r.ApplyAs))
		}
	}

	// 2. Set-Cookie headers.
	if cookies := resp.Cookies(); len(cookies) > 0 {
		cookieRule, cookieHeader := discoverCookieTokens(cookies)
		if cookieRule != nil {
			extractRules = append(extractRules, *cookieRule)
			for k, v := range cookieHeader {
				headers[k] = v
			}
			result.TokenSources = append(result.TokenSources,
				fmt.Sprintf("cookies: %d cookie(s)", len(cookies)))
		}
	}

	// 3. Auth response headers.
	for _, hdr := range knownAuthResponseHeaders {
		val := resp.Header.Get(hdr)
		if val == "" {
			continue
		}
		rule := ExtractRule{
			Source:  ExtractHeader,
			Name:    hdr,
			ApplyAs: hdr + ": {value}",
		}
		extractRules = append(extractRules, rule)
		headers[hdr] = val
		result.TokenSources = append(result.TokenSources,
			fmt.Sprintf("header: %s", hdr))
	}

	if len(extractRules) == 0 {
		return result, fmt.Errorf("no auth tokens found in response (status %d)", resp.StatusCode)
	}

	// Build the session.
	contentType := loginReq.Headers["Content-Type"]
	if contentType == "" {
		contentType = req.Header.Get("Content-Type")
	}

	sess := &Session{
		Name:    "auto-discovered",
		Role:    RolePrimary,
		Headers: headers,
		Login: &LoginFlow{
			URL:         loginReq.URL,
			Method:      strings.ToUpper(loginReq.Method),
			ContentType: contentType,
			Body:        loginReq.Body,
			Extract:     extractRules,
		},
		LoginRequest: loginReq.Raw,
		hydrated:     true,
	}

	result.Session = sess
	return result, nil
}

// LoginRequest holds a parsed raw HTTP login request.
type LoginRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
	Raw     string // original raw request text
}

// ParseRawLoginRequest parses a raw HTTP request string into a LoginRequest.
// Supports the format:
//
//	POST /rest/user/login HTTP/1.1
//	Host: localhost:3000
//	Content-Type: application/json
//
//	{"email":"admin@juice-sh.op","password":"admin123"}
func ParseRawLoginRequest(raw string) (*LoginRequest, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty request")
	}

	reader := bufio.NewReader(strings.NewReader(raw))

	// Parse request line.
	requestLine, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read request line: %w", err)
	}
	requestLine = strings.TrimSpace(requestLine)

	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line: %s", requestLine)
	}

	method := parts[0]
	path := parts[1]

	// Parse headers.
	headers := make(map[string]string)
	for {
		line, readErr := reader.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if readErr != nil && readErr != io.EOF {
			break
		}
		idx := strings.Index(line, ":")
		if idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			headers[key] = val
		}
		if readErr == io.EOF {
			break
		}
	}

	// Read body (everything after blank line).
	bodyBytes, _ := io.ReadAll(reader)
	body := strings.TrimSpace(string(bodyBytes))

	// Build full URL from Host header and path.
	host := headers["Host"]
	if host == "" {
		// Try case-insensitive lookup.
		for k, v := range headers {
			if strings.EqualFold(k, "host") {
				host = v
				break
			}
		}
	}
	if host == "" {
		return nil, fmt.Errorf("no Host header found in request")
	}

	// Determine scheme.
	scheme := "https"
	if strings.HasSuffix(host, ":80") || strings.HasPrefix(path, "http://") {
		scheme = "http"
	}

	var fullURL string
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		fullURL = path
	} else {
		fullURL = fmt.Sprintf("%s://%s%s", scheme, host, path)
	}

	// Validate URL.
	if _, urlErr := url.Parse(fullURL); urlErr != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", fullURL, urlErr)
	}

	return &LoginRequest{
		Method:  method,
		URL:     fullURL,
		Headers: headers,
		Body:    body,
		Raw:     raw,
	}, nil
}

// IsRawHTTPRequest returns true if the data looks like a raw HTTP request.
func IsRawHTTPRequest(data []byte) bool {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return false
	}
	// Check first line matches HTTP method + path + version pattern.
	firstLine := trimmed
	if idx := strings.IndexAny(trimmed, "\r\n"); idx > 0 {
		firstLine = trimmed[:idx]
	}
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) < 2 {
		return false
	}
	method := parts[0]
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT":
		return strings.HasPrefix(parts[1], "/") || strings.HasPrefix(parts[1], "http")
	}
	return false
}

// discoverJSONTokens looks for known token fields in a JSON response body.
func discoverJSONTokens(body []byte) ([]ExtractRule, map[string]string) {
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, nil
	}

	var rules []ExtractRule
	headers := make(map[string]string)

	// Search top-level fields.
	for _, field := range knownTokenFields {
		if val, ok := data[field]; ok {
			strVal := fmt.Sprintf("%v", val)
			if strVal == "" || strVal == "<nil>" {
				continue
			}
			rule := ExtractRule{
				Source:  ExtractJSON,
				Path:    field,
				ApplyAs: "Authorization: Bearer {value}",
			}
			rules = append(rules, rule)
			headers["Authorization"] = "Bearer " + strVal
			return rules, headers // take the first match
		}
	}

	// Search one level deep (e.g. data.token, authentication.token).
	for parentKey, parentVal := range data {
		nested, ok := parentVal.(map[string]any)
		if !ok {
			continue
		}
		for _, field := range knownTokenFields {
			if val, ok := nested[field]; ok {
				strVal := fmt.Sprintf("%v", val)
				if strVal == "" || strVal == "<nil>" {
					continue
				}
				path := parentKey + "." + field
				rule := ExtractRule{
					Source:  ExtractJSON,
					Path:    path,
					ApplyAs: "Authorization: Bearer {value}",
				}
				rules = append(rules, rule)
				headers["Authorization"] = "Bearer " + strVal
				return rules, headers
			}
		}
	}

	return nil, nil
}

// discoverCookieTokens creates an extract rule for all Set-Cookie values.
func discoverCookieTokens(cookies []*http.Cookie) (*ExtractRule, map[string]string) {
	if len(cookies) == 0 {
		return nil, nil
	}

	// Build Cookie header from all cookies.
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if c.Value != "" {
			parts = append(parts, c.Name+"="+c.Value)
		}
	}
	if len(parts) == 0 {
		return nil, nil
	}

	rule := &ExtractRule{
		Source: ExtractCookie,
		// Empty Name means "extract all cookies".
	}

	headers := map[string]string{
		"Cookie": strings.Join(parts, "; "),
	}

	return rule, headers
}

// isJSONResponse checks if the response has a JSON content type.
func isJSONResponse(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "json")
}
