package session

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// executeLogin performs the login flow and populates session headers with extracted credentials.
func executeLogin(sess *Session) error {
	if sess.Login == nil {
		return fmt.Errorf("session %q: no login flow defined", sess.Name)
	}
	login := sess.Login

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return fmt.Errorf("session %q: failed to create cookie jar: %w", sess.Name, err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
		// Follow redirects to capture cookies from redirect responses
	}

	var body io.Reader
	if login.Body != "" {
		body = strings.NewReader(login.Body)
	}

	req, err := http.NewRequest(strings.ToUpper(login.Method), login.URL, body)
	if err != nil {
		return fmt.Errorf("session %q: failed to create login request: %w", sess.Name, err)
	}

	if login.ContentType != "" {
		req.Header.Set("Content-Type", login.ContentType)
	} else if login.Body != "" {
		// Auto-detect content type
		if strings.HasPrefix(strings.TrimSpace(login.Body), "{") {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("session %q: login request failed: %w", sess.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024)) // 1MB limit
	if err != nil {
		return fmt.Errorf("session %q: failed to read login response: %w", sess.Name, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("session %q: login returned status %d", sess.Name, resp.StatusCode)
	}

	// Initialize headers map if nil
	if sess.Headers == nil {
		sess.Headers = make(map[string]string)
	}

	// Extract credentials from response
	for _, rule := range login.Extract {
		if err := applyExtractRule(sess, resp, respBody, jar, req, rule); err != nil {
			return fmt.Errorf("session %q: extraction failed: %w", sess.Name, err)
		}
	}

	sess.hydrated = true
	return nil
}

// applyExtractRule extracts a single credential from the login response.
func applyExtractRule(sess *Session, resp *http.Response, body []byte, jar *cookiejar.Jar, req *http.Request, rule ExtractRule) error {
	switch rule.Source {
	case ExtractCookie:
		return extractCookie(sess, resp, jar, req, rule)
	case ExtractJSON:
		return extractJSON(sess, body, rule)
	case ExtractHeader:
		return extractHeader(sess, resp, rule)
	default:
		return fmt.Errorf("unknown extract source %q", rule.Source)
	}
}

// extractCookie extracts a cookie value from the response or cookie jar.
func extractCookie(sess *Session, resp *http.Response, jar *cookiejar.Jar, req *http.Request, rule ExtractRule) error {
	if rule.Name == "" {
		// Extract all cookies from the jar and set as Cookie header
		cookies := jar.Cookies(req.URL)
		if len(cookies) == 0 {
			// Fallback: check response Set-Cookie headers directly
			cookies = resp.Cookies()
		}
		if len(cookies) == 0 {
			return fmt.Errorf("no cookies found in login response")
		}
		parts := make([]string, len(cookies))
		for i, c := range cookies {
			parts[i] = c.Name + "=" + c.Value
		}
		sess.Headers["Cookie"] = strings.Join(parts, "; ")
		return nil
	}

	// Extract specific cookie
	var cookieValue string
	for _, c := range resp.Cookies() {
		if c.Name == rule.Name {
			cookieValue = c.Value
			break
		}
	}
	if cookieValue == "" {
		// Try from jar
		for _, c := range jar.Cookies(req.URL) {
			if c.Name == rule.Name {
				cookieValue = c.Value
				break
			}
		}
	}
	if cookieValue == "" {
		return fmt.Errorf("cookie %q not found in login response", rule.Name)
	}

	if rule.ApplyAs != "" {
		if err := applyHeaderTemplate(sess, rule.ApplyAs, cookieValue); err != nil {
			return err
		}
	} else {
		// Append to Cookie header
		existing := sess.Headers["Cookie"]
		pair := rule.Name + "=" + cookieValue
		if existing != "" {
			sess.Headers["Cookie"] = existing + "; " + pair
		} else {
			sess.Headers["Cookie"] = pair
		}
	}
	return nil
}

// extractJSON extracts a value from the JSON response body using a simple path.
// Supports simple dot-notation paths like "token", "data.access_token", "$.token".
func extractJSON(sess *Session, body []byte, rule ExtractRule) error {
	if rule.Path == "" {
		return fmt.Errorf("json extract requires path")
	}

	var data any
	if err := json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("failed to parse JSON response: %w", err)
	}

	// Normalize path: strip leading "$."
	path := strings.TrimPrefix(rule.Path, "$.")
	path = strings.TrimPrefix(path, "$")

	parts := strings.Split(path, ".")
	current := data
	for _, part := range parts {
		if part == "" {
			continue
		}
		m, ok := current.(map[string]any)
		if !ok {
			return fmt.Errorf("cannot navigate path %q: not an object at %q", rule.Path, part)
		}
		current, ok = m[part]
		if !ok {
			return fmt.Errorf("path %q: key %q not found", rule.Path, part)
		}
	}

	value := fmt.Sprintf("%v", current)
	if value == "" {
		return fmt.Errorf("path %q resolved to empty value", rule.Path)
	}

	if rule.ApplyAs != "" {
		return applyHeaderTemplate(sess, rule.ApplyAs, value)
	}
	return fmt.Errorf("json extract requires apply_as to specify which header to set")
}

// extractHeader extracts a value from a response header.
func extractHeader(sess *Session, resp *http.Response, rule ExtractRule) error {
	if rule.Name == "" {
		return fmt.Errorf("header extract requires name")
	}
	value := resp.Header.Get(rule.Name)
	if value == "" {
		return fmt.Errorf("header %q not found in login response", rule.Name)
	}

	if rule.ApplyAs != "" {
		return applyHeaderTemplate(sess, rule.ApplyAs, value)
	}
	sess.Headers[rule.Name] = value
	return nil
}

// applyHeaderTemplate sets a header from a template like "Authorization: Bearer {value}".
func applyHeaderTemplate(sess *Session, template, value string) error {
	resolved := strings.ReplaceAll(template, "{value}", value)
	parts := strings.SplitN(resolved, ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		return fmt.Errorf("invalid apply_as template %q: must be in 'HeaderName: value' format", template)
	}
	sess.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	return nil
}
