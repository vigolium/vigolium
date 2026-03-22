package session

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// executeLogin performs the login flow and populates session headers with extracted credentials.
func executeLogin(sess *Session) error {
	if sess.Login == nil {
		return fmt.Errorf("session %q: no login flow defined", sess.Name)
	}

	// Expand shorthand type/token_path into extract rules.
	NormalizeLoginFlow(sess.Login)

	// Multi-step login flows.
	if len(sess.Login.Steps) > 0 {
		return executeMultiStepLogin(sess)
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

	// Validate expect constraints before checking status.
	if login.Expect != nil {
		if err := ValidateExpect(login.Expect, resp.StatusCode, respBody); err != nil {
			return fmt.Errorf("session %q: login expect failed: %w", sess.Name, err)
		}
	} else if resp.StatusCode < 200 || resp.StatusCode >= 400 {
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

// executeMultiStepLogin handles login flows with multiple steps.
// Variables extracted in step N are available as {varname} placeholders in step N+1.
func executeMultiStepLogin(sess *Session) error {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return fmt.Errorf("session %q: failed to create cookie jar: %w", sess.Name, err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
	}

	// Variables extracted across steps, available as {varname} in subsequent steps.
	vars := map[string]string{}

	if sess.Headers == nil {
		sess.Headers = make(map[string]string)
	}

	for i, step := range sess.Login.Steps {
		// Substitute variables in URL and body.
		stepURL := substituteVars(step.URL, vars)
		stepBody := substituteVars(step.Body, vars)

		var body io.Reader
		if stepBody != "" {
			body = strings.NewReader(stepBody)
		}

		req, err := http.NewRequest(strings.ToUpper(step.Method), stepURL, body)
		if err != nil {
			return fmt.Errorf("session %q: step[%d] failed to create request: %w", sess.Name, i, err)
		}

		if step.ContentType != "" {
			req.Header.Set("Content-Type", step.ContentType)
		} else if stepBody != "" {
			if strings.HasPrefix(strings.TrimSpace(stepBody), "{") {
				req.Header.Set("Content-Type", "application/json")
			} else {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("session %q: step[%d] request failed: %w", sess.Name, i, err)
		}

		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
		_ = resp.Body.Close()
		if err != nil {
			return fmt.Errorf("session %q: step[%d] failed to read response: %w", sess.Name, i, err)
		}

		// Validate expect if present.
		if step.Expect != nil {
			if err := ValidateExpect(step.Expect, resp.StatusCode, respBody); err != nil {
				return fmt.Errorf("session %q: step[%d] expect failed: %w", sess.Name, i, err)
			}
		} else if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			return fmt.Errorf("session %q: step[%d] returned status %d", sess.Name, i, resp.StatusCode)
		}

		// Extract rules for this step — may produce variables or session headers.
		for _, rule := range step.Extract {
			if rule.ApplyAs != "" && strings.HasPrefix(rule.ApplyAs, "var:") {
				// Variable extraction: "var:csrf" stores value into vars["csrf"].
				varName := strings.TrimPrefix(rule.ApplyAs, "var:")
				val, extractErr := extractValue(resp, respBody, jar, req, rule)
				if extractErr != nil {
					return fmt.Errorf("session %q: step[%d] extraction failed: %w", sess.Name, i, extractErr)
				}
				vars[varName] = val
			} else {
				// Normal extraction — sets session headers.
				if extractErr := applyExtractRule(sess, resp, respBody, jar, req, rule); extractErr != nil {
					return fmt.Errorf("session %q: step[%d] extraction failed: %w", sess.Name, i, extractErr)
				}
			}
		}
	}

	sess.hydrated = true
	return nil
}

// substituteVars replaces {varname} placeholders in a string with values from vars.
func substituteVars(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{"+k+"}", v)
	}
	return s
}

// extractValue extracts a raw string value from the response without applying it as a header.
func extractValue(resp *http.Response, body []byte, jar *cookiejar.Jar, req *http.Request, rule ExtractRule) (string, error) {
	switch rule.Source {
	case ExtractJSON:
		return extractJSONValue(body, rule.Path)
	case ExtractRegex:
		return extractRegexValue(body, rule)
	case ExtractHeader:
		if rule.Name == "" {
			return "", fmt.Errorf("header extract requires name")
		}
		value := resp.Header.Get(rule.Name)
		if value == "" {
			return "", fmt.Errorf("header %q not found", rule.Name)
		}
		return value, nil
	case ExtractCookie:
		if rule.Name == "" {
			return "", fmt.Errorf("cookie extract requires name for variable extraction")
		}
		for _, c := range resp.Cookies() {
			if c.Name == rule.Name {
				return c.Value, nil
			}
		}
		for _, c := range jar.Cookies(req.URL) {
			if c.Name == rule.Name {
				return c.Value, nil
			}
		}
		return "", fmt.Errorf("cookie %q not found", rule.Name)
	default:
		return "", fmt.Errorf("unknown extract source %q", rule.Source)
	}
}

// extractJSONValue navigates a JSON body with a dot-notation path and returns the raw value.
func extractJSONValue(body []byte, jsonPath string) (string, error) {
	if jsonPath == "" {
		return "", fmt.Errorf("json extract requires path")
	}

	var data any
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("failed to parse JSON response: %w", err)
	}

	path := normalizeJSONPath(jsonPath)

	parts := strings.Split(path, ".")
	current := data
	for _, part := range parts {
		if part == "" {
			continue
		}
		m, ok := current.(map[string]any)
		if !ok {
			return "", fmt.Errorf("cannot navigate path %q: not an object at %q", jsonPath, part)
		}
		current, ok = m[part]
		if !ok {
			return "", fmt.Errorf("path %q: key %q not found", jsonPath, part)
		}
	}

	value := fmt.Sprintf("%v", current)
	if value == "" {
		return "", fmt.Errorf("path %q resolved to empty value", jsonPath)
	}
	return value, nil
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
	case ExtractRegex:
		return extractRegex(sess, body, rule)
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

	path := normalizeJSONPath(rule.Path)

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

// extractRegex extracts a value from the response body using a regex capture group.
func extractRegex(sess *Session, body []byte, rule ExtractRule) error {
	value, err := extractRegexValue(body, rule)
	if err != nil {
		return err
	}
	if rule.ApplyAs != "" {
		return applyHeaderTemplate(sess, rule.ApplyAs, value)
	}
	return fmt.Errorf("regex extract requires apply_as to specify which header to set")
}

// extractRegexValue runs a regex pattern against the body and returns the captured group value.
func extractRegexValue(body []byte, rule ExtractRule) (string, error) {
	if rule.Pattern == "" {
		return "", fmt.Errorf("regex extract requires pattern")
	}
	re, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return "", fmt.Errorf("invalid regex pattern %q: %w", rule.Pattern, err)
	}
	matches := re.FindSubmatch(body)
	group := rule.Group
	if group == 0 {
		group = 1 // Default to first capture group.
	}
	if len(matches) <= group {
		return "", fmt.Errorf("regex pattern %q: no match for group %d", rule.Pattern, group)
	}
	value := string(matches[group])
	if value == "" {
		return "", fmt.Errorf("regex pattern %q: group %d matched empty value", rule.Pattern, group)
	}
	return value, nil
}

// ProbeLogin sends the login request and returns the HTTP status code.
// Unlike executeLogin, it does not fail on non-2xx status codes — it returns
// the status code and lets the caller decide. If extract rules are present and
// the status is 2xx/3xx, it also runs extraction to populate session headers.
// Returns an error only on network/request-building failures.
func ProbeLogin(sess *Session) (statusCode int, err error) {
	if sess.Login == nil {
		return 0, fmt.Errorf("session %q: no login flow defined", sess.Name)
	}

	// Expand shorthand type/token_path into extract rules.
	NormalizeLoginFlow(sess.Login)
	login := sess.Login

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return 0, fmt.Errorf("session %q: failed to create cookie jar: %w", sess.Name, err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
	}

	var body io.Reader
	if login.Body != "" {
		body = strings.NewReader(login.Body)
	}

	req, err := http.NewRequest(strings.ToUpper(login.Method), login.URL, body)
	if err != nil {
		return 0, fmt.Errorf("session %q: failed to create login request: %w", sess.Name, err)
	}

	if login.ContentType != "" {
		req.Header.Set("Content-Type", login.ContentType)
	} else if login.Body != "" {
		if strings.HasPrefix(strings.TrimSpace(login.Body), "{") {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("session %q: login request failed: %w", sess.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("session %q: failed to read login response: %w", sess.Name, err)
	}

	// If status is OK and extract rules exist, run extraction.
	if resp.StatusCode >= 200 && resp.StatusCode < 400 && len(login.Extract) > 0 {
		if sess.Headers == nil {
			sess.Headers = make(map[string]string)
		}
		for _, rule := range login.Extract {
			if extractErr := applyExtractRule(sess, resp, respBody, jar, req, rule); extractErr != nil {
				return resp.StatusCode, fmt.Errorf("session %q: extraction failed: %w", sess.Name, extractErr)
			}
		}
		sess.hydrated = true
	}

	return resp.StatusCode, nil
}

// normalizeJSONPath strips leading prefixes so all path formats converge:
//   - jq-style:       ".token", ".data.access_token"
//   - JSONPath-style:  "$.token", "$token"
//   - bare:            "token", "data.access_token"
func normalizeJSONPath(p string) string {
	p = strings.TrimPrefix(p, "$.")
	p = strings.TrimPrefix(p, "$")
	p = strings.TrimPrefix(p, ".")
	return p
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
