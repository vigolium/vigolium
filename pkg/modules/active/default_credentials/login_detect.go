package default_credentials

import (
	"encoding/json"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// loginEndpoint represents a detected login form with field names.
type loginEndpoint struct {
	usernameField string
	passwordField string
	isJSON        bool
}

// detectLoginEndpoint checks if the request looks like a login form submission.
// Returns the detected endpoint or nil if not a login form.
func detectLoginEndpoint(ctx *httpmsg.HttpRequestResponse) *loginEndpoint {
	if ctx.Request() == nil {
		return nil
	}

	ct := strings.ToLower(ctx.Request().Header("Content-Type"))
	isFormEncoded := strings.Contains(ct, "application/x-www-form-urlencoded")
	isJSON := strings.Contains(ct, "application/json")

	if !isFormEncoded && !isJSON {
		return nil
	}

	raw := ctx.Request().Raw()

	// Check URL path for login patterns
	pathMatch := false
	urlx, err := ctx.URL()
	if err == nil {
		pathLower := strings.ToLower(urlx.Path)
		for _, pattern := range loginPathPatterns {
			if strings.Contains(pathLower, pattern) {
				pathMatch = true
				break
			}
		}
	}

	var usernameField, passwordField string

	if isJSON {
		// Parse JSON body to find field names
		body := ctx.Request().BodyToString()
		var jsonBody map[string]interface{}
		if err := json.Unmarshal([]byte(body), &jsonBody); err != nil {
			return nil
		}

		for key := range jsonBody {
			keyLower := strings.ToLower(key)
			if usernameField == "" && matchesAny(keyLower, usernameParamNames) {
				usernameField = key
			}
			if passwordField == "" && matchesAny(keyLower, passwordParamNames) {
				passwordField = key
			}
		}
	} else {
		// Parse form-encoded body parameters
		bodyParams, err := httpmsg.GetBodyParametersMap(raw)
		if err != nil {
			return nil
		}
		for key := range bodyParams {
			keyLower := strings.ToLower(key)
			if usernameField == "" && matchesAny(keyLower, usernameParamNames) {
				usernameField = key
			}
			if passwordField == "" && matchesAny(keyLower, passwordParamNames) {
				passwordField = key
			}
		}
	}

	// Must have both username and password fields
	if usernameField == "" || passwordField == "" {
		return nil
	}

	// If path doesn't match login patterns, require strong field name signals
	if !pathMatch {
		// Be more conservative: both field names must be common login field names
		if !isStrongLoginField(strings.ToLower(usernameField)) || !isStrongLoginField(strings.ToLower(passwordField)) {
			return nil
		}
	}

	return &loginEndpoint{
		usernameField: usernameField,
		passwordField: passwordField,
		isJSON:        isJSON,
	}
}

// hasCAPTCHA checks if the response body contains CAPTCHA indicators.
func hasCAPTCHA(body string) bool {
	bodyLower := strings.ToLower(body)
	for _, indicator := range captchaIndicators {
		if strings.Contains(bodyLower, indicator) {
			return true
		}
	}
	return false
}

// isLoginSuccess determines if a response indicates successful authentication.
func isLoginSuccess(statusCode int, body string, baselineStatus int, baselineLength int, hasSetCookie bool) bool {
	// A WAF/rate-limit response is not an auth success. Credential-stuffing probes
	// frequently get throttled by Cloudflare et al. with 429+Set-Cookie (cf_chl_*,
	// __cf_bm), which would otherwise trip the Set-Cookie+body-diff path below.
	if statusCode == 401 || statusCode == 403 || statusCode == 429 || statusCode == 503 {
		return false
	}

	// Status code change from failure to success
	if baselineStatus == 401 && (statusCode == 200 || statusCode == 302 || statusCode == 303) {
		return true
	}

	// Redirect after successful login (baseline was 200, now 302/303)
	if baselineStatus == 200 && (statusCode == 302 || statusCode == 303) {
		return true
	}

	// Set-Cookie with significant body change
	if hasSetCookie {
		diff := len(body) - baselineLength
		if diff < 0 {
			diff = -diff
		}
		if diff > 100 || (baselineLength > 0 && float64(diff)/float64(baselineLength) > 0.20) {
			return true
		}
	}

	// Check for success indicators in body (with significant status/length change)
	if statusCode != baselineStatus || significantLengthDiff(len(body), baselineLength) {
		bodyLower := strings.ToLower(body)
		for _, indicator := range successIndicators {
			if strings.Contains(bodyLower, indicator) {
				return true
			}
		}
	}

	return false
}

// isLockout checks if the response indicates account lockout.
func isLockout(body string) bool {
	bodyLower := strings.ToLower(body)
	for _, indicator := range lockoutIndicators {
		if strings.Contains(bodyLower, indicator) {
			return true
		}
	}
	return false
}

func matchesAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if s == p {
			return true
		}
	}
	return false
}

func isStrongLoginField(name string) bool {
	strong := []string{"username", "user", "email", "login", "password", "passwd", "pass", "pwd"}
	for _, s := range strong {
		if name == s {
			return true
		}
	}
	return false
}

func significantLengthDiff(a, b int) bool {
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	if diff > 200 {
		return true
	}
	maxLen := a
	if b > maxLen {
		maxLen = b
	}
	if maxLen > 0 && float64(diff)/float64(maxLen) > 0.30 {
		return true
	}
	return false
}
