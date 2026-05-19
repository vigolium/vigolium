package harness

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

var csrfTokenRe = regexp.MustCompile(`user_token'\s+value='([^']+)'`)

// SetupDVWA initializes the DVWA database and logs in, returning session cookies.
// DVWA requires: 1) DB creation via /setup.php, 2) Login via /login.php (both with CSRF tokens).
func SetupDVWA(t *testing.T, baseURL string) (string, error) {
	t.Helper()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout: 15 * time.Second,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Step 1: GET /setup.php to get session + CSRF token
	setupToken, err := getCsrfToken(client, baseURL+"/setup.php")
	if err != nil {
		return "", fmt.Errorf("failed to get setup CSRF token: %w", err)
	}
	t.Logf("DVWA setup: got CSRF token")

	// Step 2: POST /setup.php to create/reset database
	resp, err := client.PostForm(baseURL+"/setup.php", url.Values{
		"create_db":  {"Create / Reset Database"},
		"user_token": {setupToken},
	})
	if err != nil {
		return "", fmt.Errorf("failed to create DVWA database: %w", err)
	}
	_ = resp.Body.Close()
	t.Logf("DVWA setup: database created (status=%d)", resp.StatusCode)

	// Step 3: GET /login.php to get fresh CSRF token
	loginToken, err := getCsrfToken(client, baseURL+"/login.php")
	if err != nil {
		return "", fmt.Errorf("failed to get login CSRF token: %w", err)
	}

	// Step 4: POST /login.php with credentials
	resp, err = client.PostForm(baseURL+"/login.php", url.Values{
		"username":   {"admin"},
		"password":   {"password"},
		"Login":      {"Login"},
		"user_token": {loginToken},
	})
	if err != nil {
		return "", fmt.Errorf("DVWA login failed: %w", err)
	}
	_ = resp.Body.Close()
	t.Logf("DVWA setup: login completed (status=%d)", resp.StatusCode)

	// Extract session cookies
	u, _ := url.Parse(baseURL)
	cookies := jar.Cookies(u)
	var cookieParts []string
	for _, c := range cookies {
		cookieParts = append(cookieParts, c.Name+"="+c.Value)
	}

	// Ensure security=low is included
	hasSecurityCookie := false
	for _, c := range cookies {
		if c.Name == "security" {
			hasSecurityCookie = true
		}
	}
	if !hasSecurityCookie {
		cookieParts = append(cookieParts, "security=low")
	}

	cookieStr := strings.Join(cookieParts, "; ")
	t.Logf("DVWA setup: session cookies obtained")

	// Verify access works
	req, _ := http.NewRequest("GET", baseURL+"/vulnerabilities/xss_r/?name=test", nil)
	req.Header.Set("Cookie", cookieStr)
	resp, err = client.Do(req)
	if err != nil {
		return cookieStr, fmt.Errorf("DVWA verification failed: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		return cookieStr, fmt.Errorf("DVWA verification: expected 200, got %d", resp.StatusCode)
	}
	t.Logf("DVWA setup: verified access to vulnerability pages")

	return cookieStr, nil
}

// getCsrfToken fetches a page and extracts the DVWA CSRF token.
func getCsrfToken(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	matches := csrfTokenRe.FindSubmatch(body)
	if len(matches) < 2 {
		return "", fmt.Errorf("CSRF token not found in %s", url)
	}
	return string(matches[1]), nil
}
