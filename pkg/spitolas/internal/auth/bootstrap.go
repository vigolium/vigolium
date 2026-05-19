// Package auth provides authentication bootstrap for benchmark apps.
package auth

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
)

// AppAuthConfig defines authentication configuration for a benchmark app.
type AppAuthConfig struct {
	Username string
	Password string
	Email    string // Some apps use email instead of username
}

// DefaultAuthConfigs returns default authentication configs for each app.
func DefaultAuthConfigs() map[string]AppAuthConfig {
	return map[string]AppAuthConfig{
		"addressbook": {Username: "admin", Password: "admin"},
		"phpbb2":      {Username: "jAEkPot", Password: "jAEkPot"},
		"drupal":      {Username: "admin", Password: "admin"},
		"vanilla":     {Username: "admin@test.com", Password: "test123test123", Email: "admin@test.com"},
		"wordpress":   {Username: "admin", Password: "admin"},
		"hotcrp":      {Email: "chair@mailinator.com", Password: "1"},
		"oscommerce2": {Username: "spitolas@spitolas.com", Password: "spitolas1", Email: "spitolas@spitolas.com"},
		"matomo":      {Username: "admin", Password: "slasti123"},
		"retroboard":  {Username: "admin@admin.admin", Password: "admin"},
		"docmost":     {Email: "admin@admin.admin", Password: "admin123admin123"},
	}
}

// Bootstrap performs login and returns cookies for an app.
func Bootstrap(baseURL string, appName string, authCfg *AppAuthConfig) ([]*http.Cookie, error) {
	// Use default config if not provided
	if authCfg == nil {
		defaults := DefaultAuthConfigs()
		cfg, ok := defaults[appName]
		if !ok {
			return nil, fmt.Errorf("no default auth config for app: %s", appName)
		}
		authCfg = &cfg
	}

	// Create HTTP client with cookie jar
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	client := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Follow redirects
		},
	}

	// Parse base URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// Perform app-specific login
	switch appName {
	case "addressbook":
		err = loginAddressbook(client, baseURL, authCfg)
	case "phpbb2":
		err = loginPhpbb2(client, baseURL, authCfg)
	case "drupal":
		err = loginDrupal(client, baseURL, authCfg)
	case "vanilla":
		err = loginVanilla(client, baseURL, authCfg)
	case "wordpress":
		err = loginWordpress(client, baseURL, authCfg)
	case "hotcrp":
		err = loginHotcrp(client, baseURL, authCfg)
	case "oscommerce2":
		err = loginOscommerce2(client, baseURL, authCfg)
	case "matomo":
		err = loginMatomo(client, baseURL, authCfg)
	case "retroboard":
		err = loginRetroboard(client, baseURL, authCfg)
	case "docmost":
		err = loginDocmost(client, baseURL, authCfg)
	default:
		return nil, fmt.Errorf("unsupported app: %s", appName)
	}

	if err != nil {
		return nil, fmt.Errorf("login failed for %s: %w", appName, err)
	}

	// Get cookies from jar - try both base URL and app-specific paths
	cookies := jar.Cookies(parsedURL)

	// If no cookies found at base URL, try common paths
	if len(cookies) == 0 {
		// Try with common app paths
		testPaths := []string{
			"/addressbook-mod/addressbook/",
			"/",
		}
		for _, path := range testPaths {
			testURL, _ := url.Parse(baseURL + path)
			cookies = jar.Cookies(testURL)
			if len(cookies) > 0 {
				break
			}
		}
	}

	zap.L().Debug("Auth bootstrap completed",
		zap.String("app", appName),
		zap.Int("cookies", len(cookies)))

	return cookies, nil
}

// loginAddressbook performs login for addressbook app.
func loginAddressbook(client *http.Client, baseURL string, cfg *AppAuthConfig) error {
	// addressbook has path prefix /addressbook-mod/addressbook/
	loginURL := strings.TrimSuffix(baseURL, "/") + "/addressbook-mod/addressbook/index.php"

	data := url.Values{
		"user": {cfg.Username},
		"pass": {cfg.Password},
	}

	resp, err := client.PostForm(loginURL, data)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	zap.L().Debug("Addressbook login response", zap.Int("status", resp.StatusCode))
	return nil
}

// loginPhpbb2 performs login for phpbb2 app.
func loginPhpbb2(client *http.Client, baseURL string, cfg *AppAuthConfig) error {
	loginURL := strings.TrimSuffix(baseURL, "/") + "/login.php"

	data := url.Values{
		"username": {cfg.Username},
		"password": {cfg.Password},
		"login":    {"Log in"},
	}

	resp, err := client.PostForm(loginURL, data)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	zap.L().Debug("Phpbb2 login response", zap.Int("status", resp.StatusCode))
	return nil
}

// loginDrupal performs login for drupal app.
func loginDrupal(client *http.Client, baseURL string, cfg *AppAuthConfig) error {
	loginURL := strings.TrimSuffix(baseURL, "/") + "/index.php/user/login"

	data := url.Values{
		"name":       {cfg.Username},
		"pass":       {cfg.Password},
		"form_id":    {"user_login"},
		"form_build": {""},
		"op":         {"Log in"},
	}

	resp, err := client.PostForm(loginURL, data)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	zap.L().Debug("Drupal login response", zap.Int("status", resp.StatusCode))
	return nil
}

// loginVanilla performs login for vanilla app.
func loginVanilla(client *http.Client, baseURL string, cfg *AppAuthConfig) error {
	loginURL := strings.TrimSuffix(baseURL, "/") + "/index.php?p=/entry/signin"

	// Vanilla needs TransientKey from the form
	resp, err := client.Get(loginURL)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Extract TransientKey
	tkRegex := regexp.MustCompile(`name="TransientKey"\s+value="([^"]+)"`)
	matches := tkRegex.FindSubmatch(body)
	transientKey := ""
	if len(matches) > 1 {
		transientKey = string(matches[1])
	}

	data := url.Values{
		"Email":        {cfg.Email},
		"Password":     {cfg.Password},
		"TransientKey": {transientKey},
		"Sign_In":      {"Sign In"},
	}

	resp, err = client.PostForm(loginURL, data)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	zap.L().Debug("Vanilla login response", zap.Int("status", resp.StatusCode))
	return nil
}

// loginWordpress performs login for wordpress app.
func loginWordpress(client *http.Client, baseURL string, cfg *AppAuthConfig) error {
	loginURL := strings.TrimSuffix(baseURL, "/") + "/wp-login.php"

	data := url.Values{
		"log":        {cfg.Username},
		"pwd":        {cfg.Password},
		"rememberme": {"forever"},
	}

	resp, err := client.PostForm(loginURL, data)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	zap.L().Debug("Wordpress login response", zap.Int("status", resp.StatusCode))
	return nil
}

// loginHotcrp performs login for hotcrp app.
func loginHotcrp(client *http.Client, baseURL string, cfg *AppAuthConfig) error {
	loginURL := strings.TrimSuffix(baseURL, "/") + "/?post=.empty"

	data := url.Values{
		"email":    {cfg.Email},
		"password": {cfg.Password},
		"action":   {"login"},
		"signin":   {"Sign in"},
	}

	resp, err := client.PostForm(loginURL, data)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	zap.L().Debug("Hotcrp login response", zap.Int("status", resp.StatusCode))
	return nil
}

// loginOscommerce2 performs login for oscommerce2 app.
// This requires creating an account first with CSRF token handling.
func loginOscommerce2(client *http.Client, baseURL string, cfg *AppAuthConfig) error {
	base := strings.TrimSuffix(baseURL, "/")

	// Step 1: Get create account page to extract CSRF token
	createURL := base + "/create_account.php"
	resp, err := client.Get(createURL)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Extract security token
	csrfRegex := regexp.MustCompile(`name="([a-f0-9]{32})"`)
	matches := csrfRegex.FindSubmatch(body)
	csrfToken := ""
	if len(matches) > 1 {
		csrfToken = string(matches[1])
	}

	// Step 2: Create account (may already exist)
	data := url.Values{
		"gender":              {"m"},
		"firstname":           {"spitolas"},
		"lastname":            {"spitolas"},
		"dob":                 {"01/01/1970"},
		"email_address":       {cfg.Email},
		"company":             {""},
		"street_address":      {"1 Street"},
		"suburb":              {""},
		"postcode":            {"12345"},
		"city":                {"City"},
		"state":               {""},
		"country":             {"223"},
		"telephone":           {"123456789"},
		"fax":                 {""},
		"newsletter":          {"0"},
		"password":            {cfg.Password},
		"confirmation":        {cfg.Password},
		"action":              {"process"},
		"formid":              {""},
		"form_name":           {"create_account"},
		"form_landing_page":   {"create_account.php"},
		"affiliate_banner_id": {"0"},
		"page_name":           {"create_account"},
		"loaded_page_url":     {base + "/create_account.php"},
		"referrer_url":        {base + "/"},
	}
	if csrfToken != "" {
		data[csrfToken] = []string{""}
	}

	resp, err = client.PostForm(createURL, data)
	if err != nil {
		zap.L().Debug("Create account request failed (may already exist)", zap.Error(err))
	} else {
		_ = resp.Body.Close()
	}

	// Step 3: Login
	loginURL := base + "/login.php"
	resp, err = client.Get(loginURL)
	if err != nil {
		return err
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Extract new CSRF token from login page
	matches = csrfRegex.FindSubmatch(body)
	csrfToken = ""
	if len(matches) > 1 {
		csrfToken = string(matches[1])
	}

	loginData := url.Values{
		"email_address": {cfg.Email},
		"password":      {cfg.Password},
		"action":        {"process"},
	}
	if csrfToken != "" {
		loginData[csrfToken] = []string{""}
	}

	resp, err = client.PostForm(loginURL, loginData)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	zap.L().Debug("Oscommerce2 login response", zap.Int("status", resp.StatusCode))
	return nil
}

// loginMatomo performs login for matomo app.
func loginMatomo(client *http.Client, baseURL string, cfg *AppAuthConfig) error {
	base := strings.TrimSuffix(baseURL, "/")

	// Step 1: Get login page to fetch CSRF nonce
	loginPageURL := base + "/index.php?module=Login"
	resp, err := client.Get(loginPageURL)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Extract nonce
	nonceRegex := regexp.MustCompile(`name="form_nonce"\s+value="([^"]+)"`)
	matches := nonceRegex.FindSubmatch(body)
	nonce := ""
	if len(matches) > 1 {
		nonce = string(matches[1])
	}

	// Step 2: Submit login
	loginURL := base + "/index.php?module=Login"
	data := url.Values{
		"form_login":    {cfg.Username},
		"form_password": {cfg.Password},
		"form_nonce":    {nonce},
	}

	resp, err = client.PostForm(loginURL, data)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	zap.L().Debug("Matomo login response", zap.Int("status", resp.StatusCode))
	return nil
}

// loginRetroboard performs API login for retroboard app.
func loginRetroboard(client *http.Client, baseURL string, cfg *AppAuthConfig) error {
	base := strings.TrimSuffix(baseURL, "/")
	loginURL := base + "/api/auth/login"

	data := url.Values{
		"username": {cfg.Username},
		"password": {cfg.Password},
	}

	req, err := http.NewRequest("POST", loginURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	zap.L().Debug("Retroboard login response", zap.Int("status", resp.StatusCode))
	return nil
}

// loginDocmost performs API login for docmost app.
func loginDocmost(client *http.Client, baseURL string, cfg *AppAuthConfig) error {
	base := strings.TrimSuffix(baseURL, "/")
	loginURL := base + "/api/auth/login"

	// JSON payload
	payload := fmt.Sprintf(`{"email":"%s","password":"%s"}`, cfg.Email, cfg.Password)

	req, err := http.NewRequest("POST", loginURL, strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	zap.L().Debug("Docmost login response", zap.Int("status", resp.StatusCode))
	return nil
}
