//go:build canary

package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/wait"

	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/lfi_generic"
	"github.com/vigolium/vigolium/pkg/modules/active/sqli_error_based"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_light_scanner"
)

// dvwaTokenRe extracts DVWA's anti-CSRF user_token hidden field, e.g.
// `<input type='hidden' name='user_token' value='a3a0...'>`. DVWA rejects
// setup/login POSTs that omit it.
var dvwaTokenRe = regexp.MustCompile(`user_token'\s+value='([0-9a-f]+)'`)

// setupDVWA runs DVWA's first-boot flow so its vulnerable pages are reachable
// and returns the Cookie header value the scanners must send.
//
// A freshly started DVWA container 302-redirects every /vulnerabilities/*
// request to /login.php, so an unauthenticated scan only ever sees the login
// page and reports nothing. This helper mirrors the manual browser flow:
//
//  1. GET /setup.php          — prime the session, grab the setup CSRF token
//  2. POST /setup.php         — create/reset the backing DB (so modules have data)
//  3. GET /login.php          — grab the login CSRF token
//  4. POST /login.php         — authenticate as admin/password
//  5. pin security=low        — select the deliberately-vulnerable code path
//
// Returns "PHPSESSID=<id>; security=low".
func setupDVWA(t *testing.T, baseURL string) string {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err, "create DVWA cookie jar")
	client := &http.Client{Jar: jar, Timeout: 15 * time.Second}

	// 1 + 2: create / reset the database.
	resp, err := client.PostForm(baseURL+"/setup.php", url.Values{
		"create_db":  {"Create / Reset Database"},
		"user_token": {dvwaUserToken(t, client, baseURL+"/setup.php")},
	})
	require.NoError(t, err, "DVWA /setup.php POST")
	_ = resp.Body.Close()

	// 3 + 4: authenticate as admin.
	resp, err = client.PostForm(baseURL+"/login.php", url.Values{
		"username":   {"admin"},
		"password":   {"password"},
		"Login":      {"Login"},
		"user_token": {dvwaUserToken(t, client, baseURL+"/login.php")},
	})
	require.NoError(t, err, "DVWA /login.php POST")
	_ = resp.Body.Close()

	// 5: resolve the authenticated PHPSESSID from the jar.
	u, err := url.Parse(baseURL)
	require.NoError(t, err, "parse DVWA base URL")
	var phpSessID string
	for _, c := range jar.Cookies(u) {
		if c.Name == "PHPSESSID" {
			phpSessID = c.Value
		}
	}
	require.NotEmpty(t, phpSessID, "DVWA login did not yield a PHPSESSID cookie")

	// DVWA only persists the security level once you toggle it on /security.php;
	// pin it here so the modules exercise the low-security (vulnerable) path.
	return fmt.Sprintf("PHPSESSID=%s; security=low", phpSessID)
}

// dvwaUserToken fetches a DVWA form page and extracts its user_token CSRF field.
func dvwaUserToken(t *testing.T, client *http.Client, pageURL string) string {
	t.Helper()
	resp, err := client.Get(pageURL)
	require.NoError(t, err, "GET %s", pageURL)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read %s body", pageURL)
	m := dvwaTokenRe.FindSubmatch(body)
	require.Len(t, m, 2, "no user_token found on %s", pageURL)
	return string(m[1])
}

// dvwaRequest builds a GET request for the given DVWA path with the
// authenticated session cookie attached, fetches it once to capture the
// baseline response, and returns the populated request/response pair ready
// for runActiveScan.
//
// Two headers matter:
//
//   - Cookie: the PHPSESSID + security=low pair from setupDVWA, without which
//     DVWA redirects every /vulnerabilities/* request to /login.php.
//   - Accept-Encoding: identity. DVWA emits a malformed compressed response
//     (Content-Encoding: gzip *and* Content-Length: 0), and decoding it yields
//     only the page tail — losing the reflected payload / SQL error the
//     scanners key off, so they'd report nothing. Requesting identity makes
//     DVWA return the full uncompressed page (the same thing curl gets, since
//     curl doesn't negotiate gzip by default).
//
// Capturing the baseline response also mirrors how real captured traffic feeds
// the executor: reflection-based modules (e.g. xss_light_scanner) read
// ctx.Response() for their passive pre-check.
func dvwaRequest(t *testing.T, infra *TestInfra, baseURL, path, cookie string) *httpmsg.HttpRequestResponse {
	t.Helper()
	base, err := httpmsg.GetRawRequestFromURL(baseURL + path)
	require.NoError(t, err, "build request for %s", path)
	req := base.Request().
		WithAddedHeader("Cookie", cookie).
		WithAddedHeader("Accept-Encoding", "identity")
	rr := httpmsg.NewHttpRequestResponse(req, nil)

	respChain, _, err := infra.HTTPClient.Execute(rr, vighttp.Options{})
	require.NoError(t, err, "fetch baseline for %s", path)
	defer respChain.Close()
	return rr.WithResponse(httpmsg.NewHttpResponse(respChain.FullResponseBytes()))
}

// DVWA (Damn Vulnerable Web Application) - https://github.com/digininja/DVWA
// A classic vulnerable web app for security testing
//
// Known vulnerabilities at low security level:
// - SQL Injection at /vulnerabilities/sqli/
// - XSS (Reflected) at /vulnerabilities/xss_r/
// - XSS (Stored) at /vulnerabilities/xss_s/
// - LFI at /vulnerabilities/fi/
// - Command Injection at /vulnerabilities/exec/

// TestDVWA_XSS tests XSS detection against DVWA
func TestDVWA_XSS(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Start DVWA container
	app, err := StartContainer(ctx, ContainerConfig{
		Image:       "vulnerables/web-dvwa:latest",
		ExposedPort: "80/tcp",
		WaitStrategy: wait.ForHTTP("/").
			WithPort("80").
			WithStartupTimeout(120 * time.Second),
		ReadyEndpoint: "/",
	})
	require.NoError(t, err, "Failed to start DVWA container")
	defer func() { _ = app.Stop() }()

	t.Logf("DVWA running at %s", app.BaseURL)

	// Setup test infrastructure
	infra, err := SetupTestInfra()
	require.NoError(t, err, "Failed to setup test infrastructure")
	defer infra.Cleanup()

	// DVWA gates its vulnerable pages behind a login + DB-setup flow; without
	// it every request 302s to /login.php and the scanner sees no reflection.
	cookie := setupDVWA(t, app.BaseURL)

	// XSS test cases.
	//
	// Only the reflected case (xss_r) is exercised here. DVWA's DOM XSS (xss_d)
	// is purely client-side — the `default` value is read from
	// document.location by JavaScript and never appears in the server
	// response — so a server-response reflection scanner like xss_light_scanner
	// cannot (and is not meant to) detect it.
	testCases := []struct {
		name        string
		url         string
		expectVuln  bool
		description string
	}{
		{
			name:        "xss_reflected",
			url:         "/vulnerabilities/xss_r/?name=test",
			expectVuln:  true,
			description: "Reflected XSS in name parameter",
		},
	}

	scanner := xss_light_scanner.New()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rr := dvwaRequest(t, infra, app.BaseURL, tc.url, cookie)

			results, err := runActiveScan(t, scanner, rr, infra)
			require.NoError(t, err, "Scanner returned error for %s", tc.url)

			if tc.expectVuln {
				assert.GreaterOrEqual(t, len(results), 1,
					"Expected XSS vulnerability at %s (%s)", tc.url, tc.description)
				for _, r := range results {
					t.Logf("Found XSS: param=%s module=%s", r.FuzzingParameter, r.ModuleID)
				}
			}
		})
	}
}

// TestDVWA_SQLi tests SQL injection detection against DVWA
func TestDVWA_SQLi(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Start DVWA container
	app, err := StartContainer(ctx, ContainerConfig{
		Image:       "vulnerables/web-dvwa:latest",
		ExposedPort: "80/tcp",
		WaitStrategy: wait.ForHTTP("/").
			WithPort("80").
			WithStartupTimeout(120 * time.Second),
		ReadyEndpoint: "/",
	})
	require.NoError(t, err, "Failed to start DVWA container")
	defer func() { _ = app.Stop() }()

	t.Logf("DVWA running at %s", app.BaseURL)

	// Setup test infrastructure
	infra, err := SetupTestInfra()
	require.NoError(t, err, "Failed to setup test infrastructure")
	defer infra.Cleanup()

	cookie := setupDVWA(t, app.BaseURL)

	// SQLi test endpoint
	rr := dvwaRequest(t, infra, app.BaseURL, "/vulnerabilities/sqli/?id=1&Submit=Submit", cookie)

	scanner := sqli_error_based.New()
	results, err := runActiveScan(t, scanner, rr, infra)
	require.NoError(t, err, "Scanner returned error")

	assert.GreaterOrEqual(t, len(results), 1, "Expected SQLi vulnerability in DVWA")
	for _, r := range results {
		t.Logf("Found SQLi: param=%s module=%s desc=%s", r.FuzzingParameter, r.ModuleID, r.Info.Description)
	}
}

// TestDVWA_LFI tests Local File Inclusion detection against DVWA
func TestDVWA_LFI(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Start DVWA container
	app, err := StartContainer(ctx, ContainerConfig{
		Image:       "vulnerables/web-dvwa:latest",
		ExposedPort: "80/tcp",
		WaitStrategy: wait.ForHTTP("/").
			WithPort("80").
			WithStartupTimeout(120 * time.Second),
		ReadyEndpoint: "/",
	})
	require.NoError(t, err, "Failed to start DVWA container")
	defer func() { _ = app.Stop() }()

	t.Logf("DVWA running at %s", app.BaseURL)

	// Setup test infrastructure
	infra, err := SetupTestInfra()
	require.NoError(t, err, "Failed to setup test infrastructure")
	defer infra.Cleanup()

	cookie := setupDVWA(t, app.BaseURL)

	// LFI test endpoint
	rr := dvwaRequest(t, infra, app.BaseURL, "/vulnerabilities/fi/?page=include.php", cookie)

	scanner := lfi_generic.New()
	results, err := runActiveScan(t, scanner, rr, infra)
	require.NoError(t, err, "Scanner returned error")

	assert.GreaterOrEqual(t, len(results), 1, "Expected LFI vulnerability in DVWA")
	for _, r := range results {
		t.Logf("Found LFI: param=%s module=%s desc=%s", r.FuzzingParameter, r.ModuleID, r.Info.Description)
	}
}

// TestDVWA_FullScan runs a comprehensive scan against DVWA
func TestDVWA_FullScan(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Start DVWA container
	app, err := StartContainer(ctx, ContainerConfig{
		Image:       "vulnerables/web-dvwa:latest",
		ExposedPort: "80/tcp",
		WaitStrategy: wait.ForHTTP("/").
			WithPort("80").
			WithStartupTimeout(120 * time.Second),
		ReadyEndpoint: "/",
	})
	require.NoError(t, err, "Failed to start DVWA container")
	defer func() { _ = app.Stop() }()

	t.Logf("DVWA running at %s", app.BaseURL)

	// Setup test infrastructure
	infra, err := SetupTestInfra()
	require.NoError(t, err, "Failed to setup test infrastructure")
	defer infra.Cleanup()

	cookie := setupDVWA(t, app.BaseURL)

	// Endpoints to test
	endpoints := []string{
		"/vulnerabilities/xss_r/?name=test",
		"/vulnerabilities/sqli/?id=1&Submit=Submit",
		"/vulnerabilities/fi/?page=include.php",
		"/vulnerabilities/exec/?ip=127.0.0.1&Submit=Submit",
	}

	// Initialize scanners
	xssScanner := xss_light_scanner.New()
	sqliScanner := sqli_error_based.New()
	lfiScanner := lfi_generic.New()

	findings := make(map[string]int)

	for _, endpoint := range endpoints {
		t.Logf("Scanning: %s", endpoint)

		rr := dvwaRequest(t, infra, app.BaseURL, endpoint, cookie)

		// Run XSS scanner
		if results, err := runActiveScan(t, xssScanner, rr, infra); err == nil {
			findings["XSS"] += len(results)
			for _, r := range results {
				t.Logf("XSS: endpoint=%s param=%s", endpoint, r.FuzzingParameter)
			}
		}

		// Run SQLi scanner
		if results, err := runActiveScan(t, sqliScanner, rr, infra); err == nil {
			findings["SQLi"] += len(results)
			for _, r := range results {
				t.Logf("SQLi: endpoint=%s param=%s", endpoint, r.FuzzingParameter)
			}
		}

		// Run LFI scanner
		if results, err := runActiveScan(t, lfiScanner, rr, infra); err == nil {
			findings["LFI"] += len(results)
			for _, r := range results {
				t.Logf("LFI: endpoint=%s param=%s", endpoint, r.FuzzingParameter)
			}
		}
	}

	// Summary
	t.Logf("=== Scan Summary ===")
	totalFindings := 0
	for vulnType, count := range findings {
		t.Logf("%s: %d findings", vulnType, count)
		totalFindings += count
	}
	t.Logf("Total: %d findings", totalFindings)

	assert.Greater(t, totalFindings, 0, "Expected to find vulnerabilities in DVWA")
}
