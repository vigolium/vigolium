//go:build canary

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_light_scanner"
	"github.com/vigolium/vigolium/pkg/modules/active/lfi_generic"
	"github.com/vigolium/vigolium/pkg/modules/active/sqli_error_based"
)

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

	// XSS test cases
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
		{
			name:        "xss_dom",
			url:         "/vulnerabilities/xss_d/?default=English",
			expectVuln:  true,
			description: "DOM-based XSS in default parameter",
		},
	}

	scanner := xss_light_scanner.New()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fullURL := app.BaseURL + tc.url

			rr, err := httpmsg.GetRawRequestFromURL(fullURL)
			require.NoError(t, err, "Failed to create request from URL: %s", fullURL)

			results, err := scanner.ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)
			require.NoError(t, err, "Scanner returned error for %s", fullURL)

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

	// SQLi test endpoint
	fullURL := app.BaseURL + "/vulnerabilities/sqli/?id=1&Submit=Submit"

	rr, err := httpmsg.GetRawRequestFromURL(fullURL)
	require.NoError(t, err, "Failed to create request")

	scanner := sqli_error_based.New()
	results, err := scanner.ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)
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

	// LFI test endpoint
	fullURL := app.BaseURL + "/vulnerabilities/fi/?page=include.php"

	rr, err := httpmsg.GetRawRequestFromURL(fullURL)
	require.NoError(t, err, "Failed to create request")

	scanner := lfi_generic.New()
	results, err := scanner.ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)
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
		fullURL := app.BaseURL + endpoint
		t.Logf("Scanning: %s", endpoint)

		rr, err := httpmsg.GetRawRequestFromURL(fullURL)
		if err != nil {
			t.Logf("Skipping %s: %v", endpoint, err)
			continue
		}

		// Run XSS scanner
		if results, err := xssScanner.ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx); err == nil {
			findings["XSS"] += len(results)
			for _, r := range results {
				t.Logf("XSS: endpoint=%s param=%s", endpoint, r.FuzzingParameter)
			}
		}

		// Run SQLi scanner
		if results, err := sqliScanner.ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx); err == nil {
			findings["SQLi"] += len(results)
			for _, r := range results {
				t.Logf("SQLi: endpoint=%s param=%s", endpoint, r.FuzzingParameter)
			}
		}

		// Run LFI scanner
		if results, err := lfiScanner.ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx); err == nil {
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
