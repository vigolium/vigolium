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
	"github.com/vigolium/vigolium/pkg/modules/active/sqli_error_based"
)

// VAmPI (Vulnerable API) - https://github.com/erev0s/VAmPI
// A vulnerable REST API for testing security tools
//
// Known vulnerabilities:
// - SQL Injection in GET /users/v1/{username} (the username path segment is
//   concatenated into a raw SQL query; injecting a quote yields an unhandled
//   sqlite3.OperationalError — classic error-based SQLi).
// - Broken Authentication
// - Mass Assignment
// - Excessive Data Exposure
//
// Note: /users/v1/_debug and GET /books/v1 ignore their query string entirely
// (they dump all rows regardless of ?username= / ?book=), so those are NOT
// injection points — the injectable surface is the {username} path segment.

// TestVAmPI_SQLi tests SQL injection detection against VAmPI
func TestVAmPI_SQLi(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Start VAmPI container
	app, err := StartContainer(ctx, ContainerConfig{
		Image:       "erev0s/vampi:latest",
		ExposedPort: "5000/tcp",
		WaitStrategy: wait.ForHTTP("/").
			WithPort("5000").
			WithStartupTimeout(60 * time.Second),
		Env: map[string]string{
			"vulnerable": "1", // Enable vulnerable mode
		},
		ReadyEndpoint: "/",
	})
	require.NoError(t, err, "Failed to start VAmPI container")
	defer func() { _ = app.Stop() }()

	t.Logf("VAmPI running at %s", app.BaseURL)

	// Seed the DB so the baseline query succeeds (see seedVAmPIDatabase).
	seedVAmPIDatabase(t, app.BaseURL)

	// Setup test infrastructure
	infra, err := SetupTestInfra()
	require.NoError(t, err, "Failed to setup test infrastructure")
	defer infra.Cleanup()

	// Test cases with known SQLi vulnerable endpoints
	testCases := []struct {
		name        string
		url         string
		expectVuln  bool
		description string
	}{
		{
			name:        "users_path_sqli_admin",
			url:         "/users/v1/admin",
			expectVuln:  true,
			description: "error-based SQL injection in the {username} path segment",
		},
		{
			name:        "users_path_sqli_name1",
			url:         "/users/v1/name1",
			expectVuln:  true,
			description: "error-based SQL injection in the {username} path segment",
		},
		{
			name:        "users_list_safe",
			url:         "/users/v1",
			expectVuln:  false,
			description: "List endpoint (no per-row query) — not an error-based injection point",
		},
	}

	scanner := sqli_error_based.New()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fullURL := app.BaseURL + tc.url

			rr, err := httpmsg.GetRawRequestFromURL(fullURL)
			require.NoError(t, err, "Failed to create request from URL: %s", fullURL)

			results, err := runActiveScan(t, scanner, rr, infra)
			require.NoError(t, err, "Scanner returned error for %s", fullURL)

			if tc.expectVuln {
				assert.GreaterOrEqual(t, len(results), 1,
					"Expected SQLi vulnerability at %s (%s)", tc.url, tc.description)
				for _, r := range results {
					t.Logf("Found SQLi: param=%s module=%s", r.FuzzingParameter, r.ModuleID)
				}
			} else {
				// The safe list endpoint is not an error-based injection point,
				// so the scanner must report nothing there. A non-empty result is
				// a false positive and should fail the test.
				assert.Empty(t, results,
					"expected no error-based SQLi at safe endpoint %s (%s); got %d (false positive)",
					tc.url, tc.description, len(results))
			}
		})
	}
}

// TestVAmPI_FullScan runs multiple modules against VAmPI
func TestVAmPI_FullScan(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Start VAmPI container
	app, err := StartContainer(ctx, ContainerConfig{
		Image:       "erev0s/vampi:latest",
		ExposedPort: "5000/tcp",
		WaitStrategy: wait.ForHTTP("/").
			WithPort("5000").
			WithStartupTimeout(60 * time.Second),
		Env: map[string]string{
			"vulnerable": "1",
		},
		ReadyEndpoint: "/",
	})
	require.NoError(t, err, "Failed to start VAmPI container")
	defer func() { _ = app.Stop() }()

	t.Logf("VAmPI running at %s", app.BaseURL)

	// Seed the DB so the baseline query succeeds (see seedVAmPIDatabase).
	seedVAmPIDatabase(t, app.BaseURL)

	// Setup test infrastructure
	infra, err := SetupTestInfra()
	require.NoError(t, err, "Failed to setup test infrastructure")
	defer infra.Cleanup()

	// Endpoints to scan. The {username} path segment is the error-based SQLi
	// surface; the others exercise non-injectable paths (the scan should run
	// cleanly against them and contribute no error-based findings).
	endpoints := []string{
		"/users/v1/admin",
		"/users/v1/name1",
		"/users/v1/_debug",
		"/users/v1/login",
	}

	sqliScanner := sqli_error_based.New()
	totalFindings := 0

	for _, endpoint := range endpoints {
		fullURL := app.BaseURL + endpoint

		rr, err := httpmsg.GetRawRequestFromURL(fullURL)
		if err != nil {
			t.Logf("Skipping %s: %v", endpoint, err)
			continue
		}

		// Run SQLi scanner
		results, err := runActiveScan(t, sqliScanner, rr, infra)
		if err != nil {
			t.Logf("SQLi scan error for %s: %v", endpoint, err)
			continue
		}

		totalFindings += len(results)
		for _, r := range results {
			t.Logf("Finding: endpoint=%s module=%s param=%s",
				endpoint, r.ModuleID, r.FuzzingParameter)
		}
	}

	t.Logf("Total findings: %d", totalFindings)
	assert.Greater(t, totalFindings, 0, "Expected to find at least one vulnerability in VAmPI")
}
