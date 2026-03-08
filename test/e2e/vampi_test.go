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
// - SQL Injection in /users/v1/_debug (username parameter)
// - SQL Injection in /books/v1 (book parameter)
// - Broken Authentication
// - Mass Assignment
// - Excessive Data Exposure

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
			name:        "users_debug_sqli",
			url:         "/users/v1/_debug?username=admin",
			expectVuln:  true,
			description: "SQL injection in username parameter",
		},
		{
			name:        "books_search",
			url:         "/books/v1?book=test",
			expectVuln:  true,
			description: "SQL injection in book search parameter",
		},
		{
			name:        "users_list_safe",
			url:         "/users/v1",
			expectVuln:  false,
			description: "Safe endpoint without injection points",
		},
	}

	scanner := sqli_error_based.New()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fullURL := app.BaseURL + tc.url

			rr, err := httpmsg.GetRawRequestFromURL(fullURL)
			require.NoError(t, err, "Failed to create request from URL: %s", fullURL)

			results, err := scanner.ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)
			require.NoError(t, err, "Scanner returned error for %s", fullURL)

			if tc.expectVuln {
				assert.GreaterOrEqual(t, len(results), 1,
					"Expected SQLi vulnerability at %s (%s)", tc.url, tc.description)
				for _, r := range results {
					t.Logf("Found SQLi: param=%s module=%s", r.FuzzingParameter, r.ModuleID)
				}
			} else {
				// For safe endpoints, we don't necessarily expect 0 results
				// but we log what was found
				t.Logf("Results for safe endpoint %s: %d findings", tc.url, len(results))
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

	// Setup test infrastructure
	infra, err := SetupTestInfra()
	require.NoError(t, err, "Failed to setup test infrastructure")
	defer infra.Cleanup()

	// Endpoints to scan
	endpoints := []string{
		"/users/v1/_debug?username=admin",
		"/books/v1?book=test",
		"/users/v1/login",
		"/users/v1/register",
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
		results, err := sqliScanner.ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)
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
