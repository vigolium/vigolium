//go:build canary

// debug_test.go contains diagnostic tests for comparing direct module invocation
// with harness-based invocation. Run with:
//   go test -v -tags=canary -run TestDebug ./test/benchmark/whitebox/...

package whitebox

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_light_scanner"
	"github.com/vigolium/vigolium/test/benchmark/harness"
)

// TestDebug_DirectVsHarness compares direct module invocation with harness-based invocation.
func TestDebug_DirectVsHarness(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping debug test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Start DVWA using harness container
	app, err := harness.StartContainer(ctx, harness.ContainerConfig{
		Image:       "vulnerables/web-dvwa:latest",
		ExposedPort: "80/tcp",
		WaitStrategy: wait.ForHTTP("/").
			WithPort("80").
			WithStartupTimeout(120 * time.Second),
		ReadyEndpoint: "/",
	})
	require.NoError(t, err, "Failed to start DVWA")
	defer func() { _ = app.Stop() }()

	t.Logf("DVWA at %s", app.BaseURL)

	infra, err := harness.SetupTestInfra()
	require.NoError(t, err)
	defer infra.Cleanup()

	// Test 1: Direct XSS invocation
	t.Run("direct_xss", func(t *testing.T) {
		fullURL := app.BaseURL + "/vulnerabilities/xss_r/?name=test"
		rr, err := httpmsg.GetRawRequestFromURL(fullURL)
		require.NoError(t, err)
		t.Logf("Request raw:\n%s", string(rr.Request().Raw()))

		scanner := xss_light_scanner.New()
		results, err := scanner.ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)
		require.NoError(t, err)
		t.Logf("Direct XSS results: %d", len(results))
		for _, r := range results {
			t.Logf("  Finding: param=%s module=%s", r.FuzzingParameter, r.ModuleID)
		}
	})

	// Test 2: Harness-driven SQLi (should use insertion points now)
	t.Run("harness_sqli", func(t *testing.T) {
		tc := harness.TestCase{
			ID:          "debug-sqli",
			Endpoint:    "/vulnerabilities/sqli/?id=1&Submit=Submit",
			Method:      "GET",
			Modules:     []string{"active-sqli-error-based"},
			Assertion:   "soft",
			MinFindings: 1,
			ScanMode:    "active",
		}
		results := harness.RunActiveTestCase(t, tc, app.BaseURL, infra)
		for _, r := range results {
			t.Logf("SQLi result: findings=%d err=%v duration=%v", r.FindingCount, r.Error, r.Duration)
		}
	})

	// Test 3: Harness-driven LFI (should use insertion points now)
	t.Run("harness_lfi", func(t *testing.T) {
		tc := harness.TestCase{
			ID:          "debug-lfi",
			Endpoint:    "/vulnerabilities/fi/?page=include.php",
			Method:      "GET",
			Modules:     []string{"active-lfi-generic"},
			Assertion:   "soft",
			MinFindings: 1,
			ScanMode:    "active",
		}
		results := harness.RunActiveTestCase(t, tc, app.BaseURL, infra)
		for _, r := range results {
			t.Logf("LFI result: findings=%d err=%v duration=%v", r.FindingCount, r.Error, r.Duration)
		}
	})

	// Test 4: Harness-driven XSS via harness
	t.Run("harness_xss", func(t *testing.T) {
		tc := harness.TestCase{
			ID:          "debug-xss",
			Endpoint:    "/vulnerabilities/xss_r/?name=test",
			Method:      "GET",
			Modules:     []string{"active-xss-light-url-params"},
			Assertion:   "soft",
			MinFindings: 1,
			ScanMode:    "active",
		}
		results := harness.RunActiveTestCase(t, tc, app.BaseURL, infra)
		for _, r := range results {
			t.Logf("XSS result: findings=%d err=%v duration=%v", r.FindingCount, r.Error, r.Duration)
		}
	})

	// Test 5: Harness-driven passive security headers
	t.Run("harness_passive_headers", func(t *testing.T) {
		tc := harness.TestCase{
			ID:          "debug-headers",
			Endpoint:    "/",
			Method:      "GET",
			Modules:     []string{"passive-security-headers-missing"},
			Assertion:   "soft",
			MinFindings: 1,
			ScanMode:    "passive",
		}
		results := harness.RunPassiveTestCase(t, tc, app.BaseURL, infra)
		for _, r := range results {
			t.Logf("Headers result: findings=%d err=%v duration=%v", r.FindingCount, r.Error, r.Duration)
		}
	})
}
