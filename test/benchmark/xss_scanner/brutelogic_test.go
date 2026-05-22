//go:build integration

package xss_scanner_integration

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	httpRequester "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_light_scanner"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types"
)

// testCases contains brutelogic XSS gym URLs that should be detected by the scanner
// Excluded:
// - p04: Event handler with double URL encoding (%26apos;) - requires advanced double encoding detection
// - p21, p25, p26, p27: DOM-based XSS (out of scope for reflected XSS scanner)
// - p29, p30, p31, p32, p33, p34: Special techniques (header/path injection, CSP bypass, unicode escapes)
// - ent.php, mjson.php: Multiple reflection points with complex encodings
var testCases = []string{
	// gym.php - reflected XSS cases
	"https://x55.is/brutelogic/gym.php?p01=hello", // HTML in title
	"https://x55.is/brutelogic/gym.php?p02=hello", // HTML in noscript
	"https://x55.is/brutelogic/gym.php?p03=hello", // HTML in style
	"https://x55.is/brutelogic/gym.php?p05=hello", // HTML body
	"https://x55.is/brutelogic/gym.php?p06=hello", // HTML attribute DQ
	"https://x55.is/brutelogic/gym.php?p07=hello", // HTML attribute SQ
	"https://x55.is/brutelogic/gym.php?p08=hello", // HTML input value DQ
	"https://x55.is/brutelogic/gym.php?p09=hello", // HTML input value SQ
	"https://x55.is/brutelogic/gym.php?p10=hello", // HTML textarea
	"https://x55.is/brutelogic/gym.php?p11=hello", // JS string SQ with </script> breakout
	"https://x55.is/brutelogic/gym.php?p12=hello", // JS string DQ with </script> breakout
	"https://x55.is/brutelogic/gym.php?p13=hello", // JS string SQ
	"https://x55.is/brutelogic/gym.php?p14=hello", // JS string DQ
	"https://x55.is/brutelogic/gym.php?p15=hello", // JS string SQ with backslash escape
	"https://x55.is/brutelogic/gym.php?p16=hello", // JS string DQ with backslash escape
	"https://x55.is/brutelogic/gym.php?p17=hello", // JS template literal with </script> breakout
	"https://x55.is/brutelogic/gym.php?p18=hello", // JS template literal
	"https://x55.is/brutelogic/gym.php?p19=hello", // JS template literal with backslash escape
	"https://x55.is/brutelogic/gym.php?p20=hello", // JS template literal with ${} injection
	"https://x55.is/brutelogic/gym.php?p22=hello", // URL attribute
	"https://x55.is/brutelogic/gym.php?p23=hello", // CRLF injection
	"https://x55.is/brutelogic/gym.php?p24=hello", // JS multi-statement
	"https://x55.is/brutelogic/gym.php?p28=hello", // HTML comment breakout

	// xss.php - a, b1-b6, c1-c6
	"https://x55.is/brutelogic/xss.php?a=hello",  // HTML body
	"https://x55.is/brutelogic/xss.php?b1=hello", // HTML attribute DQ
	"https://x55.is/brutelogic/xss.php?b2=hello", // HTML attribute SQ
	"https://x55.is/brutelogic/xss.php?b3=hello", // HTML attribute DQ
	"https://x55.is/brutelogic/xss.php?b4=hello", // HTML attribute SQ
	"https://x55.is/brutelogic/xss.php?b5=hello", // HTML attribute DQ
	"https://x55.is/brutelogic/xss.php?b6=hello", // HTML attribute SQ
	"https://x55.is/brutelogic/xss.php?c1=hello", // JS string SQ with </script> breakout
	"https://x55.is/brutelogic/xss.php?c2=hello", // JS string DQ with </script> breakout
	"https://x55.is/brutelogic/xss.php?c3=hello", // JS string SQ
	"https://x55.is/brutelogic/xss.php?c4=hello", // JS string DQ
	"https://x55.is/brutelogic/xss.php?c5=hello", // JS string SQ with backslash escape
	"https://x55.is/brutelogic/xss.php?c6=hello", // JS string DQ with backslash escape
}

// checkBrutelogicAvailable checks if the brutelogic XSS gym server is reachable
func checkBrutelogicAvailable(t *testing.T) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://x55.is/brutelogic/gym.php?p01=test")
	if err != nil {
		t.Skipf("Brutelogic XSS gym not available: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Skipf("Brutelogic XSS gym returned status %d", resp.StatusCode)
	}
}

// TestInfra holds the test infrastructure components
type TestInfra struct {
	HTTPClient  *httpRequester.Requester
	HostErrors  *hosterrors.Cache
	HostLimiter *hostlimit.HostRateLimiter
	ScanCtx     *modkit.ScanContext
}

// setupTestInfra initializes HTTP client and services
func setupTestInfra(t *testing.T) *TestInfra {
	t.Helper()

	opts := types.DefaultOptions()
	opts.Timeout = 30
	opts.Retries = 1
	opts.MaxPerHost = 5
	opts.MaxHostError = 5

	err := network.Init(opts)
	require.NoError(t, err, "Failed to initialize network dialer")

	hostErrors := hosterrors.New(opts.MaxHostError, hosterrors.DefaultMaxHostsCount, nil)
	hostLimiter := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{
		MaxPerHost: opts.MaxPerHost,
	})

	svc := &services.Services{
		Options:     opts,
		HostLimiter: hostLimiter,
		HostErrors:  hostErrors,
	}

	httpClient, err := httpRequester.NewRequester(opts, svc)
	require.NoError(t, err, "Failed to create HTTP requester")

	return &TestInfra{
		HTTPClient:  httpClient,
		HostErrors:  hostErrors,
		HostLimiter: hostLimiter,
		ScanCtx:     &modkit.ScanContext{},
	}
}

// cleanup performs cleanup after tests
func (infra *TestInfra) cleanup() {
	if infra.HostErrors != nil {
		infra.HostErrors.Close()
	}
	if infra.HostLimiter != nil {
		_ = infra.HostLimiter.Close()
	}
	network.Close()
}

// extractTestName extracts test name from URL (e.g. "p01" from gym.php?p01=hello)
func extractTestName(url string) string {
	for i := len(url) - 1; i >= 0; i-- {
		if url[i] == '?' {
			end := i + 1
			for j := end; j < len(url); j++ {
				if url[j] == '=' {
					return url[end:j]
				}
			}
		}
	}
	return url
}

// TestBrutelogicGym tests XSS scanner against all brutelogic gym URLs
// Each URL must return at least 1 result - test fails otherwise
func TestBrutelogicGym(t *testing.T) {
	checkBrutelogicAvailable(t)

	infra := setupTestInfra(t)
	defer infra.cleanup()

	for _, url := range testCases {
		url := url // capture range variable
		testName := extractTestName(url)

		t.Run(testName, func(t *testing.T) {
			// Create fresh scanner for each test to avoid deduplication
			scanner := xss_light_scanner.New()

			rr, err := httpmsg.GetRawRequestFromURL(url)
			require.NoError(t, err, "Failed to create request from URL: %s", url)

			results, err := scanner.ScanPerRequest(rr, infra.HTTPClient, infra.ScanCtx)
			require.NoError(t, err, "Scanner returned error for %s", url)

			// MUST have at least 1 result - fail if not detected
			assert.GreaterOrEqual(t, len(results), 1,
				"Expected at least 1 result for %s, got %d", url, len(results))

			// Log and verify result fields when detected
			for _, r := range results {
				assert.NotEmpty(t, r.URL, "Result URL should not be empty")
				assert.NotEmpty(t, r.FuzzingParameter, "FuzzingParameter should not be empty")
				t.Logf("Found XSS: param=%s desc=%s", r.FuzzingParameter, r.Info.Description)
			}
		})
	}
}
