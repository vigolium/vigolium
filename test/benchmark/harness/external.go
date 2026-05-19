package harness

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// ExternalSiteConfig configures rate limiting and timeout for external sites.
type ExternalSiteConfig struct {
	RateLimit      int           // Requests per second (default: 2)
	RequestTimeout time.Duration // Per-request timeout (default: 30s)
}

// DefaultExternalConfig returns conservative defaults for external site testing.
func DefaultExternalConfig() ExternalSiteConfig {
	return ExternalSiteConfig{
		RateLimit:      2,
		RequestTimeout: 30 * time.Second,
	}
}

// CheckExternalAvailability verifies an external site is reachable.
// Calls t.Skip() if the site is unreachable.
func CheckExternalAvailability(t *testing.T, baseURL string) {
	t.Helper()

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(baseURL)
	if err != nil {
		t.Skipf("External site %s is unreachable: %v", baseURL, err)
		return
	}
	_ = resp.Body.Close()

	if resp.StatusCode >= 500 {
		t.Skipf("External site %s returned server error: %d", baseURL, resp.StatusCode)
	}
}

// CheckExternalAvailabilityE verifies an external site is reachable.
// Returns an error instead of skipping.
func CheckExternalAvailabilityE(baseURL string) error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(baseURL)
	if err != nil {
		return fmt.Errorf("external site %s is unreachable: %w", baseURL, err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode >= 500 {
		return fmt.Errorf("external site %s returned server error: %d", baseURL, resp.StatusCode)
	}
	return nil
}
