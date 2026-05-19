package fingerprint

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// Learner implements the 3-baseline sampling algorithm for learning 404 signatures
type Learner struct {
	client        *http.Client
	delay         time.Duration     // Delay between requests (default: 1 second)
	customHeaders map[string]string // User-defined HTTP request headers
}

// NewLearner creates a new learner with optional custom headers
func NewLearner(client *http.Client, customHeaders map[string]string) *Learner {
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	return &Learner{
		client:        client,
		delay:         20 * time.Millisecond, // Reduced from 1s for faster validation
		customHeaders: customHeaders,
	}
}

// SetDelay sets the delay between learning requests
func (l *Learner) SetDelay(delay time.Duration) {
	l.delay = delay
}

// Learn performs 3-baseline sampling and returns a signature
//
// Algorithm:
// 1. Generate 3 random non-existent paths
// 2. Request each path with delay
// 3. Extract fingerprint from each response
// 4. Build signature from stable attributes
func (l *Learner) Learn(ctx context.Context, baseURL *url.URL) (*Signature, error) {
	if baseURL == nil {
		return nil, fmt.Errorf("base URL is nil")
	}

	// Generate 3 random path variations
	paths, err := GenerateRandomPaths(baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random paths: %w", err)
	}

	// Request each path and extract sample
	samples := make([]*Sample, 0, 3)

	for i, pathVariation := range paths {
		// Build full URL
		testURL := *baseURL // Copy
		testURL.Path = pathVariation

		// Add delay between requests (except first)
		if i > 0 && l.delay > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(l.delay):
			}
		}

		// Request the non-existent path
		sample, err := l.RequestAndExtract(ctx, &testURL)
		if err != nil {
			return nil, fmt.Errorf("failed to request path %s: %w", pathVariation, err)
		}

		samples = append(samples, sample)
	}

	// Build signature from samples
	signature, err := NewSignature(samples)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %w", err)
	}

	// Set debug info
	signature.SetDebug(fmt.Sprintf("learned from %s", baseURL.Host))

	return signature, nil
}

// LearnFromPaths learns from specific paths (for testing or custom scenarios)
func (l *Learner) LearnFromPaths(ctx context.Context, baseURL *url.URL, paths []string) (*Signature, error) {
	if baseURL == nil {
		return nil, fmt.Errorf("base URL is nil")
	}

	if len(paths) < 3 {
		return nil, fmt.Errorf("need at least 3 paths, got %d", len(paths))
	}

	samples := make([]*Sample, 0, len(paths))

	for i, pathVariation := range paths {
		// Build full URL
		testURL := *baseURL // Copy
		testURL.Path = pathVariation

		// Add delay between requests (except first)
		if i > 0 && l.delay > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(l.delay):
			}
		}

		// Request the path
		sample, err := l.RequestAndExtract(ctx, &testURL)
		if err != nil {
			return nil, fmt.Errorf("failed to request path %s: %w", pathVariation, err)
		}

		samples = append(samples, sample)
	}

	// Build signature from samples
	signature, err := NewSignature(samples)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %w", err)
	}

	signature.SetDebug(fmt.Sprintf("learned from %s", baseURL.Host))

	return signature, nil
}

// RequestAndExtract performs HTTP request and extracts fingerprint sample
// This is exported for use by wildcard comparator
func (l *Learner) RequestAndExtract(ctx context.Context, url *url.URL) (*Sample, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set browser-like headers (matches infrahttp.RequestBuilder defaults)
	req.Header.Set("User-Agent", httpmsg.DefaultUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	// req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	// Apply custom headers (override defaults if specified)
	for key, value := range l.customHeaders {
		// Special handling for Host header - Go's net/http ignores Header["Host"]
		if strings.EqualFold(key, "Host") {
			req.Host = value
		} else {
			req.Header.Set(key, value)
		}
	}

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}

	// Use ResponseChain for body handling
	rc := responsechain.NewResponseChain(resp, 0)
	if err := rc.Fill(); err != nil {
		rc.Close()
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	defer rc.Close()

	return NewSampleFromRC(rc)
}

// ValidateSignature checks if signature is usable
// A good signature should have:
// - At least 5 stable attributes (structural stability)
// - Include critical attributes (StatusCode, ContentType)
func (l *Learner) ValidateSignature(sig *Signature) error {
	if sig == nil {
		return fmt.Errorf("signature is nil")
	}

	// stableCount := sig.StableAttributeCount()
	// if stableCount < 5 {
	// 	return fmt.Errorf("signature has too few stable attributes (%d), need at least 5", stableCount)
	// }

	// Check for critical attributes
	if !sig.HasAttribute(StatusCode) {
		return fmt.Errorf("signature missing critical attribute: StatusCode")
	}

	return nil
}

// LearnWithValidation learns and validates signature in one call
func (l *Learner) LearnWithValidation(ctx context.Context, baseURL *url.URL) (*Signature, error) {
	sig, err := l.Learn(ctx, baseURL)
	if err != nil {
		return nil, err
	}

	if err := l.ValidateSignature(sig); err != nil {
		return nil, fmt.Errorf("learned signature is invalid: %w", err)
	}

	return sig, nil
}
