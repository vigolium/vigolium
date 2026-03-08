package config

import (
	"fmt"
	"time"
)

// SpideringConfig configures the browser-based spidering phase.
type SpideringConfig struct {
	MaxDepth            int    `yaml:"max_depth"`             // 0 = unlimited
	MaxStates           int    `yaml:"max_states"`            // 0 = unlimited
	MaxDuration         string `yaml:"max_duration"`          // default: "30m"
	MaxConsecutiveFails int    `yaml:"max_consecutive_fails"` // default: 100
	Headless            bool   `yaml:"headless"`              // default: true
	BrowserCount        int    `yaml:"browser_count"`         // default: 1
	Strategy            string `yaml:"strategy"`              // default: "adaptive"
	IncludeResponseBody bool   `yaml:"include_response_body"` // default: true
	BrowserEngine       string `yaml:"browser_engine"`        // "chromium" (default), "ungoogled", or "fingerprint"
	NoCDP               bool   `yaml:"no_cdp"`                // disable CDP event listener detection
	NoForms             bool   `yaml:"no_forms"`              // disable automatic form filling
}

// DefaultSpideringConfig returns sensible defaults for spidering.
func DefaultSpideringConfig() *SpideringConfig {
	return &SpideringConfig{
		MaxDepth:            0,
		MaxStates:           0,
		MaxDuration:         "30m",
		MaxConsecutiveFails: 100,
		Headless:            true,
		BrowserCount:        1,
		Strategy:            "adaptive",
		IncludeResponseBody: true,
		BrowserEngine:       "chromium",
		NoCDP:               false,
		NoForms:             false,
	}
}

// MaxDurationParsed parses the max_duration string into time.Duration.
func (c *SpideringConfig) MaxDurationParsed() time.Duration {
	if c.MaxDuration == "" {
		return 30 * time.Minute
	}
	d, err := time.ParseDuration(c.MaxDuration)
	if err != nil {
		return 30 * time.Minute
	}
	return d
}

// Validate checks spidering configuration for errors.
func (c *SpideringConfig) Validate() error {
	if c.MaxDepth < 0 {
		return fmt.Errorf("spidering.max_depth must be >= 0")
	}
	if c.MaxStates < 0 {
		return fmt.Errorf("spidering.max_states must be >= 0")
	}
	if c.MaxConsecutiveFails < 0 {
		return fmt.Errorf("spidering.max_consecutive_fails must be >= 0")
	}
	if c.BrowserCount < 0 {
		return fmt.Errorf("spidering.browser_count must be >= 0")
	}
	if c.MaxDuration != "" {
		if _, err := time.ParseDuration(c.MaxDuration); err != nil {
			return fmt.Errorf("spidering.max_duration: invalid duration %q: %w", c.MaxDuration, err)
		}
	}
	validStrategies := map[string]bool{
		"normal": true, "random": true, "oldest_first": true, "shallow_first": true, "adaptive": true,
	}
	if c.Strategy != "" && !validStrategies[c.Strategy] {
		return fmt.Errorf("spidering.strategy must be normal/random/oldest_first/shallow_first/adaptive, got: %s", c.Strategy)
	}
	validEngines := map[string]bool{
		"": true, "chromium": true, "ungoogled": true, "fingerprint": true,
	}
	if !validEngines[c.BrowserEngine] {
		return fmt.Errorf("spidering.browser_engine must be 'chromium', 'ungoogled', or 'fingerprint', got: %s", c.BrowserEngine)
	}
	return nil
}
