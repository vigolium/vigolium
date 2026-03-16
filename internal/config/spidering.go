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

	// Pilot mode: AI-powered crawling where an ACP agent fully controls the browser
	PilotMode         bool   `yaml:"pilot_mode"`          // enable pilot-driven crawl mode
	PilotAutoRegister bool   `yaml:"pilot_auto_register"` // auto-register if no credentials
	PilotUsername     string `yaml:"pilot_username"`      // auth username for pilot mode
	PilotPassword     string `yaml:"pilot_password"`      // auth password for pilot mode
	PilotScreenshot    bool   `yaml:"pilot_screenshot"`      // include screenshot with every action result (more tokens)
	PilotMaxRetries   int    `yaml:"pilot_max_retries"`    // max ACP prompt retries on stall (default: 2)
	PilotStallTimeout string `yaml:"pilot_stall_timeout"` // no-tool-call timeout before retry (default: "7m")
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
		PilotMode:           false,
		PilotAutoRegister:   true,
		PilotUsername:       "",
		PilotPassword:       "",
		PilotScreenshot:     true,
		PilotMaxRetries:     2,
		PilotStallTimeout: "7m",
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

// PilotStallTimeoutParsed parses the pilot_stall_timeout string into time.Duration.
// Returns 7m if not set.
func (c *SpideringConfig) PilotStallTimeoutParsed() time.Duration {
	if c.PilotStallTimeout == "" {
		return 7 * time.Minute
	}
	d, err := time.ParseDuration(c.PilotStallTimeout)
	if err != nil {
		return 7 * time.Minute
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
	if c.PilotMaxRetries < 0 {
		return fmt.Errorf("spidering.pilot_max_retries must be >= 0")
	}
	if c.PilotStallTimeout != "" {
		if _, err := time.ParseDuration(c.PilotStallTimeout); err != nil {
			return fmt.Errorf("spidering.pilot_stall_timeout: invalid duration %q: %w", c.PilotStallTimeout, err)
		}
	}
	validEngines := map[string]bool{
		"": true, "chromium": true, "ungoogled": true, "fingerprint": true,
	}
	if !validEngines[c.BrowserEngine] {
		return fmt.Errorf("spidering.browser_engine must be 'chromium', 'ungoogled', or 'fingerprint', got: %s", c.BrowserEngine)
	}
	return nil
}
