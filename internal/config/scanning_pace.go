package config

import (
	"fmt"
	"math"
	"time"
)

// ScanningPaceConfig provides centralized speed control parameters.
// Common values serve as a baseline for all phases; per-phase subsections
// override specific values. CLI flags still take higher precedence.
type ScanningPaceConfig struct {
	Concurrency int    `yaml:"concurrency"`
	RateLimit   int    `yaml:"rate_limit"`
	MaxPerHost  int    `yaml:"max_per_host"`
	MaxDuration string `yaml:"max_duration"`

	Discovery         PhasePace `yaml:"discovery"`
	Spidering         PhasePace `yaml:"spidering"`
	KnownIssueScan    PhasePace `yaml:"known_issue_scan"`
	ExternalHarvester PhasePace `yaml:"external_harvester"`
	Audit PhasePace `yaml:"audit"`
}

// PhasePace holds per-phase speed overrides.
// Zero values mean "not set" and fall through to common or built-in defaults.
type PhasePace struct {
	Concurrency       int     `yaml:"concurrency"`
	RateLimit         int     `yaml:"rate_limit"`
	MaxPerHost        int     `yaml:"max_per_host"`
	MaxDuration       string  `yaml:"max_duration"`
	ConcurrencyFactor float64 `yaml:"concurrency_factor"`
	DurationFactor    float64 `yaml:"duration_factor"`
	ParallelPassive       *bool  `yaml:"parallel_passive,omitempty"`
	FeedbackDrainTimeout  string `yaml:"feedback_drain_timeout,omitempty"`
}

// ResolvedPhasePace is the result of merging common + per-phase values.
type ResolvedPhasePace struct {
	Concurrency          int
	RateLimit            int
	MaxPerHost           int
	MaxDuration          time.Duration
	ConcurrencyFactor    float64
	DurationFactor       float64
	ParallelPassive      bool
	FeedbackDrainTimeout time.Duration
}

// DefaultScanningPaceConfig returns default scanning pace configuration
// matching the values shown in the example YAML config.
func DefaultScanningPaceConfig() *ScanningPaceConfig {
	return &ScanningPaceConfig{
		Concurrency: 50,
		RateLimit:   100,
		MaxPerHost:  20,
		MaxDuration: "2h",

		KnownIssueScan:    PhasePace{DurationFactor: 3.0},
		Spidering:         PhasePace{DurationFactor: 0.15},
		ExternalHarvester: PhasePace{DurationFactor: 0.2},
		Audit: PhasePace{DurationFactor: 1.0, ParallelPassive: boolPtr(true), FeedbackDrainTimeout: "500ms"},
	}
}

// maxDurationParsed parses the common max_duration string into a time.Duration.
// Returns 0 if unset or unparseable.
func (c *ScanningPaceConfig) maxDurationParsed() time.Duration {
	if c.MaxDuration == "" {
		return 0
	}
	d, err := time.ParseDuration(c.MaxDuration)
	if err != nil {
		return 0
	}
	return d
}

// MaxDurationParsed parses the max_duration string into a time.Duration.
// Returns 0 if unset or unparseable.
func (p *PhasePace) MaxDurationParsed() time.Duration {
	if p.MaxDuration == "" {
		return 0
	}
	d, err := time.ParseDuration(p.MaxDuration)
	if err != nil {
		return 0
	}
	return d
}

// ResolvePhase merges common values with per-phase overrides for the named phase.
// Non-zero per-phase values win over common values.
func (c *ScanningPaceConfig) ResolvePhase(phase string) ResolvedPhasePace {
	var pp PhasePace
	switch phase {
	case "discovery":
		pp = c.Discovery
	case "spidering":
		pp = c.Spidering
	case "known-issue-scan":
		pp = c.KnownIssueScan
	case "external_harvester":
		pp = c.ExternalHarvester
	case "audit":
		pp = c.Audit
	}

	resolved := ResolvedPhasePace{
		Concurrency: c.Concurrency,
		RateLimit:   c.RateLimit,
		MaxPerHost:  c.MaxPerHost,
	}

	// Concurrency: explicit per-phase > factor × common > common
	if pp.Concurrency > 0 {
		resolved.Concurrency = pp.Concurrency
	} else if pp.ConcurrencyFactor > 0 && c.Concurrency > 0 {
		resolved.Concurrency = int(math.Round(float64(c.Concurrency) * pp.ConcurrencyFactor))
		resolved.ConcurrencyFactor = pp.ConcurrencyFactor
	}

	if pp.RateLimit > 0 {
		resolved.RateLimit = pp.RateLimit
	}
	if pp.MaxPerHost > 0 {
		resolved.MaxPerHost = pp.MaxPerHost
	}

	// MaxDuration: explicit per-phase > factor × common > common
	commonDuration := c.maxDurationParsed()
	if pp.MaxDuration != "" {
		resolved.MaxDuration = pp.MaxDurationParsed()
	} else if pp.DurationFactor > 0 && commonDuration > 0 {
		resolved.MaxDuration = time.Duration(float64(commonDuration) * pp.DurationFactor)
		resolved.DurationFactor = pp.DurationFactor
	} else {
		resolved.MaxDuration = commonDuration
	}

	// ParallelPassive: per-phase pointer overrides common default (false)
	if pp.ParallelPassive != nil {
		resolved.ParallelPassive = *pp.ParallelPassive
	}

	// FeedbackDrainTimeout: per-phase overrides common default (0 = executor default)
	if pp.FeedbackDrainTimeout != "" {
		if d, err := time.ParseDuration(pp.FeedbackDrainTimeout); err == nil {
			resolved.FeedbackDrainTimeout = d
		}
	}

	return resolved
}

// boolPtr returns a pointer to a bool value. Used for optional YAML fields.
func boolPtr(b bool) *bool { return &b }

// Validate rejects negative values and invalid duration strings.
func (c *ScanningPaceConfig) Validate() error {
	if c.Concurrency < 0 {
		return fmt.Errorf("scanning_pace.concurrency must be >= 0")
	}
	if c.RateLimit < 0 {
		return fmt.Errorf("scanning_pace.rate_limit must be >= 0")
	}
	if c.MaxPerHost < 0 {
		return fmt.Errorf("scanning_pace.max_per_host must be >= 0")
	}
	if c.MaxDuration != "" {
		if _, err := time.ParseDuration(c.MaxDuration); err != nil {
			return fmt.Errorf("scanning_pace.max_duration: invalid duration %q: %w", c.MaxDuration, err)
		}
	}

	phases := map[string]*PhasePace{
		"discovery":          &c.Discovery,
		"spidering":          &c.Spidering,
		"known-issue-scan":   &c.KnownIssueScan,
		"external_harvester": &c.ExternalHarvester,
		"audit": &c.Audit,
	}
	for name, pp := range phases {
		if pp.Concurrency < 0 {
			return fmt.Errorf("scanning_pace.%s.concurrency must be >= 0", name)
		}
		if pp.RateLimit < 0 {
			return fmt.Errorf("scanning_pace.%s.rate_limit must be >= 0", name)
		}
		if pp.MaxPerHost < 0 {
			return fmt.Errorf("scanning_pace.%s.max_per_host must be >= 0", name)
		}
		if pp.MaxDuration != "" {
			if _, err := time.ParseDuration(pp.MaxDuration); err != nil {
				return fmt.Errorf("scanning_pace.%s.max_duration: invalid duration %q: %w", name, pp.MaxDuration, err)
			}
		}
		if pp.ConcurrencyFactor < 0 {
			return fmt.Errorf("scanning_pace.%s.concurrency_factor must be >= 0", name)
		}
		if pp.DurationFactor < 0 {
			return fmt.Errorf("scanning_pace.%s.duration_factor must be >= 0", name)
		}
		if pp.FeedbackDrainTimeout != "" {
			if _, err := time.ParseDuration(pp.FeedbackDrainTimeout); err != nil {
				return fmt.Errorf("scanning_pace.%s.feedback_drain_timeout: invalid duration %q: %w", name, pp.FeedbackDrainTimeout, err)
			}
		}
	}

	return nil
}
