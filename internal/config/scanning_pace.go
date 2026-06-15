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

	// AdaptivePerHost enables AIMD per-host concurrency control: each host starts
	// at MaxPerHost and backs off (halving, bounded by MinPerHost) on distress
	// signals (429/503/502/504, connection error, timeout), recovering toward the
	// ceiling as healthy responses accrue. Off by default — a healthy scan then
	// behaves exactly like the static MaxPerHost semaphore.
	AdaptivePerHost bool `yaml:"adaptive_per_host"`
	// MinPerHost is the adaptive back-off floor (0 = auto: max(1, MaxPerHost/10)).
	MinPerHost int `yaml:"min_per_host"`
	// MaxPerHostCeiling is the adaptive ramp ceiling (0 = MaxPerHost, so adaptive
	// never exceeds the configured concurrency). Set above MaxPerHost to let
	// healthy hosts ramp past it.
	MaxPerHostCeiling int `yaml:"max_per_host_ceiling"`

	Discovery         PhasePace `yaml:"discovery"`
	Spidering         PhasePace `yaml:"spidering"`
	KnownIssueScan    PhasePace `yaml:"known_issue_scan"`
	ExternalHarvester PhasePace `yaml:"external_harvester"`
	DynamicAssessment PhasePace `yaml:"dynamic-assessment"`
}

// PhasePace holds per-phase speed overrides.
// Zero values mean "not set" and fall through to common or built-in defaults.
type PhasePace struct {
	Concurrency          int     `yaml:"concurrency"`
	RateLimit            int     `yaml:"rate_limit"`
	MaxPerHost           int     `yaml:"max_per_host"`
	MaxDuration          string  `yaml:"max_duration"`
	ConcurrencyFactor    float64 `yaml:"concurrency_factor"`
	DurationFactor       float64 `yaml:"duration_factor"`
	ParallelPassive      *bool   `yaml:"parallel_passive,omitempty"`
	FeedbackDrainTimeout string  `yaml:"feedback_drain_timeout,omitempty"`
	ActiveModuleTimeout  string  `yaml:"active_module_timeout,omitempty"`
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
	ActiveModuleTimeout  time.Duration
}

// DefaultScanningPaceConfig returns default scanning pace configuration
// matching the values shown in the example YAML config.
func DefaultScanningPaceConfig() *ScanningPaceConfig {
	return &ScanningPaceConfig{
		Concurrency: 50,
		RateLimit:   100,
		MaxPerHost:  50,
		MaxDuration: "45m",

		Discovery:         PhasePace{DurationFactor: 0.5},
		KnownIssueScan:    PhasePace{DurationFactor: 0.5},
		Spidering:         PhasePace{DurationFactor: 0.1},
		ExternalHarvester: PhasePace{DurationFactor: 0.1},
		DynamicAssessment: PhasePace{DurationFactor: 1.0, ParallelPassive: boolPtr(true), FeedbackDrainTimeout: "500ms"},
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
	case "dynamic-assessment":
		pp = c.DynamicAssessment
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

	// ActiveModuleTimeout: per-phase overrides common default (0 = executor default)
	if pp.ActiveModuleTimeout != "" {
		if d, err := time.ParseDuration(pp.ActiveModuleTimeout); err == nil {
			resolved.ActiveModuleTimeout = d
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
		"dynamic-assessment": &c.DynamicAssessment,
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
		if pp.ActiveModuleTimeout != "" {
			if _, err := time.ParseDuration(pp.ActiveModuleTimeout); err != nil {
				return fmt.Errorf("scanning_pace.%s.active_module_timeout: invalid duration %q: %w", name, pp.ActiveModuleTimeout, err)
			}
		}
	}

	return nil
}
