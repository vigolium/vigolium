package config

import (
	"fmt"
)

// SPAConfig holds configuration for Security Posture Assessment (nuclei library).
type SPAConfig struct {
	Tags               []string `yaml:"tags"`                 // nuclei template tags (empty = all)
	ExcludeTags        []string `yaml:"exclude_tags"`         // tags to exclude
	Severities         []string `yaml:"severities"`           // filter severities (empty = all)
	TemplatesDir       string   `yaml:"templates_dir"`        // custom templates path
	EnrichTargets  bool     `yaml:"enrich_targets"`  // enrich SPA targets with paths discovered in previous phases (increases coverage but can slow down scans)
}

// DefaultSPAConfig returns default SPA configuration.
func DefaultSPAConfig() *SPAConfig {
	return &SPAConfig{
		ExcludeTags:       []string{"dos"},
		EnrichTargets: true,
	}
}

// Validate checks SPA configuration for errors.
func (c *SPAConfig) Validate() error {
	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true,
		"low": true, "info": true,
	}
	for _, s := range c.Severities {
		if !validSeverities[s] {
			return fmt.Errorf("spa.severities: invalid severity %q", s)
		}
	}

	return nil
}
