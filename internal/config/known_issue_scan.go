package config

import (
	"fmt"
	"strings"
)

// KnownIssueScanConfig holds configuration for known-issue scan (nuclei library).
type KnownIssueScanConfig struct {
	Tags         []string `yaml:"tags"`          // nuclei template tags (empty = all)
	ExcludeTags  []string `yaml:"exclude_tags"`  // tags to exclude
	Severities   []string `yaml:"severities"`    // filter severities (empty = all)
	TemplatesDir string   `yaml:"templates_dir"` // custom templates path
	// SeverityOverrides remaps the severity a finding is recorded with, keyed by
	// nuclei template ID (case-insensitive). The override is applied after a match
	// but before output/persistence, so the finding, console output, and severity
	// counts all reflect the remapped value. Use it to right-size noisy or
	// context-dependent templates without forking the upstream template (which
	// reverts on `nuclei -update-templates`). Example:
	//
	//	known_issue_scan:
	//	  severity_overrides:
	//	    config-json-exposure-fuzz: medium
	SeverityOverrides map[string]string `yaml:"severity_overrides"`
	EnrichTargets     bool              `yaml:"enrich_targets"` // enrich known-issue scan targets with paths discovered in previous phases (increases coverage but can slow down scans)
}

// DefaultKnownIssueScanConfig returns default known-issue scan configuration.
//
// Severities defaults to critical+high only: at the default (balanced) intensity
// the known-issue scan focuses on high-signal findings rather than enumerating
// every info/low template, which keeps the phase within its time budget. Operators
// who want the full sweep can widen it with:
//
//	vigolium config set known_issue_scan.severities "critical,high,medium,low,info"
func DefaultKnownIssueScanConfig() *KnownIssueScanConfig {
	return &KnownIssueScanConfig{
		Severities:  []string{"critical", "high"},
		ExcludeTags: []string{"dos"},
		// An exposed config.json is not uniformly critical — many ship only public
		// base URLs / feature flags. Record it as medium by default; operators can
		// raise it again or add their own remaps via known_issue_scan.severity_overrides.
		SeverityOverrides: map[string]string{
			"config-json-exposure-fuzz": "medium",
		},
		EnrichTargets: true,
	}
}

// Validate checks known-issue scan configuration for errors.
func (c *KnownIssueScanConfig) Validate() error {
	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true,
		"low": true, "info": true,
	}
	for _, s := range c.Severities {
		if !validSeverities[s] {
			return fmt.Errorf("known_issue_scan.severities: invalid severity %q", s)
		}
	}

	for tmpl, sev := range c.SeverityOverrides {
		if !validSeverities[strings.ToLower(strings.TrimSpace(sev))] {
			return fmt.Errorf("known_issue_scan.severity_overrides[%q]: invalid severity %q", tmpl, sev)
		}
	}

	return nil
}
