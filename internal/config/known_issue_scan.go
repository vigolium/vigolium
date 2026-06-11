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
	// GroupByValue collapses findings that repeat the same extracted value across
	// many URLs (e.g. one leaked secret reported once per page) into a single
	// finding. It applies both to the stored/reported findings (a post-phase
	// merge pass) and to the live console output (one line per unique value).
	GroupByValue *FindingGroupingConfig `yaml:"group_by_value,omitempty"`
}

// FindingGroupingConfig controls value-based grouping of findings that share an
// identical extracted value across many URLs — the classic example being one
// leaked API key surfaced on dozens of pages, which would otherwise be reported
// once per page.
type FindingGroupingConfig struct {
	// Enabled turns value-based grouping on.
	Enabled bool `yaml:"enabled"`
	// PerHost keeps the same value found on different hosts as separate findings.
	// When false, grouping is project-wide regardless of host.
	PerHost bool `yaml:"per_host"`
	// Tags, when non-empty, restricts grouping to findings carrying at least one
	// of these tags (case-insensitive). Empty groups any finding that repeats an
	// identical extracted value — the value-identity (plus module + severity) is
	// itself the guardrail against merging unrelated findings.
	Tags []string `yaml:"tags"`
	// MaxURLs caps how many distinct matched URLs are retained on the survivor
	// finding (0 = unlimited), bounding MatchedAt on very noisy sites.
	MaxURLs int `yaml:"max_urls"`
}

// defaultFindingGrouping is the effective grouping config when none is set in
// YAML. Grouping is on by default with per-host scoping so a leaked secret seen
// across a site collapses to one finding without merging across hostnames.
func defaultFindingGrouping() FindingGroupingConfig {
	return FindingGroupingConfig{
		Enabled: true,
		PerHost: true,
		MaxURLs: 50,
	}
}

// ResolveGroupByValue returns the effective grouping config, falling back to the
// shipped default when unset (a nil pointer survives profile overlays via the
// omitempty tag, so this keeps grouping on for partial configs).
func (c *KnownIssueScanConfig) ResolveGroupByValue() FindingGroupingConfig {
	if c.GroupByValue != nil {
		return *c.GroupByValue
	}
	return defaultFindingGrouping()
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
	grouping := defaultFindingGrouping()
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
		GroupByValue:  &grouping,
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

	if c.GroupByValue != nil && c.GroupByValue.MaxURLs < 0 {
		return fmt.Errorf("known_issue_scan.group_by_value.max_urls: must be >= 0, got %d", c.GroupByValue.MaxURLs)
	}

	return nil
}
