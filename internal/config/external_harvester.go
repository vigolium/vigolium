package config

import (
	"fmt"
)

// ExternalHarvesterConfig holds configuration for pre-scan external intelligence harvesting.
type ExternalHarvesterConfig struct {
	Sources []string `yaml:"sources"`
	APIKeys ExternalHarvesterAPIKeys `yaml:"api_keys"`
}

// ExternalHarvesterAPIKeys holds API keys for external harvester sources that require authentication.
type ExternalHarvesterAPIKeys struct {
	URLScan    string `yaml:"urlscan"`
	VirusTotal string `yaml:"virustotal"`
}

// DefaultExternalHarvesterConfig returns default external harvester configuration.
func DefaultExternalHarvesterConfig() *ExternalHarvesterConfig {
	return &ExternalHarvesterConfig{
		Sources: []string{"wayback", "commoncrawl", "alienvault"},
	}
}

var validExternalHarvesterSources = map[string]bool{
	"wayback":     true,
	"commoncrawl": true,
	"urlscan":     true,
	"alienvault":  true,
	"virustotal":  true,
}

var keyRequiredSources = map[string]bool{
	"urlscan":    true,
	"virustotal": true,
}

// Validate checks external harvester configuration for errors.
func (c *ExternalHarvesterConfig) Validate() error {
	for _, s := range c.Sources {
		if !validExternalHarvesterSources[s] {
			return fmt.Errorf("external_harvester.sources: unknown source %q (valid: wayback, commoncrawl, urlscan, alienvault, virustotal)", s)
		}
	}

	// Validate API keys for sources that require them
	for _, s := range c.Sources {
		if !keyRequiredSources[s] {
			continue
		}
		switch s {
		case "urlscan":
			if c.APIKeys.URLScan == "" {
				return fmt.Errorf("external_harvester: source %q requires api_keys.urlscan to be set", s)
			}
		case "virustotal":
			if c.APIKeys.VirusTotal == "" {
				return fmt.Errorf("external_harvester: source %q requires api_keys.virustotal to be set", s)
			}
		}
	}

	return nil
}
