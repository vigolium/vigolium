package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Settings holds all configuration settings
type Settings struct {
	Server             ServerConfig             `yaml:"server"`
	Database           DatabaseConfig           `yaml:"database"`
	Notify             NotifyConfig             `yaml:"notify"`
	DynamicAssessment  DynamicAssessmentConfig  `yaml:"dynamic-assessment"`
	MutationStrategy   MutationStrategyConfig   `yaml:"mutation_strategy"`
	Scope              ScopeConfig              `yaml:"scope"`
	SourceAware      SourceAwareConfig      `yaml:"source_aware"`
	Discovery        DiscoveryConfig        `yaml:"discovery"`
	KnownIssueScan   KnownIssueScanConfig   `yaml:"known_issue_scan"`
	ExternalHarvester  ExternalHarvesterConfig  `yaml:"external_harvester"`
	ScanningStrategy   ScanningStrategyConfig   `yaml:"scanning_strategy"`
	ScanningPace       ScanningPaceConfig       `yaml:"scanning_pace"`
	Spidering          SpideringConfig          `yaml:"spidering"`
	Agent              AgentConfig              `yaml:"agent"`
	OAST               OASTConfig               `yaml:"oast"`
}

// ProfileSettings is the subset of Settings that a scanning profile can override.
// Only non-nil pointer fields are applied; nil fields leave the main config unchanged.
type ProfileSettings struct {
	ScanningStrategy  *ScanningStrategyConfig  `yaml:"scanning_strategy,omitempty"`
	ScanningPace      *ScanningPaceConfig      `yaml:"scanning_pace,omitempty"`
	Discovery         *DiscoveryConfig         `yaml:"discovery,omitempty"`
	Spidering         *SpideringConfig         `yaml:"spidering,omitempty"`
	KnownIssueScan    *KnownIssueScanConfig    `yaml:"known_issue_scan,omitempty"`
	DynamicAssessment *DynamicAssessmentConfig `yaml:"dynamic-assessment,omitempty"`
	ExternalHarvester *ExternalHarvesterConfig `yaml:"external_harvester,omitempty"`
	MutationStrategy  *MutationStrategyConfig  `yaml:"mutation_strategy,omitempty"`
	Scope             *ScopeConfig             `yaml:"scope,omitempty"`
}

// LoadProfile reads and parses a scanning profile YAML file.
func LoadProfile(path string) (*ProfileSettings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile file %s: %w", path, err)
	}

	content := ExpandEnvVars(string(data))

	var profile ProfileSettings
	if err := yaml.Unmarshal([]byte(content), &profile); err != nil {
		return nil, fmt.Errorf("failed to parse profile file %s: %w", path, err)
	}

	return &profile, nil
}

// ApplyProfile overlays non-nil profile sections onto settings.
// It marshals each non-nil profile section to YAML, then unmarshals it onto the
// corresponding settings section. This preserves the "zero-values don't override"
// behavior already used by the config system.
func ApplyProfile(settings *Settings, profile *ProfileSettings) error {
	type overlay struct {
		src  any
		dest any
	}

	overlays := []overlay{}
	if profile.ScanningStrategy != nil {
		overlays = append(overlays, overlay{profile.ScanningStrategy, &settings.ScanningStrategy})
	}
	if profile.ScanningPace != nil {
		overlays = append(overlays, overlay{profile.ScanningPace, &settings.ScanningPace})
	}
	if profile.Discovery != nil {
		overlays = append(overlays, overlay{profile.Discovery, &settings.Discovery})
	}
	if profile.Spidering != nil {
		overlays = append(overlays, overlay{profile.Spidering, &settings.Spidering})
	}
	if profile.KnownIssueScan != nil {
		overlays = append(overlays, overlay{profile.KnownIssueScan, &settings.KnownIssueScan})
	}
	if profile.DynamicAssessment != nil {
		overlays = append(overlays, overlay{profile.DynamicAssessment, &settings.DynamicAssessment})
	}
	if profile.ExternalHarvester != nil {
		overlays = append(overlays, overlay{profile.ExternalHarvester, &settings.ExternalHarvester})
	}
	if profile.MutationStrategy != nil {
		overlays = append(overlays, overlay{profile.MutationStrategy, &settings.MutationStrategy})
	}
	if profile.Scope != nil {
		overlays = append(overlays, overlay{profile.Scope, &settings.Scope})
	}

	for _, o := range overlays {
		data, err := yaml.Marshal(o.src)
		if err != nil {
			return fmt.Errorf("failed to marshal profile section: %w", err)
		}
		if err := yaml.Unmarshal(data, o.dest); err != nil {
			return fmt.Errorf("failed to apply profile section: %w", err)
		}
	}

	return nil
}

// LoadSettings loads configuration from YAML file
// Search paths (in order):
//  1. --config flag path (if specified)
//  2. $HOME/.vigolium/vigolium-configs.yaml
//  3. ./vigolium-configs.yaml
func LoadSettings(configPath string) (*Settings, error) {
	var path string

	// If config path is explicitly provided, use it
	if configPath != "" {
		path = ExpandPath(configPath)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil, fmt.Errorf("config file not found: %s", path)
		}
	} else {
		// Try default locations
		paths := []string{
			ExpandPath("~/.vigolium/vigolium-configs.yaml"),
			"./vigolium-configs.yaml",
		}

		found := false
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				path = p
				found = true
				break
			}
		}

		// If no config file found, return default settings
		if !found {
			return DefaultSettings(), nil
		}
	}

	// Read config file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables in YAML content
	content := ExpandEnvVars(string(data))

	// Parse YAML on top of defaults so unspecified sections keep sensible values
	settings := *DefaultSettings()
	if err := yaml.Unmarshal([]byte(content), &settings); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &settings, nil
}

// DefaultSettings returns default configuration
func DefaultSettings() *Settings {
	return &Settings{
		Server:            *DefaultServerConfig(),
		Database:          *DefaultDatabaseConfig(),
		Notify:            *DefaultNotifyConfig(),
		DynamicAssessment: *DefaultDynamicAssessmentConfig(),
		MutationStrategy:  *DefaultMutationStrategyConfig(),
		Scope:             *DefaultScopeConfig(),
		SourceAware:      *DefaultSourceAwareConfig(),
		Discovery:        *DefaultDiscoveryConfig(),
		KnownIssueScan:   *DefaultKnownIssueScanConfig(),
		ExternalHarvester: *DefaultExternalHarvesterConfig(),
		ScanningStrategy:  *DefaultScanningStrategyConfig(),
		ScanningPace:      *DefaultScanningPaceConfig(),
		Spidering:         *DefaultSpideringConfig(),
		Agent:             *DefaultAgentConfig(),
		OAST:              *DefaultOASTConfig(),
	}
}

// ExpandPath handles ~ expansion and environment variables
func ExpandPath(path string) string {
	// Expand environment variables
	path = ExpandEnvVars(path)

	// Expand ~ to home directory
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		path = filepath.Join(home, path[2:])
	}

	return path
}

// ContractPath replaces the user's home directory prefix with ~ — the inverse of ExpandPath.
func ContractPath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if strings.HasPrefix(path, home) {
		return "~" + path[len(home):]
	}
	return path
}

// ExpandEnvVars replaces environment variable references in s.
//
// Supported syntax (follows bash/Docker Compose conventions):
//
//	${VAR}            — value of VAR; empty string if unset
//	${VAR:-default}   — value of VAR if set and non-empty, otherwise "default"
//	$VAR              — same as ${VAR} (no default support)
func ExpandEnvVars(s string) string {
	return os.Expand(s, func(key string) string {
		if name, defaultVal, ok := parseDefault(key); ok {
			if v := os.Getenv(name); v != "" {
				return v
			}
			return defaultVal
		}
		return os.Getenv(key)
	})
}

// parseDefault splits "VAR:-default" into ("VAR", "default", true).
// Returns ("", "", false) if the separator is not present.
func parseDefault(key string) (name, defaultVal string, ok bool) {
	idx := strings.Index(key, ":-")
	if idx < 0 {
		return "", "", false
	}
	return key[:idx], key[idx+2:], true
}

// ProjectConfigDir returns the directory for a project's config files.
// Layout: ~/.vigolium/projects/<uuid>/
func ProjectConfigDir(projectUUID string) string {
	return ExpandPath("~/.vigolium/projects/" + projectUUID)
}

// ProjectConfigPath returns the path to a project's config overlay file.
func ProjectConfigPath(projectUUID string) string {
	return filepath.Join(ProjectConfigDir(projectUUID), "config.yaml")
}

// LoadProjectConfig loads the project-specific config overlay if it exists.
// Returns nil (no error) if the file doesn't exist.
func LoadProjectConfig(projectUUID string) (*ProfileSettings, error) {
	profile, err := LoadProfile(ProjectConfigPath(projectUUID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return profile, nil
}

// LoadSettingsWithProject loads global settings, then overlays project-specific
// config on top. This implements the merge strategy: global → project → CLI flags.
// CLI flag overrides happen after this function returns.
func LoadSettingsWithProject(configPath string, projectUUID string) (*Settings, error) {
	settings, err := LoadSettings(configPath)
	if err != nil {
		return nil, err
	}

	if projectUUID == "" {
		return settings, nil
	}

	profile, err := LoadProjectConfig(projectUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to load project config for %s: %w", projectUUID, err)
	}
	if profile == nil {
		return settings, nil
	}

	if err := ApplyProfile(settings, profile); err != nil {
		return nil, fmt.Errorf("failed to apply project config: %w", err)
	}

	return settings, nil
}

// SaveProjectConfig writes a project config overlay to its config directory.
func SaveProjectConfig(projectUUID string, profile *ProfileSettings) error {
	dir := ProjectConfigDir(projectUUID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create project config directory: %w", err)
	}

	data, err := yaml.Marshal(profile)
	if err != nil {
		return fmt.Errorf("failed to marshal project config: %w", err)
	}

	path := ProjectConfigPath(projectUUID)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write project config: %w", err)
	}

	return nil
}

// ConfigFilePath returns the resolved path to the config file.
// It searches the same locations as LoadSettings but only returns the path.
// If no config file exists, returns the default path.
func ConfigFilePath() string {
	paths := []string{
		ExpandPath("~/.vigolium/vigolium-configs.yaml"),
		"./vigolium-configs.yaml",
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ExpandPath("~/.vigolium/vigolium-configs.yaml")
}

// SaveSettings writes settings to YAML file
func SaveSettings(path string, settings *Settings) error {
	path = ExpandPath(path)

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	// Write to file
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
