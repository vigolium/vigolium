package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"gopkg.in/yaml.v3"
)

// Settings holds all configuration settings
type Settings struct {
	Server            ServerConfig            `yaml:"server"`
	Database          DatabaseConfig          `yaml:"database"`
	Notify            NotifyConfig            `yaml:"notify"`
	DynamicAssessment DynamicAssessmentConfig `yaml:"dynamic-assessment"`
	MutationStrategy  MutationStrategyConfig  `yaml:"mutation_strategy"`
	Scope             ScopeConfig             `yaml:"scope"`
	Discovery         DiscoveryConfig         `yaml:"discovery"`
	KnownIssueScan    KnownIssueScanConfig    `yaml:"known_issue_scan"`
	ExternalHarvester ExternalHarvesterConfig `yaml:"external_harvester"`
	ScanningStrategy  ScanningStrategyConfig  `yaml:"scanning_strategy"`
	ScanningPace      ScanningPaceConfig      `yaml:"scanning_pace"`
	Spidering         SpideringConfig         `yaml:"spidering"`
	Agent             AgentConfig             `yaml:"agent"`
	OAST              OASTConfig              `yaml:"oast"`
	Storage           StorageConfig           `yaml:"storage"`
}

// ProfileScanningStrategy is the subset of ScanningStrategyConfig that a
// profile is permitted to override. It deliberately excludes the per-strategy
// phase tables (Lite/Balanced/Deep), session, and scan_logs — those are
// global-config concerns, and exposing them here would let a profile silently
// zero-clobber strategy phase definitions during the YAML round-trip used by
// ApplyProfile (every field without omitempty round-trips as its zero value).
//
// A profile selects WHICH strategy applies (DefaultStrategy) and tunes the
// heuristics check; it does not redefine WHAT each strategy means.
type ProfileScanningStrategy struct {
	DefaultStrategy string `yaml:"default_strategy,omitempty"`
	HeuristicsCheck string `yaml:"heuristics_check,omitempty"`
}

// ProfileSettings is the subset of Settings that a scanning profile can override.
// Only non-nil pointer fields are applied; nil fields leave the main config unchanged.
type ProfileSettings struct {
	ScanningStrategy  *ProfileScanningStrategy `yaml:"scanning_strategy,omitempty"`
	ScanningPace      *ScanningPaceConfig      `yaml:"scanning_pace,omitempty"`
	Discovery         *DiscoveryConfig         `yaml:"discovery,omitempty"`
	Spidering         *SpideringConfig         `yaml:"spidering,omitempty"`
	KnownIssueScan    *KnownIssueScanConfig    `yaml:"known_issue_scan,omitempty"`
	DynamicAssessment *DynamicAssessmentConfig `yaml:"dynamic-assessment,omitempty"`
	ExternalHarvester *ExternalHarvesterConfig `yaml:"external_harvester,omitempty"`
	MutationStrategy  *MutationStrategyConfig  `yaml:"mutation_strategy,omitempty"`
	Scope             *ScopeConfig             `yaml:"scope,omitempty"`
	Notify            *NotifyConfig            `yaml:"notify,omitempty"`
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
//
// Most sections are overlaid via a YAML round-trip (marshal the profile section,
// unmarshal onto the settings section). The ScanningStrategy section is handled
// specially via ProfileScanningStrategy: its fields are merged explicitly so that
// the per-strategy phase tables (Lite/Balanced/Deep) defined in the global config
// are never clobbered by a profile that only meant to set default_strategy.
func ApplyProfile(settings *Settings, profile *ProfileSettings) error {
	if profile.ScanningStrategy != nil {
		if v := profile.ScanningStrategy.DefaultStrategy; v != "" {
			settings.ScanningStrategy.DefaultStrategy = v
		}
		if v := profile.ScanningStrategy.HeuristicsCheck; v != "" {
			settings.ScanningStrategy.HeuristicsCheck = v
		}
	}

	type overlay struct {
		src  any
		dest any
	}

	overlays := []overlay{}
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
	if profile.Notify != nil {
		overlays = append(overlays, overlay{profile.Notify, &settings.Notify})
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

	// Install the configured global User-Agent so every scan phase that resolves
	// httpmsg.DefaultUserAgent() at request time picks it up. Empty is a no-op,
	// preserving the built-in Chrome default.
	httpmsg.SetDefaultUserAgent(settings.ScanningStrategy.HTTP.UserAgent)

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
		Discovery:         *DefaultDiscoveryConfig(),
		KnownIssueScan:    *DefaultKnownIssueScanConfig(),
		ExternalHarvester: *DefaultExternalHarvesterConfig(),
		ScanningStrategy:  *DefaultScanningStrategyConfig(),
		ScanningPace:      *DefaultScanningPaceConfig(),
		Spidering:         *DefaultSpideringConfig(),
		Agent:             *DefaultAgentConfig(),
		OAST:              *DefaultOASTConfig(),
		Storage:           *DefaultStorageConfig(),
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

// ActiveProjectFilePath returns the path to the file that records the
// shell-independent active project (used as a fallback when no flag/env var
// is set). Layout: ~/.vigolium/active-project
func ActiveProjectFilePath() string {
	return ExpandPath("~/.vigolium/active-project")
}

// ReadActiveProject returns the persisted active project UUID, or "" if the
// file does not exist or is empty. Read errors other than not-exist surface
// to the caller.
func ReadActiveProject() (string, error) {
	data, err := os.ReadFile(ActiveProjectFilePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// WriteActiveProject persists the active project UUID to disk so that future
// shells/commands resolve to it without needing VIGOLIUM_PROJECT_UUID.
func WriteActiveProject(projectUUID string) error {
	path := ActiveProjectFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create vigolium config dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(projectUUID+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write active project file: %w", err)
	}
	return nil
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
