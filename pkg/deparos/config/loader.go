package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ModuleConfigFile represents a YAML file with custom module definitions.
// This allows users to define custom modules without recompiling.
//
// Example YAML:
//
//	modules:
//	  built_in: [wildcard]
//	  disabled: []
//	  custom:
//	    - name: skip-node-modules
//	      description: Skip node_modules directories
//	      enabled: true
//	      priority: 10
//	      patterns:
//	        - type: contains
//	          value: node_modules
//	      actions:
//	        stop_recursion: true
//	        block_task_patterns:
//	          - ".*node_modules.*"
type ModuleConfigFile struct {
	Modules ModuleConfig `yaml:"modules"`
}

// LoadModuleConfig loads module configuration from a YAML file.
func LoadModuleConfig(path string) (*ModuleConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read module config file: %w", err)
	}

	var configFile ModuleConfigFile
	if err := yaml.Unmarshal(data, &configFile); err != nil {
		return nil, fmt.Errorf("parse module config YAML: %w", err)
	}

	return &configFile.Modules, nil
}

// MergeModuleConfig merges a loaded config into the base config.
// The loaded config takes precedence for overlapping settings.
// Note: Enabled flag is NOT merged - it's controlled by CLI/config.yaml only.
func MergeModuleConfig(base *ModuleConfig, loaded *ModuleConfig) {
	if loaded == nil {
		return
	}

	// Merge built-in modules (loaded takes precedence if non-empty)
	if len(loaded.BuiltIn) > 0 {
		base.BuiltIn = loaded.BuiltIn
	}

	// Merge disabled modules (append)
	if len(loaded.Disabled) > 0 {
		base.Disabled = append(base.Disabled, loaded.Disabled...)
	}

	// Append custom modules
	if len(loaded.Custom) > 0 {
		base.Custom = append(base.Custom, loaded.Custom...)
	}
}

// ConfigFileWithModules represents config.yaml with inline module definitions.
type ConfigFileWithModules struct {
	ModuleDefinitions ModuleConfig `yaml:"module-definitions"`
}

// LoadInlineModuleDefinitions loads module definitions embedded in config.yaml.
// Returns nil if config file doesn't exist or has no module definitions.
func LoadInlineModuleDefinitions(configPath string) (*ModuleConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Config file does not exist = no definitions
		}
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg ConfigFileWithModules
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config YAML: %w", err)
	}

	// Return nil if there are no definitions
	if len(cfg.ModuleDefinitions.Custom) == 0 &&
		len(cfg.ModuleDefinitions.BuiltIn) == 0 {
		return nil, nil
	}

	return &cfg.ModuleDefinitions, nil
}

// ValidateModuleConfig validates the module configuration.
func ValidateModuleConfig(cfg *ModuleConfig) error {
	for i, custom := range cfg.Custom {
		if custom.Name == "" {
			return fmt.Errorf("custom module %d: name is required", i)
		}
		if len(custom.Patterns) == 0 {
			return fmt.Errorf("custom module %q: at least one pattern is required", custom.Name)
		}
		for j, p := range custom.Patterns {
			if p.Type == "" {
				return fmt.Errorf("custom module %q pattern %d: type is required", custom.Name, j)
			}
			if p.Value == "" {
				return fmt.Errorf("custom module %q pattern %d: value is required", custom.Name, j)
			}
			// Validate pattern type (13 semantic types)
			validTypes := map[string]bool{
				// Path-level patterns
				"path_contains": true, "path_prefix": true, "path_suffix": true,
				"path_exact": true, "path_regex": true,
				// Segment-level patterns
				"segment_exact": true, "segment_contains": true,
				"segment_prefix": true, "segment_suffix": true, "segment_regex": true,
				// File-level patterns
				"file_extension": true, "file_name": true, "file_glob": true,
			}
			if !validTypes[p.Type] {
				return fmt.Errorf("custom module %q pattern %d: invalid type %q (valid types: path_contains, path_prefix, path_suffix, path_exact, path_regex, segment_exact, segment_contains, segment_prefix, segment_suffix, segment_regex, file_extension, file_name, file_glob)", custom.Name, j, p.Type)
			}
		}
	}
	return nil
}
