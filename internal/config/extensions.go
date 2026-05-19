package config

import (
	"fmt"
	"os"
	"time"
)

// ExtensionsConfig holds configuration for JavaScript extensions.
type ExtensionsConfig struct {
	Enabled      bool              `yaml:"enabled"`
	ExtensionDir string            `yaml:"extension_dir"`
	CustomDir    []string          `yaml:"custom_dir"`
	Variables    map[string]string `yaml:"variables"`
	Limits       ScriptLimits      `yaml:"limits"`
	AllowExec    bool              `yaml:"allow_exec"`  // enables exec() and setEnv(); default false
	SandboxDir   string            `yaml:"sandbox_dir"` // base path for file ops; empty = cwd
}

// ExecTimeout returns the max seconds for exec(), default 30, cap 120.
func (c *ExtensionsConfig) ExecTimeout() int {
	if c.Limits.Timeout == "" {
		return 30
	}
	d, err := time.ParseDuration(c.Limits.Timeout)
	if err != nil {
		return 30
	}
	secs := int(d.Seconds())
	if secs <= 0 {
		return 30
	}
	if secs > 120 {
		return 120
	}
	return secs
}

// ScriptLimits defines resource constraints for JS execution.
type ScriptLimits struct {
	Timeout     string `yaml:"timeout"`
	MaxMemoryMB int    `yaml:"max_memory_mb"`
}

// DefaultExtensionsConfig returns default (disabled) configuration.
func DefaultExtensionsConfig() *ExtensionsConfig {
	return &ExtensionsConfig{
		Enabled:      false,
		ExtensionDir: "~/.vigolium/extensions/",
		Limits: ScriptLimits{
			Timeout:     "30s",
			MaxMemoryMB: 128,
		},
	}
}

// TimeoutDuration returns the parsed timeout duration for script execution.
func (l *ScriptLimits) TimeoutDuration() time.Duration {
	if l.Timeout == "" {
		return 30 * time.Second
	}
	d, err := time.ParseDuration(l.Timeout)
	if err != nil {
		return 30 * time.Second
	}
	return d
}

// Validate checks configuration validity.
func (c *ExtensionsConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	// Validate extension_dir if set
	if c.ExtensionDir != "" {
		dir := ExpandPath(c.ExtensionDir)
		if info, err := os.Stat(dir); err == nil {
			if !info.IsDir() {
				return fmt.Errorf("extensions.extension_dir %q is not a directory", c.ExtensionDir)
			}
		}
		// It's fine if the directory doesn't exist yet; it will just yield no scripts
	}

	// Validate explicit script paths
	for i, script := range c.CustomDir {
		path := ExpandPath(script)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("extensions.custom_dir[%d]: file not found: %s", i, script)
		}
	}

	// Validate limits
	if c.Limits.Timeout != "" {
		if _, err := time.ParseDuration(c.Limits.Timeout); err != nil {
			return fmt.Errorf("extensions.limits.timeout: invalid duration %q: %w", c.Limits.Timeout, err)
		}
	}

	if c.Limits.MaxMemoryMB < 0 {
		return fmt.Errorf("extensions.limits.max_memory_mb must be >= 0")
	}

	return nil
}
