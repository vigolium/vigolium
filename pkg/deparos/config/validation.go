package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"
)

// Common validation errors.
var (
	ErrEmptyURL              = errors.New("start URL is required")
	ErrInvalidURL            = errors.New("invalid URL format")
	ErrInvalidURLScheme      = errors.New("URL must use http or https scheme")
	ErrMissingHost           = errors.New("URL must have a host")
	ErrInvalidDepth          = errors.New("max depth must be between 1 and 32767")
	ErrInvalidThreads        = errors.New("invalid thread count")
	ErrEmptyCustomList       = errors.New("custom extensions enabled but list is empty")
	ErrEmptyBackupExtensions = errors.New("backup extensions enabled but list is empty")
	ErrFileNotFound          = errors.New("file not found")
	ErrNotRegularFile        = errors.New("path is not a regular file")
	ErrFileNotReadable       = errors.New("file is not readable")
	ErrInvalidTimeout        = errors.New("timeout must be between 1s and 300s")
)

// Validate validates the entire configuration.
func (c *Config) Validate() error {
	if err := c.Target.Validate(); err != nil {
		return fmt.Errorf("target config: %w", err)
	}

	if err := c.Filenames.Validate(); err != nil {
		return fmt.Errorf("filename config: %w", err)
	}

	if err := c.Extensions.Validate(); err != nil {
		return fmt.Errorf("extension config: %w", err)
	}

	if err := c.Engine.Validate(); err != nil {
		return fmt.Errorf("engine config: %w", err)
	}
	if err := c.JSTangle.Validate(); err != nil {
		return fmt.Errorf("jstangle config: %w", err)
	}

	return nil
}

func (c *JSTangleConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	switch c.ReplayMode {
	case "", "exact", "conservative", "off":
	default:
		return fmt.Errorf("replay_mode must be exact, conservative, or off")
	}
	switch c.ReplaySafety {
	case "", "metadata-only", "read-only", "safe-baseline", "state-changing":
	default:
		return fmt.Errorf("replay_safety must be metadata-only, read-only, safe-baseline, or state-changing")
	}
	if c.WorkerCount < 0 || c.WorkerCount > 16 || c.MemoryBudgetMB < 128 || c.CacheMB < 0 {
		return fmt.Errorf("invalid worker_count/memory_budget_mb/cache_mb")
	}
	if c.JobTimeout < time.Second || c.JobTimeout > 5*time.Minute {
		return fmt.Errorf("job_timeout must be 1s-5m")
	}
	if c.NormalInputMB < 1 || c.MaxASTInputMB < c.NormalInputMB || c.HardInputMB < c.MaxASTInputMB {
		return fmt.Errorf("input limits must satisfy 1 <= normal_input_mb <= max_ast_input_mb <= hard_input_mb")
	}
	if c.MaxRequestsPerFile < 1 || c.MaxASTNodes < 1_000 || c.MaxASTNodes > 5_000_000 ||
		c.MaxAssetDepth < 1 || c.MaxAssetsPerParent < 1 || c.MaxAssetsPerHost < 1 || c.MaxAssetsTotal < 1 {
		return fmt.Errorf("request/asset limits must be positive and max_ast_nodes must be 1000-5000000")
	}
	return nil
}

// Validate validates target configuration.
func (t *TargetConfig) Validate() error {
	// 1. Start URL is required
	if t.StartURL == "" {
		return ErrEmptyURL
	}

	// 2. Parse URL
	u, err := url.Parse(t.StartURL)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidURL, err)
	}

	// 3. Must be HTTP or HTTPS
	if u.Scheme != "http" && u.Scheme != "https" {
		return ErrInvalidURLScheme
	}

	// 4. Must have a host
	if u.Host == "" {
		return ErrMissingHost
	}

	// 5. Validate recursion config
	if err := t.Recursion.Validate(); err != nil {
		return err
	}

	return nil
}

// Validate validates recursion configuration.
func (r *RecursionConfig) Validate() error {
	// Only validate depth if recursion is enabled
	if r.Enabled {
		// Valid range: 1-32767 (int16 max positive value)
		if r.MaxDepth < 1 {
			return fmt.Errorf("%w: got %d", ErrInvalidDepth, r.MaxDepth)
		}
	}
	return nil
}

// Validate validates filename configuration.
func (f *FilenameConfig) Validate() error {
	// Wordlist path validation is now handled in builder.go's validateWordlistPaths()
	// No additional validation needed here
	return nil
}

// Validate validates extension configuration.
func (e *ExtensionConfig) Validate() error {
	// If custom extensions testing is enabled, the list must not be empty
	if e.TestCustom && len(e.CustomList) == 0 {
		return ErrEmptyCustomList
	}

	// If backup extensions testing is enabled, the list must not be empty
	if e.TestBackupExtensions && len(e.BackupExtensions) == 0 {
		return ErrEmptyBackupExtensions
	}

	return nil
}

// Validate validates engine configuration.
func (e *EngineConfig) Validate() error {
	// Discovery threads: 1-255 (uint8 max)
	if e.DiscoveryThreads < 1 || e.DiscoveryThreads > 255 {
		return fmt.Errorf("%w: discovery threads must be 1-255, got %d", ErrInvalidThreads, e.DiscoveryThreads)
	}

	// Timeout: 1s-300s (reasonable range)
	if e.Timeout < 1*time.Second || e.Timeout > 300*time.Second {
		return fmt.Errorf("%w: got %v", ErrInvalidTimeout, e.Timeout)
	}

	return nil
}

// validateFilePath validates that a file path exists, is a regular file, and is readable.
func validateFilePath(path string) error {
	// 1. Check if file exists
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", ErrFileNotFound, path)
		}
		return fmt.Errorf("stat file: %w", err)
	}

	// 2. Check if it's a regular file (not a directory or special file)
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", ErrNotRegularFile, path)
	}

	// 3. Check if file is readable
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrFileNotReadable, path)
	}
	_ = file.Close()

	return nil
}
