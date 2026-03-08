package config

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// Builder provides a fluent API for constructing and validating Config instances.
// It accumulates configuration changes and validates them when Build() is called.
type Builder struct {
	config *Config
	errors []error
}

// NewBuilder creates a new Builder initialized with default configuration values.
func NewBuilder() *Builder {
	return &Builder{
		config: NewDefaultConfig(),
		errors: []error{},
	}
}

// WithStartURL sets the target start URL.
// The URL will be validated when Build() is called.
func (b *Builder) WithStartURL(url string) *Builder {
	b.config.Target.StartURL = url
	return b
}

// WithDiscoveryMode sets the discovery mode (files and/or directories).
func (b *Builder) WithDiscoveryMode(mode DiscoveryMode) *Builder {
	b.config.Target.Mode = mode
	return b
}

// WithRecursion configures recursion settings.
// maxDepth must be between 1 and 32767 when enabled is true.
func (b *Builder) WithRecursion(enabled bool, maxDepth int16) *Builder {
	b.config.Target.Recursion.Enabled = enabled
	b.config.Target.Recursion.MaxDepth = maxDepth
	return b
}

// WithThreads sets the number of discovery worker threads.
// discoveryThreads must be between 1 and 255.
func (b *Builder) WithThreads(discoveryThreads int) *Builder {
	b.config.Engine.DiscoveryThreads = discoveryThreads
	return b
}

// WithTimeout sets the HTTP request timeout.
// timeout must be between 1s and 300s.
func (b *Builder) WithTimeout(timeout time.Duration) *Builder {
	b.config.Engine.Timeout = timeout
	return b
}

// WithCaseSensitivity sets the case sensitivity mode for filenames.
func (b *Builder) WithCaseSensitivity(mode CaseSensitivityMode) *Builder {
	b.config.Engine.CaseSensitivity = mode
	return b
}

// WithWordlists sets wordlist file paths. Empty path = disabled.
func (b *Builder) WithWordlists(shortFile, longFile, shortDir, longDir string) *Builder {
	b.config.Filenames.Wordlists.ShortFilePath = shortFile
	b.config.Filenames.Wordlists.LongFilePath = longFile
	b.config.Filenames.Wordlists.ShortDirPath = shortDir
	b.config.Filenames.Wordlists.LongDirPath = longDir
	return b
}

// WithObservedNames enables or disables using observed filenames from spidering.
func (b *Builder) WithObservedNames(enabled bool) *Builder {
	b.config.Filenames.UseObservedNames = enabled
	return b
}

// WithDerivedNames enables or disables using derived filename variations.
func (b *Builder) WithDerivedNames(enabled bool) *Builder {
	b.config.Filenames.EnableNumericFuzzing = enabled
	return b
}

// WithCustomExtensions configures custom extension testing.
// If enabled is true, extensions list must not be empty (validated in Build).
func (b *Builder) WithCustomExtensions(enabled bool, extensions []string) *Builder {
	b.config.Extensions.TestCustom = enabled
	if extensions != nil {
		b.config.Extensions.CustomList = extensions
	}
	return b
}

// WithObservedExtensions configures observed extension testing.
func (b *Builder) WithObservedExtensions(enabled bool) *Builder {
	b.config.Extensions.TestObserved = enabled
	return b
}

// WithVariantExtensions configures variant extension testing (backups, temp files).
// If enabled is true, extensions list must not be empty (validated in Build).
func (b *Builder) WithVariantExtensions(enabled bool, extensions []string) *Builder {
	b.config.Extensions.TestVariants = enabled
	if extensions != nil {
		b.config.Extensions.VariantList = extensions
	}
	return b
}

// WithNoExtension enables or disables testing files without extensions.
func (b *Builder) WithNoExtension(enabled bool) *Builder {
	b.config.Extensions.TestNoExtension = enabled
	return b
}

// Build validates the configuration and returns it if valid.
// Returns an error if any validation fails.
// If multiple validation errors occurred, they are combined into a single error.
func (b *Builder) Build() (*Config, error) {
	// Validate wordlist paths before standard validation
	if err := b.validateWordlistPaths(); err != nil {
		b.errors = append(b.errors, err)
	}

	// Validate the configuration
	if err := b.config.Validate(); err != nil {
		b.errors = append(b.errors, err)
	}

	// If there are any errors, return them
	if len(b.errors) > 0 {
		return nil, b.combineErrors()
	}

	return b.config, nil
}

// validateWordlistPaths validates that provided wordlist file paths exist and are readable.
func (b *Builder) validateWordlistPaths() error {
	wordlists := b.config.Filenames.Wordlists

	checks := []struct {
		path string
		name string
	}{
		{wordlists.ShortFilePath, "short file"},
		{wordlists.LongFilePath, "long file"},
		{wordlists.ShortDirPath, "short directory"},
		{wordlists.LongDirPath, "long directory"},
	}

	var errs []error
	for _, check := range checks {
		if check.path != "" {
			if info, err := os.Stat(check.path); err != nil {
				if os.IsNotExist(err) {
					errs = append(errs, fmt.Errorf("%s wordlist not found: %s", check.name, check.path))
				} else {
					errs = append(errs, fmt.Errorf("%s wordlist error: %w", check.name, err))
				}
			} else if !info.Mode().IsRegular() {
				errs = append(errs, fmt.Errorf("%s wordlist is not a regular file: %s", check.name, check.path))
			}
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// Reset clears any accumulated errors and resets the config to defaults.
// This allows reusing the builder for a fresh configuration.
func (b *Builder) Reset() *Builder {
	b.config = NewDefaultConfig()
	b.errors = []error{}
	return b
}

// combineErrors combines multiple errors into a single error message.
func (b *Builder) combineErrors() error {
	if len(b.errors) == 0 {
		return nil
	}

	if len(b.errors) == 1 {
		return b.errors[0]
	}

	// Combine multiple errors
	var errMsg string
	for i, err := range b.errors {
		if i > 0 {
			errMsg += "; "
		}
		errMsg += err.Error()
	}

	return errors.New(errMsg)
}

// QuickConfig creates a minimal valid configuration with just a URL and default settings.
func QuickConfig(startURL string) (*Config, error) {
	return NewBuilder().
		WithStartURL(startURL).
		Build()
}
