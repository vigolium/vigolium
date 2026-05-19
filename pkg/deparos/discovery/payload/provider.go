package payload

import (
	"context"
)

// Provider generates payloads for content discovery tasks.
// Each implementation provides a different source of filenames/directories to test.
//
// Providers are single-use: each task creates a new provider instance.
// Once exhausted (Next returns io.EOF), the provider is discarded.
type Provider interface {
	// Next returns the next payload to test, or io.EOF if exhausted.
	Next(ctx context.Context) ([]byte, error)

	// Count returns the total number of payloads (0 if unknown).
	Count() int

	// Name returns a descriptive name for this provider (for logging/debugging).
	Name() string

	// Close releases any resources held by the provider.
	Close() error

	// HashContent returns a FNV-1a 64-bit hash of the provider's content/configuration.
	// Used for task deduplication - providers with same content should return same hash.
	HashContent() uint64
}

// ProviderType identifies the payload source.
type ProviderType int

const (
	TypeObserved  ProviderType = iota // Filenames discovered during spidering
	TypeCustom                        // User-provided wordlist file
	TypeBuiltIn                       // Embedded short/long wordlist
	TypeExtension                     // Extension variants (.bak, .old, etc.)
)
