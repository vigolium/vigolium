package harvester

import "context"

// Result represents a single URL discovered by a harvester source.
type Result struct {
	Source string
	URL    string
	Error  error
}

// Source is the interface that all harvester sources must implement.
type Source interface {
	// Run starts the source and returns a channel of results.
	// The channel is closed when the source has finished.
	Run(ctx context.Context, domain string) <-chan Result

	// Name returns the source identifier.
	Name() string

	// NeedsKey returns true if the source requires an API key.
	NeedsKey() bool
}
