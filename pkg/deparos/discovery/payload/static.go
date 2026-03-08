package payload

import (
	"bytes"
	"context"
	"hash/fnv"
	"io"
	"sort"
)

// StaticProvider provides a fixed list of payloads without iteration state management.
// Used for dynamic task generation where we need to provide specific values
// (e.g., a single newly discovered extension) rather than iterating through a growing list.
//
// NOT thread-safe. Thread-safety is provided by PayloadDispatcher which serializes
// all calls to Next(). This provider should only be accessed through a dispatcher.
type StaticProvider struct {
	payloads [][]byte
	index    int
}

// NewStaticProvider creates a provider with a fixed list of payloads.
// The payloads are provided at construction time and never change.
//
// Example usage:
//
//	// Create provider for single extension "inc"
//	provider := NewStaticProvider([][]byte{[]byte("inc")})
func NewStaticProvider(payloads [][]byte) *StaticProvider {
	return &StaticProvider{
		payloads: payloads,
		index:    0,
	}
}

// NewStaticListProvider creates a StaticProvider from a list of strings.
// Convenience wrapper for common case of string lists.
func NewStaticListProvider(items []string) (*StaticProvider, error) {
	payloads := make([][]byte, len(items))
	for i, item := range items {
		payloads[i] = []byte(item)
	}
	return NewStaticProvider(payloads), nil
}

// Next returns the next payload from the static list.
// Returns io.EOF when all payloads have been consumed.
func (sp *StaticProvider) Next(ctx context.Context) ([]byte, error) {
	if sp.index >= len(sp.payloads) {
		return nil, io.EOF
	}

	payload := sp.payloads[sp.index]
	sp.index++
	return payload, nil
}

// Count returns the total number of payloads in this provider.
// Implements Provider interface.
func (sp *StaticProvider) Count() int {
	return len(sp.payloads)
}

// Name returns a descriptive name for this provider.
// Implements Provider interface.
func (sp *StaticProvider) Name() string {
	return "static"
}

// Close releases any resources held by this provider.
// StaticProvider has no resources to release, but implements Provider interface.
func (sp *StaticProvider) Close() error {
	return nil
}

// HashContent returns a FNV-1a 64-bit hash of the provider's payload content.
// Hashes the sorted payloads for deterministic deduplication.
func (sp *StaticProvider) HashContent() uint64 {
	sorted := make([][]byte, len(sp.payloads))
	copy(sorted, sp.payloads)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i], sorted[j]) < 0
	})

	h := fnv.New64a()
	for _, payload := range sorted {
		h.Write(payload)
		h.Write([]byte{0})
	}

	return h.Sum64()
}
