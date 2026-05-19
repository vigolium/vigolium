package payload

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"
)

// LazyBuiltInProvider wraps CachedWordlist with its own iterator state.
// Shares underlying [][]byte data with other providers using same cache entry.
//
// NOT thread-safe. Thread-safety is provided by PayloadDispatcher which serializes
// all calls to Next(). This provider should only be accessed through a dispatcher.
type LazyBuiltInProvider struct {
	source        *CachedWordlist
	index         int
	listType      BuiltInListType
	caseSensitive bool
}

// NewLazyBuiltInProvider creates a provider that shares data from a cached wordlist.
// Each provider has its own iterator state (index) but shares the underlying data.
func NewLazyBuiltInProvider(source *CachedWordlist, listType BuiltInListType, caseSensitive bool) *LazyBuiltInProvider {
	return &LazyBuiltInProvider{
		source:        source,
		index:         0,
		listType:      listType,
		caseSensitive: caseSensitive,
	}
}

// Next returns the next payload from the wordlist or io.EOF when exhausted.
func (p *LazyBuiltInProvider) Next(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if p.index >= len(p.source.Payloads) {
		return nil, io.EOF
	}

	payload := p.source.Payloads[p.index]
	p.index++
	return payload, nil
}

// Count returns the total number of payloads in the wordlist.
func (p *LazyBuiltInProvider) Count() int {
	return len(p.source.Payloads)
}

// Name returns a descriptive name for this provider.
func (p *LazyBuiltInProvider) Name() string {
	return fmt.Sprintf("lazy-builtin:%s", p.listType)
}

// Close releases any resources held by the provider.
// Data is owned by cache, so nothing to release here.
func (p *LazyBuiltInProvider) Close() error {
	return nil
}

// HashContent returns a FNV-1a 64-bit hash of the provider's configuration.
// Hashes the file path, list type, and case sensitivity for stable deduplication.
func (p *LazyBuiltInProvider) HashContent() uint64 {
	h := fnv.New64a()
	h.Write([]byte(p.source.FilePath))
	h.Write([]byte{0}) // Separator
	h.Write([]byte{uint8(p.listType)})
	h.Write([]byte{0}) // Separator
	if p.caseSensitive {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	return h.Sum64()
}
