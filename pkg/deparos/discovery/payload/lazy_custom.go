package payload

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"strings"
)

// LazyCustomProvider wraps CachedWordlist with custom name for module wordlists.
// Shares underlying [][]byte data with other providers using same cache entry.
//
// NOT thread-safe. Thread-safety is provided by PayloadDispatcher which serializes
// all calls to Next(). This provider should only be accessed through a dispatcher.
type LazyCustomProvider struct {
	source *CachedWordlist
	index  int
	name   string
}

// NewLazyCustomProvider creates a provider for cached custom wordlist files.
func NewLazyCustomProvider(source *CachedWordlist, name string) *LazyCustomProvider {
	return &LazyCustomProvider{
		source: source,
		index:  0,
		name:   name,
	}
}

// NewLazyCustomProviderFromInline creates a provider from inline words.
// This doesn't use cache since inline words are typically small and unique per module.
func NewLazyCustomProviderFromInline(name string, words []string) *LazyCustomProvider {
	payloads := make([][]byte, 0, len(words))
	for _, w := range words {
		w = strings.TrimSpace(w)
		if w != "" {
			payloads = append(payloads, []byte(w))
		}
	}
	return &LazyCustomProvider{
		source: &CachedWordlist{
			Payloads: payloads,
			FilePath: "",
			ListType: CustomListType,
		},
		index: 0,
		name:  name,
	}
}

// Next returns the next payload or io.EOF when exhausted.
func (p *LazyCustomProvider) Next(ctx context.Context) ([]byte, error) {
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

// Count returns the total number of payloads.
func (p *LazyCustomProvider) Count() int {
	return len(p.source.Payloads)
}

// Name returns a descriptive name for this provider.
func (p *LazyCustomProvider) Name() string {
	return fmt.Sprintf("lazy-custom:%s", p.name)
}

// Close releases any resources held by the provider.
// Data is owned by cache (or inline), so nothing to release here.
func (p *LazyCustomProvider) Close() error {
	return nil
}

// HashContent returns a hash of the provider's configuration.
func (p *LazyCustomProvider) HashContent() uint64 {
	h := fnv.New64a()
	h.Write([]byte(p.name))

	// For file-based: hash the file path
	if p.source.FilePath != "" {
		h.Write([]byte{0})
		h.Write([]byte(p.source.FilePath))
	} else {
		// For inline: hash the content
		for _, payload := range p.source.Payloads {
			h.Write([]byte{0})
			h.Write(payload)
		}
	}
	return h.Sum64()
}
