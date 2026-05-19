package payload

import (
	"context"
	"hash/fnv"
	"io"
)

// LazyObservedProvider wraps an ObservedProvider and takes a snapshot lazily
// when iteration starts. This allows tasks to see the latest observed names
// at execution time rather than at task creation time.
//
// Memory efficient: only creates the snapshot when actually needed.
// Thread-safe: safe to create from any goroutine, snapshot is taken under lock.
type LazyObservedProvider struct {
	source *ObservedProvider

	// Snapshot taken on first Next() call
	items [][]byte
	index int

	// Track if snapshot was taken
	initialized bool
}

// NewLazyObservedProvider creates a provider that will snapshot the source
// ObservedProvider when iteration begins.
func NewLazyObservedProvider(source *ObservedProvider) *LazyObservedProvider {
	return &LazyObservedProvider{
		source:      source,
		initialized: false,
	}
}

// initialize takes a snapshot of the source provider.
// Called once on first Next() call.
func (p *LazyObservedProvider) initialize() {
	if p.initialized {
		return
	}

	// Use public SnapshotBytes which handles locking and rebuilding
	p.items = p.source.SnapshotBytes()
	p.index = 0
	p.initialized = true
}

// Next returns the next observed filename or io.EOF when exhausted.
func (p *LazyObservedProvider) Next(ctx context.Context) ([]byte, error) {
	// Take snapshot on first call
	if !p.initialized {
		p.initialize()
	}

	if p.index >= len(p.items) {
		return nil, io.EOF
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	item := p.items[p.index]
	p.index++
	return item, nil
}

// Count returns the current count from source (may change until initialized).
func (p *LazyObservedProvider) Count() int {
	if p.initialized {
		return len(p.items)
	}
	return p.source.Count()
}

// Name returns the provider name.
func (p *LazyObservedProvider) Name() string {
	return "lazy-observed"
}

// Close releases resources.
func (p *LazyObservedProvider) Close() error {
	p.items = nil
	return nil
}

// HashContent returns a constant hash for this provider type.
//
// IMPORTANT: Do NOT include source pointer in the hash. Only one ObservedProvider
// is used per target, and the task already uses directory URL as part of its
// deduplication key.
func (p *LazyObservedProvider) HashContent() uint64 {
	h := fnv.New64a()
	h.Write([]byte("lazy-observed"))
	h.Write([]byte{0})
	return h.Sum64()
}

// Clone creates a new LazyObservedProvider pointing to the same source.
// The new provider has its own iterator state.
func (p *LazyObservedProvider) Clone() *LazyObservedProvider {
	return NewLazyObservedProvider(p.source)
}
