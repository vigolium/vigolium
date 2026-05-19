package source

import (
	"context"
	"io"
	"sync"

	"github.com/vigolium/vigolium/pkg/work"
)

// MultiSource combines multiple InputSource into one.
// It drains sources in order: exhausts the first source before moving to the next.
type MultiSource struct {
	sources []InputSource
	current int
	mu      sync.Mutex
	closed  bool
}

// NewMultiSource creates a MultiSource from multiple InputSources.
func NewMultiSource(sources ...InputSource) *MultiSource {
	return &MultiSource{
		sources: sources,
	}
}

// Next returns the next item from the current source, advancing to the next source when exhausted.
func (m *MultiSource) Next(ctx context.Context) (*work.WorkItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, io.EOF
	}

	for m.current < len(m.sources) {
		item, err := m.sources[m.current].Next(ctx)
		if err == io.EOF {
			// Current source exhausted, move to next
			m.current++
			continue
		}
		if err != nil {
			return nil, err
		}
		return item, nil // Forward WorkItem as-is (preserves callback)
	}

	return nil, io.EOF
}

// Close closes all underlying sources.
func (m *MultiSource) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}
	m.closed = true

	var firstErr error
	for _, src := range m.sources {
		if err := src.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Count returns the sum of counts from all sources that implement Countable.
func (m *MultiSource) Count() int64 {
	var total int64
	for _, src := range m.sources {
		if c, ok := src.(Countable); ok {
			total += c.Count()
		}
	}
	return total
}
