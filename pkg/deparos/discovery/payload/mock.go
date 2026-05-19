package payload

import (
	"bytes"
	"context"
	"hash/fnv"
	"io"
	"sort"
)

// MockProvider provides a fixed list of payloads for testing.
type MockProvider struct {
	payloads [][]byte
	index    int
}

// NewMockProvider creates a mock provider with the given payloads.
func NewMockProvider(payloads ...string) *MockProvider {
	bytePayloads := make([][]byte, len(payloads))
	for i, p := range payloads {
		bytePayloads[i] = []byte(p)
	}
	return &MockProvider{
		payloads: bytePayloads,
		index:    0,
	}
}

// Next returns the next payload or io.EOF when exhausted.
func (m *MockProvider) Next(ctx context.Context) ([]byte, error) {
	if m.index >= len(m.payloads) {
		return nil, io.EOF
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	payload := m.payloads[m.index]
	m.index++
	return payload, nil
}

// Count returns the total number of payloads.
func (m *MockProvider) Count() int {
	return len(m.payloads)
}

// Name returns a descriptive name for this provider.
func (m *MockProvider) Name() string {
	return "mock"
}

// Close releases any resources (no-op for mock).
func (m *MockProvider) Close() error {
	return nil
}

// HashContent returns a FNV-1a 64-bit hash of the mock provider's payloads.
// Hashes the sorted payloads for deterministic deduplication.
func (m *MockProvider) HashContent() uint64 {
	// Sort payloads for deterministic hash
	sorted := make([][]byte, len(m.payloads))
	copy(sorted, m.payloads)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i], sorted[j]) < 0
	})

	h := fnv.New64a()
	for _, payload := range sorted {
		h.Write(payload)
		h.Write([]byte{0}) // Separator
	}

	return h.Sum64()
}
