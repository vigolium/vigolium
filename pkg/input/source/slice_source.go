package source

import (
	"context"
	"io"
	"sync/atomic"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
)

// SliceSource is an InputSource that yields work items from a slice of HttpRequestResponse.
// Implements InputSource and Countable.
type SliceSource struct {
	items []*work.WorkItem
	index atomic.Int64
}

// NewSliceSource creates a SliceSource from a slice of HttpRequestResponse items.
func NewSliceSource(items []*httpmsg.HttpRequestResponse, enableModules []string) *SliceSource {
	workItems := make([]*work.WorkItem, len(items))
	for i, rr := range items {
		workItems[i] = work.NewWithModules(rr, enableModules)
	}
	return &SliceSource{items: workItems}
}

// Next returns the next work item, or io.EOF when all items have been consumed.
func (s *SliceSource) Next(ctx context.Context) (*work.WorkItem, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	idx := s.index.Add(1) - 1
	if int(idx) >= len(s.items) {
		return nil, io.EOF
	}
	return s.items[idx], nil
}

// Close is a no-op for SliceSource.
func (s *SliceSource) Close() error {
	return nil
}

// Count returns the number of items in the source (implements Countable).
func (s *SliceSource) Count() int64 {
	return int64(len(s.items))
}
