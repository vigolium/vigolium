package source

import (
	"context"
	"io"
	"sync/atomic"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
)

// SingleSource is an InputSource that yields exactly one WorkItem, then returns io.EOF.
// Used by scan-url and scan-request commands for single-target scanning.
type SingleSource struct {
	item *work.WorkItem
	done atomic.Bool
}

// NewSingleSource creates a SingleSource from a single HttpRequestResponse.
func NewSingleSource(rr *httpmsg.HttpRequestResponse, enableModules []string) *SingleSource {
	return &SingleSource{
		item: work.NewWithModules(rr, enableModules),
	}
}

// Next returns the single work item on first call, then io.EOF on subsequent calls.
func (s *SingleSource) Next(ctx context.Context) (*work.WorkItem, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if s.done.CompareAndSwap(false, true) {
		return s.item, nil
	}
	return nil, io.EOF
}

// Close is a no-op for SingleSource.
func (s *SingleSource) Close() error {
	return nil
}

// Count returns 1 (implements Countable).
func (s *SingleSource) Count() int64 {
	return 1
}
