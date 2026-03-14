package source

import (
	"context"
	"io"
	"sync"

	"github.com/vigolium/vigolium/pkg/work"
	"github.com/sourcegraph/conc"
)

type itemOrError struct {
	item *work.WorkItem
	err  error
}

// ConcurrentMultiSource merges multiple InputSources by reading from all
// concurrently. Unlike MultiSource which drains sources sequentially,
// ConcurrentMultiSource reads from all sources in parallel via goroutines
// pushing to a shared channel. This is required when some sources block
// indefinitely (e.g., queue sources).
type ConcurrentMultiSource struct {
	sources []InputSource
	items   chan itemOrError
	cancel  context.CancelFunc
	wg      conc.WaitGroup
	once    sync.Once
}

// NewConcurrentMultiSource creates a ConcurrentMultiSource that reads from
// all provided sources concurrently.
func NewConcurrentMultiSource(sources ...InputSource) *ConcurrentMultiSource {
	ctx, cancel := context.WithCancel(context.Background())

	bufSize := len(sources) * 10
	if bufSize < 64 {
		bufSize = 64
	}
	if bufSize > 4096 {
		bufSize = 4096
	}

	cs := &ConcurrentMultiSource{
		sources: sources,
		items:   make(chan itemOrError, bufSize),
		cancel:  cancel,
	}

	for _, src := range sources {
		cs.wg.Go(func() {
			cs.readSource(ctx, src)
		})
	}

	// Close the items channel when all source goroutines finish
	go func() {
		defer close(cs.items)
		cs.wg.Wait()
	}()

	return cs
}

func (cs *ConcurrentMultiSource) readSource(ctx context.Context, src InputSource) {
	for {
		item, err := src.Next(ctx)
		if err != nil {
			if IsEOF(err) || ctx.Err() != nil {
				return
			}
			select {
			case cs.items <- itemOrError{err: err}:
			case <-ctx.Done():
				return
			}
			continue
		}
		select {
		case cs.items <- itemOrError{item: item}:
		case <-ctx.Done():
			return
		}
	}
}

// Next returns the next work item from any of the underlying sources.
func (cs *ConcurrentMultiSource) Next(ctx context.Context) (*work.WorkItem, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ie, ok := <-cs.items:
		if !ok {
			return nil, io.EOF
		}
		if ie.err != nil {
			return nil, ie.err
		}
		return ie.item, nil
	}
}

// Close cancels all source goroutines and closes all underlying sources.
func (cs *ConcurrentMultiSource) Close() error {
	var firstErr error
	cs.once.Do(func() {
		cs.cancel()
		cs.wg.Wait()
		for _, src := range cs.sources {
			if err := src.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	})
	return firstErr
}
