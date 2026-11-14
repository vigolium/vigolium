package runner

import (
	"context"
	"io"
	"sync"

	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/work"
)

// harvestPrefetch runs the external-harvest archive queries in the background
// from scan start. The harvest phase sends nothing to the target, yet it ran
// alone, so the scan waited on third-party archives while doing nothing else.
// The phase itself still runs at its plan position (console lines, outcome
// ledger, scope filtering, storage); it just joins this work instead of doing
// it.
type harvestPrefetch struct {
	done   chan struct{}
	cancel context.CancelFunc
	src    *source.ExternalHarvesterInputSource
	items  []*work.WorkItem
	err    error
}

// harvestSourceBuilder is the seam tests replace; production uses the
// runner's configured archive sources.
type harvestSourceBuilder func() *source.ExternalHarvesterInputSource

// startHarvestPrefetch begins draining the external-harvest source on a
// goroutine. It returns nil when there is nothing to prefetch.
func startHarvestPrefetch(parent context.Context, build harvestSourceBuilder) *harvestPrefetch {
	ctx, cancel := context.WithCancel(parent)
	p := &harvestPrefetch{done: make(chan struct{}), cancel: cancel}
	go func() {
		defer close(p.done)
		p.src = build()
		if p.src == nil {
			return
		}
		for {
			item, err := p.src.Next(ctx)
			if err != nil {
				if !source.IsEOF(err) && ctx.Err() == nil {
					p.err = err
				}
				return
			}
			if item != nil {
				p.items = append(p.items, item)
			}
		}
	}()
	return p
}

// wait blocks until the prefetch finished or ctx ends (which also stops it).
func (p *harvestPrefetch) wait(ctx context.Context) error {
	select {
	case <-p.done:
	case <-ctx.Done():
		p.cancel()
		<-p.done
	}
	return p.err
}

// stop cancels an unconsumed prefetch and waits for its goroutine. Nil-safe.
func (p *harvestPrefetch) stop() {
	if p == nil {
		return
	}
	p.cancel()
	<-p.done
	if p.src != nil {
		_ = p.src.Close()
	}
}

// replay returns the prefetched items as an InputSource for the ingest path.
// Only valid after wait.
func (p *harvestPrefetch) replay() source.InputSource {
	return &sliceInputSource{items: p.items}
}

type sliceInputSource struct {
	mu    sync.Mutex
	items []*work.WorkItem
	next  int
}

func (s *sliceInputSource) Next(ctx context.Context) (*work.WorkItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.next >= len(s.items) {
		return nil, io.EOF
	}
	it := s.items[s.next]
	s.next++
	return it, nil
}

func (s *sliceInputSource) Close() error { return nil }

// takeHarvestPrefetch hands the pending prefetch to the harvest phase exactly
// once.
func (r *Runner) takeHarvestPrefetch() *harvestPrefetch {
	r.harvestPrefetchMu.Lock()
	defer r.harvestPrefetchMu.Unlock()
	p := r.harvestPrefetch
	r.harvestPrefetch = nil
	return p
}
