package source

import (
	"context"
	"io"
	"sync"

	"github.com/vigolium/vigolium/pkg/harvester"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// ExternalHarvesterInputSource adapts the external harvester into an InputSource.
// It lazily starts harvesting from external intelligence sources on the first Next() call.
type ExternalHarvesterInputSource struct {
	harvester     *harvester.Harvester
	domains       []string
	enableModules []string

	mu      sync.Mutex
	items   chan *work.WorkItem
	done    chan struct{}
	started bool
	closed  bool
}

// NewExternalHarvesterInputSource creates a new ExternalHarvesterInputSource.
func NewExternalHarvesterInputSource(h *harvester.Harvester, domains []string, enableModules []string) *ExternalHarvesterInputSource {
	return &ExternalHarvesterInputSource{
		harvester:     h,
		domains:       domains,
		enableModules: enableModules,
		items:         make(chan *work.WorkItem, 100),
		done:          make(chan struct{}),
	}
}

// Next returns the next externally harvested item as a WorkItem.
// It lazily starts the external harvesting process on first call.
func (s *ExternalHarvesterInputSource) Next(ctx context.Context) (*work.WorkItem, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, io.EOF
	}
	if !s.started {
		s.started = true
		go s.run()
	}
	s.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case item, ok := <-s.items:
		if !ok {
			return nil, io.EOF
		}
		return item, nil
	}
}

// run harvests URLs from external sources and converts them to WorkItems.
func (s *ExternalHarvesterInputSource) run() {
	defer close(s.items)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Stop harvesting if Close() is called
	go func() {
		select {
		case <-s.done:
			cancel()
		case <-ctx.Done():
		}
	}()

	urlCh := s.harvester.Harvest(ctx, s.domains)
	for rawURL := range urlCh {
		rr, err := httpmsg.GetRawRequestFromURL(rawURL)
		if err != nil {
			zap.L().Debug("ExternalHarvester: skipping invalid URL", zap.String("url", rawURL), zap.Error(err))
			continue
		}

		item := work.NewWithModules(rr, s.enableModules)

		select {
		case <-s.done:
			return
		case s.items <- item:
		}
	}
}

// Close releases resources and stops external harvesting.
func (s *ExternalHarvesterInputSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	if s.started {
		close(s.done)
		// Drain channel to unblock goroutine
		go func() {
			for range s.items {
			}
		}()
	}

	return nil
}
