package source

import (
	"bufio"
	"context"
	"io"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
)

// StdinSource reads URLs line-by-line from a reader (typically stdin).
type StdinSource struct {
	scanner       *bufio.Scanner
	enableModules []string
	mu            sync.Mutex
	closed        bool
}

// NewStdinSource creates a StdinSource from an io.Reader.
func NewStdinSource(reader io.Reader, enableModules []string) *StdinSource {
	return &StdinSource{
		scanner:       bufio.NewScanner(reader),
		enableModules: enableModules,
	}
}

// Next returns the next URL as WorkItem.
func (s *StdinSource) Next(ctx context.Context) (*work.WorkItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, io.EOF
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	for s.scanner.Scan() {
		line := strings.TrimSpace(s.scanner.Text())
		if line == "" {
			continue
		}

		rr, err := httpmsg.GetRawRequestFromURL(line)
		if err != nil {
			// Skip invalid URLs, continue to next line
			continue
		}
		return work.NewWithModules(rr, s.enableModules), nil
	}

	if err := s.scanner.Err(); err != nil {
		return nil, err
	}

	return nil, io.EOF
}

// Close marks the source as closed.
func (s *StdinSource) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}
