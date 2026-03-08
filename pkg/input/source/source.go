package source

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"github.com/vigolium/vigolium/pkg/work"
)

// InputSource provides a stream of work items for scanning.
// This is a pull-based interface where consumers call Next() to get items.
// Implementations must be safe for concurrent Next() calls from multiple goroutines.
type InputSource interface {
	// Next returns the next work item from the source.
	// It blocks until an item is available (for queue-based sources).
	//
	// Returns:
	//   - (*work.WorkItem, nil) - next item
	//   - (nil, io.EOF) - source exhausted, no more items
	//   - (nil, context.Canceled) - context was cancelled
	//   - (nil, error) - other error occurred
	Next(ctx context.Context) (*work.WorkItem, error)

	// Close releases any resources held by the source.
	// After Close, Next will return io.EOF.
	Close() error
}

// Countable is an optional interface for sources that can report total item count.
type Countable interface {
	Count() int64
}

// GetTotal returns the total count from a source if it implements Countable, otherwise 0.
func GetTotal(src InputSource) int64 {
	if c, ok := src.(Countable); ok {
		return c.Count()
	}
	return 0
}

// IsEOF checks if an error indicates end of source.
func IsEOF(err error) bool {
	return err == io.EOF
}

// SourceConfig holds configuration for creating an InputSource.
type SourceConfig struct {
	// Direct targets (from -u flag)
	Targets []string

	// File-based input
	FilePath string
	Format   string // "urls", "nuclei", "crawlerxdir", "apivoyagerlist"

	// Stdin
	UseStdin bool
	Stdin    io.Reader // defaults to os.Stdin

	// Format options
	SkipFormatValidation  bool
	FormatUseRequiredOnly bool

	// Buffer size for channels
	BufferSize int

	// EnableModules for per-item module filtering (from -m flag)
	EnableModules []string
}

// NewInputSource creates appropriate InputSource based on config.
// Combines multiple sources if needed (e.g., -u flags + -l file + stdin).
func NewInputSource(cfg SourceConfig) (InputSource, error) {
	var sources []InputSource

	// Add target source if targets provided
	if len(cfg.Targets) > 0 {
		sources = append(sources, NewTargetSource(cfg.Targets, cfg.EnableModules))
	}

	// Add file source if file path provided
	if cfg.FilePath != "" {
		bufSize := cfg.BufferSize
		if bufSize <= 0 {
			bufSize = 100
		}
		fs, err := NewFileSource(FileSourceConfig{
			FilePath:      cfg.FilePath,
			Format:        cfg.Format,
			BufferSize:    bufSize,
			EnableModules: cfg.EnableModules,
			FormatOptions: formats.InputFormatOptions{
				SkipFormatValidation: cfg.SkipFormatValidation,
				RequiredOnly:         cfg.FormatUseRequiredOnly,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("file source: %w", err)
		}
		sources = append(sources, fs)
	}

	// Add stdin source if enabled
	if cfg.UseStdin {
		reader := cfg.Stdin
		if reader == nil {
			reader = os.Stdin
		}
		sources = append(sources, NewStdinSource(reader, cfg.EnableModules))
	}

	// Return appropriate source
	switch len(sources) {
	case 0:
		return nil, fmt.Errorf("no input source configured: provide targets (-u), file (-l), or stdin")
	case 1:
		return sources[0], nil
	default:
		return NewMultiSource(sources...), nil
	}
}

// SupportedFormats returns comma-separated list of supported input formats.
func SupportedFormats() string {
	return "urls, nuclei, crawlerxdir, apivoyagerlist, openapi, swagger, deparos"
}

// TargetSource provides input from direct URL targets (from -u flag).
type TargetSource struct {
	targets       []string
	enableModules []string
	index         int
	mu            sync.Mutex
	closed        bool
}

// NewTargetSource creates a TargetSource from a slice of URLs.
func NewTargetSource(targets []string, enableModules []string) *TargetSource {
	return &TargetSource{
		targets:       targets,
		enableModules: enableModules,
	}
}

// Next returns the next URL as WorkItem.
func (t *TargetSource) Next(ctx context.Context) (*work.WorkItem, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, io.EOF
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if t.index >= len(t.targets) {
		return nil, io.EOF
	}

	target := t.targets[t.index]
	t.index++

	rr, err := httpmsg.GetRawRequestFromURL(target)
	if err != nil {
		return nil, err
	}
	return work.NewWithModules(rr, t.enableModules), nil
}

// Close marks the source as closed.
func (t *TargetSource) Close() error {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	return nil
}

// Count returns the total number of targets (known upfront).
func (t *TargetSource) Count() int64 {
	return int64(len(t.targets))
}
