package source

import (
	"context"
	"io"
	"sync"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"github.com/vigolium/vigolium/pkg/input/formats/apivoyagerlist"
	"github.com/vigolium/vigolium/pkg/input/formats/burpraw"
	"github.com/vigolium/vigolium/pkg/input/formats/burpxml"
	"github.com/vigolium/vigolium/pkg/input/formats/crawlerxdir"
	"github.com/vigolium/vigolium/pkg/input/formats/curl"
	"github.com/vigolium/vigolium/pkg/input/formats/deparos"
	"github.com/vigolium/vigolium/pkg/input/formats/har"
	"github.com/vigolium/vigolium/pkg/input/formats/nuclei"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/postman"
	"github.com/vigolium/vigolium/pkg/input/formats/urls"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// FileSource provides lazy-loading input from files using format parsers.
// It wraps the existing Format interface and converts push-based callback to pull-based Next().
type FileSource struct {
	format        formats.Format
	filePath      string
	enableModules []string

	mu       sync.Mutex
	items    chan *work.WorkItem
	done     chan struct{}
	started  bool
	closed   bool
	parseErr error
}

// FileSourceConfig configures FileSource behavior.
type FileSourceConfig struct {
	FilePath      string
	Format        string // "urls", "nuclei-output", "spitolas", "openapi", etc.
	BufferSize    int    // Channel buffer size (default: 100)
	EnableModules []string
	FormatOptions formats.InputFormatOptions
}

// NewFileSource creates a new FileSource for the given file and format.
func NewFileSource(cfg FileSourceConfig) (*FileSource, error) {
	format, err := resolveFormat(cfg.Format)
	if err != nil {
		return nil, err
	}

	// Apply format options
	format.SetOptions(cfg.FormatOptions)

	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = 100
	}

	return &FileSource{
		format:        format,
		filePath:      cfg.FilePath,
		enableModules: cfg.EnableModules,
		items:         make(chan *work.WorkItem, bufSize),
		done:          make(chan struct{}),
	}, nil
}

// resolveFormat returns the appropriate Format implementation for the given name.
func resolveFormat(name string) (formats.Format, error) {
	switch name {
	case "nuclei", "nuclei-output":
		return nuclei.New(), nil
	case "urls", "url", "list":
		return urls.New(), nil
	case "crawlerxdir", "crawlerx", "parquet", "spitolas", "spitolas-output":
		return crawlerxdir.New(), nil
	case "apivoyagerlist", "apivoyager":
		return apivoyagerlist.New(), nil
	case "openapi", "swagger":
		return openapi.New(), nil
	case "postman":
		return postman.New(), nil
	case "curl":
		return curl.New(), nil
	case "burpraw", "burp-raw", "raw":
		return burpraw.New(), nil
	case "burpxml", "burp-xml", "burp", "burpstate":
		return burpxml.New(), nil
	case "har", "http-archive":
		return har.New(), nil
	case "deparos", "deparos-output":
		return deparos.New(), nil
	default:
		return nuclei.New(), nil // Default to nuclei format
	}
}

// Format returns the underlying format parser.
// This allows callers to configure format-specific options after creation.
func (f *FileSource) Format() formats.Format {
	return f.format
}

// Next returns the next item from the file.
// It blocks until an item is available or the file is exhausted.
func (f *FileSource) Next(ctx context.Context) (*work.WorkItem, error) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil, io.EOF
	}
	if !f.started {
		f.started = true
		go f.startParsing()
	}
	f.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case item, ok := <-f.items:
		if !ok {
			// Channel closed - check for parse error
			f.mu.Lock()
			err := f.parseErr
			f.mu.Unlock()
			if err != nil {
				return nil, err
			}
			return nil, io.EOF
		}
		return item, nil
	}
}

// startParsing runs the format parser in a goroutine and sends items to the channel.
func (f *FileSource) startParsing() {
	defer close(f.items)

	err := f.format.Parse(f.filePath, func(rr *httpmsg.HttpRequestResponse) bool {
		select {
		case <-f.done:
			return false // Stop parsing
		case f.items <- work.NewWithModules(rr, f.enableModules):
			return true // Continue parsing
		}
	})

	if err != nil {
		f.mu.Lock()
		f.parseErr = err
		f.mu.Unlock()
		zap.L().Error("FileSource: Parse error", zap.String("file", f.filePath), zap.Error(err))
	}
}

// Close releases resources and stops parsing.
func (f *FileSource) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return nil
	}
	f.closed = true

	if f.started {
		close(f.done)
		// Drain channel to unblock parser goroutine
		go func() {
			for range f.items {
			}
		}()
	}

	return nil
}

// Count returns the total item count if the underlying format supports counting.
func (f *FileSource) Count() int64 {
	if counter, ok := f.format.(formats.Counter); ok {
		count, err := counter.Count(f.filePath)
		if err != nil {
			zap.L().Debug("FileSource: Count failed", zap.String("file", f.filePath), zap.Error(err))
			return 0
		}
		return count
	}
	return 0
}
