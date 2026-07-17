package source

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"github.com/vigolium/vigolium/pkg/input/formats/burpraw"
	"github.com/vigolium/vigolium/pkg/input/formats/burpxml"
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

// formatEntry binds a canonical input-format name and its accepted aliases to a
// parser constructor. formatRegistry (below) is the single source of truth for
// which input formats exist: resolveFormat, SupportedFormats, and
// SupportedFormatNames all derive from it so the accepted set, the help text,
// and the error message can never drift apart.
type formatEntry struct {
	canonical string
	aliases   []string
	newParser func() formats.Format
}

// formatRegistry lists every supported input format in display order.
var formatRegistry = []formatEntry{
	{"urls", []string{"url", "list"}, func() formats.Format { return urls.New() }},
	{"nuclei", []string{"nuclei-output"}, func() formats.Format { return nuclei.New() }},
	{"openapi", []string{"swagger"}, func() formats.Format { return openapi.New() }},
	{"postman", nil, func() formats.Format { return postman.New() }},
	{"curl", nil, func() formats.Format { return curl.New() }},
	{"burpraw", []string{"burp-raw", "raw"}, func() formats.Format { return burpraw.New() }},
	{"burpxml", []string{"burp-xml", "burp", "burpstate"}, func() formats.Format { return burpxml.New() }},
	{"har", []string{"http-archive"}, func() formats.Format { return har.New() }},
	{"deparos", []string{"deparos-output"}, func() formats.Format { return deparos.New() }},
}

// resolveFormat returns the parser for the given format name or alias. An empty
// name resolves to the default "urls" list format (matching the -I flag
// default). An unknown explicit format is a hard error: previously any
// unrecognized value silently fell back to the Nuclei parser, so a typo (e.g.
// "postamn") would misparse the input as Nuclei JSONL and yield zero or partial
// records with no error. Failing fast surfaces the mistake before any scan runs.
func resolveFormat(name string) (formats.Format, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		key = "urls"
	}
	for _, e := range formatRegistry {
		if key == e.canonical {
			return e.newParser(), nil
		}
		for _, a := range e.aliases {
			if key == a {
				return e.newParser(), nil
			}
		}
	}
	return nil, fmt.Errorf("unknown input format %q; supported formats: %s (see 'vigolium scan --list-input-mode')", name, SupportedFormats())
}

// ParseFileRecords parses the file at filePath using the named input format and
// returns the discovered HTTP records. It is the synchronous, pull-everything
// convenience wrapper over the format registry for callers that just want the
// records in a slice (e.g. the autopilot knowledge-base traffic loader) rather
// than the streaming FileSource/Next() API. formatName accepts any canonical
// name or alias resolveFormat understands ("har", "burpxml", "openapi", …); an
// unknown name is a hard error. When max > 0 parsing stops after max records.
// A non-nil parse error is returned alongside whatever records were gathered
// before it (a partially-parseable file still yields its good records).
func ParseFileRecords(filePath, formatName string, max int) ([]*httpmsg.HttpRequestResponse, error) {
	format, err := resolveFormat(formatName)
	if err != nil {
		return nil, err
	}
	var records []*httpmsg.HttpRequestResponse
	parseErr := format.Parse(filePath, func(rr *httpmsg.HttpRequestResponse) bool {
		records = append(records, rr)
		return max <= 0 || len(records) < max
	})
	return records, parseErr
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
			// Channel closed (parse finished or failed). Surface a parse error
			// exactly once — clearing it so subsequent calls report io.EOF.
			// Returning the same non-EOF error on every call would busy-loop a
			// consumer that retries non-EOF errors (see core.Executor.feedItems)
			// and the scan would never terminate.
			f.mu.Lock()
			err := f.parseErr
			f.parseErr = nil
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
