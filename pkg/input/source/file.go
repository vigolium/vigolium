package source

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"github.com/vigolium/vigolium/pkg/input/formats/burpraw"
	"github.com/vigolium/vigolium/pkg/input/formats/burpscope"
	"github.com/vigolium/vigolium/pkg/input/formats/burpxml"
	"github.com/vigolium/vigolium/pkg/input/formats/curl"
	"github.com/vigolium/vigolium/pkg/input/formats/deparos"
	"github.com/vigolium/vigolium/pkg/input/formats/har"
	"github.com/vigolium/vigolium/pkg/input/formats/nuclei"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/postman"
	"github.com/vigolium/vigolium/pkg/input/formats/urls"
	"github.com/vigolium/vigolium/pkg/input/formats/wsdl"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"
)

// FileSource provides lazy-loading input from files using format parsers.
// It wraps the existing Format interface and converts push-based callback to pull-based Next().
type FileSource struct {
	format        formats.Format
	detection     Detection // content detection, when the URL-list default was in play
	filePath      string
	enableModules []string

	mu       sync.Mutex
	items    chan *work.WorkItem
	done     chan struct{}
	started  bool
	closed   bool
	parseErr error

	// countOnce memoizes Count. Counting re-reads and re-parses the WHOLE file
	// (HAR and Postman unmarshal the entire archive to do it), and Count is asked
	// more than once per run — the pre-scan banner and progress reporting both
	// call it. The file is an immutable input for the life of this source, so one
	// parse is enough; the -T path memoizes its line count for the same reason.
	countOnce  sync.Once
	countValue int64
}

// FileSourceConfig configures FileSource behavior.
type FileSourceConfig struct {
	FilePath      string
	Format        string // canonical name or alias from formatRegistry ("urls", "nuclei", "openapi", …)
	BufferSize    int    // Channel buffer size (default: 100)
	EnableModules []string
	FormatOptions formats.InputFormatOptions

	// FormatExplicit marks Format as chosen by the user (-I given, a REST mode
	// other than "auto"). Only then does a URL-list Format skip content
	// detection; the "urls" default is otherwise indistinguishable from it.
	FormatExplicit bool
}

// NewFileSource creates a new FileSource for the given file and format.
func NewFileSource(cfg FileSourceConfig) (*FileSource, error) {
	format, err := resolveFormat(cfg.Format)
	if err != nil {
		return nil, err
	}

	// A file that arrives with the URL-list default (-i without -I, a -T list,
	// REST "auto") may be any format: Burp scope and project exports, HARs,
	// Postman collections and OpenAPI specs share .json, captures come without
	// extensions, and reading any of them line by line hands the scanner JSON
	// punctuation as targets. Detect by content (DetectFormat, the one detector)
	// and displace only the URL-list default, so an explicit -I always wins.
	var detection Detection
	if _, isURLList := format.(*urls.URLListFormat); isURLList {
		head, headErr := readHead(cfg.FilePath, DetectHeadBytes)
		if headErr == nil {
			detection = DetectFormatHead(head, filepath.Base(cfg.FilePath))
			if !cfg.FormatExplicit && detection.Detected() {
				e, _ := lookupFormat(detection.Format)
				format = e.newParser()
				zap.L().Info("detected input format",
					zap.String("file", cfg.FilePath),
					zap.String("format", detection.Format),
					zap.String("reason", detection.Reason))
			} else if err := checkURLListHead(cfg.FilePath, head, detection, cfg.FormatExplicit); err != nil {
				// Never silent: a file that is mostly not URLs must not become a
				// pile of junk targets (or zero of them) with a log line per line.
				return nil, err
			}
		}
		// An unreadable file keeps the URL parser, whose open error reports it.
	}

	// Apply format options
	format.SetOptions(cfg.FormatOptions)

	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = 100
	}

	return &FileSource{
		format:        format,
		detection:     detection,
		filePath:      cfg.FilePath,
		enableModules: cfg.EnableModules,
		items:         make(chan *work.WorkItem, bufSize),
		done:          make(chan struct{}),
	}, nil
}

// formatEntry binds a canonical input-format name and its accepted aliases to a
// parser constructor and a content sniffer. formatRegistry (below) is the single
// source of truth for which input formats exist: resolveFormat, LookupFormat,
// DetectFormat, SupportedFormats, and SupportedFormatNames all derive from it so
// the accepted set, the detector, the help text, and the error message can never
// drift apart.
type formatEntry struct {
	canonical string
	aliases   []string
	newParser func() formats.Format
	// targetList marks the formats whose file IS a list of target URLs rather
	// than a spec or a traffic export. Only these can be promoted into
	// Options.Targets (see IsTargetListFormat) — the rest yield records whose
	// URLs are not seeds a phase can crawl from. Kept as a column here rather
	// than as a name list elsewhere so a new alias inherits the answer.
	targetList bool
	// sniff scores a file head for this format (see DetectFormat). The
	// sniffers live in detect.go.
	sniff Sniff
}

// formatRegistry lists every supported input format in display order. Ties in
// DetectFormat go to the earlier row.
//
// The REST ingest API's historical input_mode names (postman_collection,
// http_archive, url_file) are aliases here, so REST and CLI share one
// vocabulary.
var formatRegistry = []formatEntry{
	{"urls", []string{"url", "list", "url_file"}, func() formats.Format { return urls.New() }, true, sniffURLList},
	{"nuclei", []string{"nuclei-output"}, func() formats.Format { return nuclei.New() }, false, sniffNuclei},
	{"openapi", []string{"swagger"}, func() formats.Format { return openapi.New() }, false, sniffOpenAPI},
	{"wsdl", []string{"soap", "svc"}, func() formats.Format { return wsdl.New() }, false, sniffWSDL},
	{"postman", []string{"postman_collection"}, func() formats.Format { return postman.New() }, false, sniffPostman},
	{"curl", nil, func() formats.Format { return curl.New() }, false, sniffCurl},
	{"burpraw", []string{"burp-raw", "raw"}, func() formats.Format { return burpraw.New() }, false, sniffBurpRaw},
	{"burpxml", []string{"burp-xml", "burp", "burpstate"}, func() formats.Format { return burpxml.New() }, false, sniffBurpXML},
	{"burpscope", []string{"burp-scope", "burp-config", "burp-project-config"}, func() formats.Format { return burpscope.New() }, true, sniffBurpScope},
	{"har", []string{"http-archive", "http_archive"}, func() formats.Format { return har.New() }, false, sniffHAR},
	{"deparos", []string{"deparos-output"}, func() formats.Format { return deparos.New() }, false, sniffDeparos},
}

// FormatInfo is the public view of one formatRegistry row: everything a caller
// outside this package needs to describe an input format, and nothing that
// would let it construct a parser of its own.
//
// It exists so the CLI's -I help text and `--list-input-mode` table are derived
// from the registry rather than re-typed beside it. The hand-maintained copy
// they used to carry had already drifted: it advertised "nuclei-output" as the
// canonical name with "nuclei" as the alias, which is the reverse of what
// resolveFormat accepts, and it was missing burpscope's burp-project-config
// alias entirely.
type FormatInfo struct {
	Name       string   // canonical -I value
	Aliases    []string // accepted alternatives, in registry order
	TargetList bool     // the file is a list of target URLs (see IsTargetListFormat)
}

// Formats returns every supported input format in display order. The aliases
// slice is copied, so a caller cannot mutate the registry through it.
func Formats() []FormatInfo {
	out := make([]FormatInfo, 0, len(formatRegistry))
	for _, e := range formatRegistry {
		out = append(out, FormatInfo{
			Name:       e.canonical,
			Aliases:    append([]string(nil), e.aliases...),
			TargetList: e.targetList,
		})
	}
	return out
}

// IsTargetListFormat reports whether the given -I/--input-mode name or alias
// names a format whose file is a list of target URLs. An empty name resolves to
// the "urls" default, matching resolveFormat; an unknown name is not a target
// list (resolveFormat rejects it separately).
//
// Callers use it to decide whether a file's contents can be promoted into
// Options.Targets. It reads the same registry row resolveFormat does, so an
// alias added there is promoted without a second edit — a hand-copied alias list
// that missed one would parse the file fine and then leave every target-seeded
// phase with nothing, which is the bug this predicate exists to prevent.
func IsTargetListFormat(name string) bool {
	e, ok := lookupFormat(name)
	return ok && e.targetList
}

// IsOpenAPIFormat reports whether the given -I name or alias selects the
// OpenAPI/Swagger parser (whose spec carries servers[] and honours --spec-url).
func IsOpenAPIFormat(name string) bool {
	e, ok := lookupFormat(name)
	return ok && e.canonical == "openapi"
}

// LookupFormat resolves an input-format name or alias (case-insensitive; empty
// means the "urls" default) to its registry row. Callers outside this package
// — the REST ingest handler — use it to accept exactly the names -I accepts.
func LookupFormat(name string) (FormatInfo, bool) {
	e, ok := lookupFormat(name)
	if !ok {
		return FormatInfo{}, false
	}
	return FormatInfo{Name: e.canonical, Aliases: append([]string(nil), e.aliases...), TargetList: e.targetList}, true
}

// lookupFormat resolves a format name or alias to its registry row. It is the
// ONE place the registry's normalization rules live — an empty name defaulting
// to "urls", case folding, alias scanning — so `resolveFormat` and
// `IsTargetListFormat` cannot answer from subtly different rules. Two
// hand-written copies of this loop is exactly the drift the `targetList` column
// was added to prevent.
func lookupFormat(name string) (formatEntry, bool) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		key = "urls"
	}
	for _, e := range formatRegistry {
		if key == e.canonical {
			return e, true
		}
		for _, a := range e.aliases {
			if key == a {
				return e, true
			}
		}
	}
	return formatEntry{}, false
}

// resolveFormat returns the parser for the given format name or alias. An empty
// name resolves to the default "urls" list format (matching the -I flag
// default). An unknown explicit format is a hard error: previously any
// unrecognized value silently fell back to the Nuclei parser, so a typo (e.g.
// "postamn") would misparse the input as Nuclei JSONL and yield zero or partial
// records with no error. Failing fast surfaces the mistake before any scan runs.
func resolveFormat(name string) (formats.Format, error) {
	if e, ok := lookupFormat(name); ok {
		return e.newParser(), nil
	}
	return nil, fmt.Errorf("unknown input format %q; supported formats: %s (see 'vigolium scan --list-input-mode')", name, SupportedFormats())
}

// NewParser returns a fresh parser for the given format name or alias, for
// callers that drive Parse themselves (the REST ingest handler) and need to set
// format-specific options first. Unknown names error like resolveFormat.
func NewParser(name string) (formats.Format, error) {
	return resolveFormat(name)
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

// HostCensus counts the hosts an input file's records target, for deriving a
// file-input scan's scope when no -t was given (SAFE-4). primary is the host
// the file is "about":
//
//   - HAR, Burp and other traffic exports: the first record's host, else the
//     most frequent registrable domain;
//   - OpenAPI: the first absolute server (the census lists every server, one
//     count each; scanning them all needs an explicit --spec-url or
//     --scope-origin all).
//
// formatName is resolved like NewFileSource resolves it (the URL-list default
// is displaced by content detection). Hosts are lowercased, without port.
func HostCensus(filePath, formatName string) (census map[string]int, primary string, err error) {
	fs, err := NewFileSource(FileSourceConfig{FilePath: filePath, Format: formatName})
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = fs.Close() }()
	census = make(map[string]int)
	if _, isSpec := fs.Format().(*openapi.Format); isSpec {
		servers, err := openapi.SpecServerURLs(filePath)
		if err != nil {
			return nil, "", err
		}
		for _, raw := range servers {
			host := hostOfURL(raw)
			if host == "" {
				continue
			}
			if primary == "" {
				primary = host
			}
			census[host]++
		}
		return census, primary, nil
	}
	first := ""
	parseErr := fs.Format().Parse(filePath, func(rr *httpmsg.HttpRequestResponse) bool {
		svc := rr.Service()
		if svc == nil {
			return true
		}
		host := strings.ToLower(strings.TrimSpace(svc.Host()))
		if host == "" {
			return true
		}
		if first == "" {
			first = host
		}
		census[host]++
		return true
	})
	if parseErr != nil && len(census) == 0 {
		return nil, "", parseErr
	}
	if first != "" {
		return census, first, nil
	}
	return census, mostFrequentDomain(census), nil
}

// mostFrequentDomain is the registrable domain with the most records in
// census (ties broken alphabetically), or "".
func mostFrequentDomain(census map[string]int) string {
	byDomain := make(map[string]int)
	for host, n := range census {
		d, err := publicsuffix.EffectiveTLDPlusOne(host)
		if err != nil {
			d = host
		}
		byDomain[d] += n
	}
	best, bestN := "", 0
	for d, n := range byDomain {
		if n > bestN || (n == bestN && d < best) {
			best, bestN = d, n
		}
	}
	return best
}

func hostOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// Detection returns the content detection NewFileSource ran when the format
// was the URL-list default (zero value otherwise). Detection.Detected reports
// whether it displaced the default.
func (f *FileSource) Detection() Detection {
	return f.detection
}

// Format returns the underlying format parser.
// This allows callers to configure format-specific options after creation.
func (f *FileSource) Format() formats.Format {
	return f.format
}

// FirstFileSource returns the first *FileSource reachable from src, unwrapping a
// MultiSource (the shape NewInputSource produces when targets/-t and a file/-i
// are combined). Returns nil when there is none. Callers use it to configure
// format-specific options (OpenAPI BaseURL, WSDL endpoint) on the file parser
// after the source is built — a bare `inputSource.(*FileSource)` misses the
// parser whenever -t is also present, silently dropping the override.
func FirstFileSource(src InputSource) *FileSource {
	switch s := src.(type) {
	case *FileSource:
		return s
	case *MultiSource:
		for _, child := range s.sources {
			if fs := FirstFileSource(child); fs != nil {
				return fs
			}
		}
	}
	return nil
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
	f.countOnce.Do(func() {
		counter, ok := f.format.(formats.Counter)
		if !ok {
			return
		}
		count, err := counter.Count(f.filePath)
		if err != nil {
			zap.L().Debug("FileSource: Count failed", zap.String("file", f.filePath), zap.Error(err))
			return
		}
		f.countValue = count
	})
	return f.countValue
}
