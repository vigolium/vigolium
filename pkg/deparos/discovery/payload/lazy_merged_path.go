package payload

import (
	"context"
	"hash/fnv"
	"io"
	"net/url"
	"strings"
)

// LazyMergedPathProvider wraps an ObservedProvider and lazily applies
// a path merge transformation when iteration starts.
//
// Memory efficient: only takes snapshot and applies transformation when
// the task actually executes (not at creation time).
//
// Thread-safe: safe to create from any goroutine, transformation happens
// when initialized on first Next() call.
type LazyMergedPathProvider struct {
	source  *ObservedProvider
	dirPath string

	// Snapshot taken and transformed on first Next() call
	items [][]byte
	index int

	// Track if snapshot was taken
	initialized bool
}

// NewLazyMergedPathProvider creates a provider that will snapshot the source
// ObservedProvider and apply the merge transformation when iteration begins.
//
// Parameters:
//   - source: The ObservedProvider containing observed paths
//   - dirPath: The current directory path to merge against (full URL or path)
func NewLazyMergedPathProvider(source *ObservedProvider, dirPath string) *LazyMergedPathProvider {
	return &LazyMergedPathProvider{
		source:      source,
		dirPath:     dirPath,
		initialized: false,
	}
}

// initialize takes a snapshot of the source provider and applies the merge transformation.
// Called once on first Next() call.
func (p *LazyMergedPathProvider) initialize() {
	if p.initialized {
		return
	}

	// Take snapshot from source
	allPaths := p.source.GetAllItems()

	// Extract path portion from dirPath if it's a full URL
	// e.g., "http://host/api/v1/" → "/api/v1/"
	dirPathOnly := ExtractPathFromURL(p.dirPath)

	// Apply merge transformation using MergePathWithBase directly
	p.items = make([][]byte, 0, len(allPaths))
	for _, storedPath := range allPaths {
		merged := MergePathWithBase(storedPath, dirPathOnly)
		if merged != "" {
			// Strip query params - merged paths should be clean for URL construction
			if qIdx := strings.IndexByte(merged, '?'); qIdx >= 0 {
				merged = merged[:qIdx]
			}
			p.items = append(p.items, []byte(merged))
		}
	}

	p.index = 0
	p.initialized = true
}

// ExtractPathFromURL extracts the path portion from a URL string. It is the single
// source of truth for path extraction across the discovery packages (the
// discovery package delegates to it).
// If the input is already just a path (no scheme), returns it unchanged.
// Example: "http://example.com/api/v1/" → "/api/v1/"
// Example: "http://example.com/api?q=test" → "/api" (query stripped)
// Example: "/api/v1/" → "/api/v1/"
//
// Returns the ESCAPED (on-the-wire) path so a path-normalization bypass base
// ("/%23/../") survives verbatim into probes instead of decoding to "/#/../"
// (whose "#" is a fragment delimiter). For ordinary paths this is a no-op since
// EscapedPath() equals Path.
func ExtractPathFromURL(urlStr string) string {
	if urlStr == "" {
		return "/"
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}

	// If it has scheme and host, extract path ONLY (no query)
	if parsed.Scheme != "" && parsed.Host != "" {
		p := parsed.EscapedPath()
		if p == "" {
			p = "/"
		}
		// Query params are NOT included - extensions should be added to path, not query
		return p
	}

	// Otherwise return as-is (it's already a path)
	return urlStr
}

// Next returns the next merged path or io.EOF when exhausted.
func (p *LazyMergedPathProvider) Next(ctx context.Context) ([]byte, error) {
	// Take snapshot and apply transformation on first call
	if !p.initialized {
		p.initialize()
	}

	if p.index >= len(p.items) {
		return nil, io.EOF
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	item := p.items[p.index]
	p.index++
	return item, nil
}

// Count returns the current count from source (may change until initialized).
// After initialization, returns the actual count of successfully merged paths.
func (p *LazyMergedPathProvider) Count() int {
	if p.initialized {
		return len(p.items)
	}
	return p.source.Count()
}

// Name returns the provider name.
func (p *LazyMergedPathProvider) Name() string {
	return "lazy-merged-path"
}

// Close releases resources.
func (p *LazyMergedPathProvider) Close() error {
	p.items = nil
	return nil
}

// HashContent returns a constant hash for this provider type.
//
// IMPORTANT: Do NOT include dirPath in the hash. The task already uses
// dirPath (directory URL) as part of its deduplication key. Including it
// here would be redundant and break deduplication logic.
func (p *LazyMergedPathProvider) HashContent() uint64 {
	h := fnv.New64a()
	h.Write([]byte("lazy-merged-path"))
	h.Write([]byte{0})

	return h.Sum64()
}
