package discovery

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"io"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
	"github.com/vigolium/vigolium/pkg/deparos/jsscan/linkfinder"
)

// JSFetchTask fetches and parses JavaScript files to extract API paths.
// Batched implementation - a single task contains multiple JS URLs.
//
// Priority 0 (same as spider) - must run early to populate observed collections
// before wordlist brute force tasks.
//
// Follows the SpiderTask batching pattern:
// - Multiple JS URLs stored in StaticProvider
// - Expand() iterates provider and emits each URL
// - Coordinator validates status 200 + JS content-type
// - OnResult is called to create findings
type JSFetchTask struct {
	provider   payload.Provider
	cachedHash uint64
}

// JSFetchTaskConfig contains configuration for creating a batched JSFetchTask.
type JSFetchTaskConfig struct {
	JSURLs []string // List of JS URLs to fetch
}

// NewJSFetchTask creates a new batched JS fetch task.
// URLs are stored in a StaticProvider for iteration during Expand().
func NewJSFetchTask(cfg *JSFetchTaskConfig) *JSFetchTask {
	if len(cfg.JSURLs) == 0 {
		return nil
	}

	provider, _ := payload.NewStaticListProvider(cfg.JSURLs)

	task := &JSFetchTask{
		provider: provider,
	}
	task.cachedHash = task.computeHash()
	return task
}

// Hash returns the cached hash computed at creation time.
func (t *JSFetchTask) Hash() uint64 {
	return t.cachedHash
}

// computeHash computes FNV-1a 64-bit hash using provider content.
// Uses sorted hash of all URLs for deterministic deduplication.
func (t *JSFetchTask) computeHash() uint64 {
	h := fnv.New64a()

	// Include priority
	h.Write([]byte{PriorityJSFetch})
	h.Write([]byte{0})

	// Include task type marker
	h.Write([]byte("jsfetch-batch"))
	h.Write([]byte{0})

	// Include provider content hash (sorted URLs)
	if sp, ok := t.provider.(*payload.StaticProvider); ok {
		providerHash := sp.HashContent()
		_ = binary.Write(h, binary.LittleEndian, providerHash)
	}

	return h.Sum64()
}

// Priority returns the task's priority level (0 = highest, same as spider).
func (t *JSFetchTask) Priority() uint8 {
	return PriorityJSFetch
}

// Description returns a human-readable task description.
func (t *JSFetchTask) Description() string {
	return "JS fetch batch (path extraction)"
}

// FoundByName returns a short identifier for result attribution.
func (t *JSFetchTask) FoundByName() string {
	return "jsfetch"
}

// PayloadProvider returns the provider containing JS URLs.
func (t *JSFetchTask) PayloadProvider() payload.Provider {
	return t.provider
}

// FullURL returns empty - batched task has multiple URLs.
func (t *JSFetchTask) FullURL() []byte {
	return nil
}

// Extension returns empty string - JSFetchTask doesn't test extensions.
func (t *JSFetchTask) Extension() string {
	return ""
}

// Depth returns 0 - all JS fetch tasks run at depth 0.
func (t *JSFetchTask) Depth() uint16 {
	return 0
}

// IsFromSpider returns false.
func (t *JSFetchTask) IsFromSpider() bool { return false }

// Expand iterates over all JS URLs in the provider and emits each for fetching.
// Each URL results in a separate HTTP request through the coordinator.
func (t *JSFetchTask) Expand(ctx context.Context, callback func(url string, depth uint16)) error {
	if t.provider == nil {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		urlBytes, err := t.provider.Next(ctx)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			continue
		}

		// All JS fetches use depth 0
		callback(string(urlBytes), 0)
	}
}

// ExtractPathsFromContent extracts paths from content using linkfinder.
// Content can be raw JS body or transformed code from jsscan's CodeRecord.
func (t *JSFetchTask) ExtractPathsFromContent(content []byte) []string {
	return linkfinder.ExtractPaths(content)
}
