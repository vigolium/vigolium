package discovery

import (
	"context"
	"hash/fnv"
	"net/url"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
)

// CaseSenseCallback is called when case sensitivity detection should be triggered.
type CaseSenseCallback func(ctx context.Context, url *url.URL, sample *fingerprint.Sample, isDirectory bool)

// CaseSenseDetectionTask performs lazy case sensitivity detection.
// Queued when first valid FILE/DIR is discovered.
// Priority 0 (critical) - runs before other pending tasks.
//
// Unlike standard tasks, CaseSenseDetectionTask doesn't use payload iteration.
// The coordinator handles it specially by calling the CaseSenseCallback.
type CaseSenseDetectionTask struct {
	discoveredURL *url.URL
	sample        *fingerprint.Sample
	isDirectory   bool
	callback      CaseSenseCallback
}

// CaseSenseDetectionTaskConfig contains configuration for creating task.
type CaseSenseDetectionTaskConfig struct {
	DiscoveredURL *url.URL
	Sample        *fingerprint.Sample
	IsDirectory   bool
	Callback      CaseSenseCallback
}

// NewCaseSenseDetectionTask creates a new case sensitivity detection task.
func NewCaseSenseDetectionTask(cfg *CaseSenseDetectionTaskConfig) *CaseSenseDetectionTask {
	return &CaseSenseDetectionTask{
		discoveredURL: cfg.DiscoveredURL,
		sample:        cfg.Sample,
		isDirectory:   cfg.IsDirectory,
		callback:      cfg.Callback,
	}
}

// DiscoveredURL returns the discovered URL.
func (t *CaseSenseDetectionTask) DiscoveredURL() *url.URL { return t.discoveredURL }

// Sample returns the fingerprint sample.
func (t *CaseSenseDetectionTask) Sample() *fingerprint.Sample { return t.sample }

// IsDirectory returns true if this is a directory.
func (t *CaseSenseDetectionTask) IsDirectory() bool { return t.isDirectory }

// Callback returns the detection callback.
func (t *CaseSenseDetectionTask) Callback() CaseSenseCallback { return t.callback }

// Hash returns a FNV-1a 64-bit hash for task deduplication.
// Only one detection task per type (file/dir) is needed.
func (t *CaseSenseDetectionTask) Hash() uint64 {
	h := fnv.New64a()
	h.Write([]byte{PriorityJSFetch}) // Priority 0
	h.Write([]byte{0})
	h.Write([]byte("casesense-detect"))
	h.Write([]byte{0})
	if t.isDirectory {
		h.Write([]byte("dir"))
	} else {
		h.Write([]byte("file"))
	}
	return h.Sum64()
}

// Priority returns 0 (highest/critical priority).
// Same as JSFetch - must run as soon as possible.
func (t *CaseSenseDetectionTask) Priority() uint8 { return PriorityJSFetch }

// Description returns a human-readable task description.
func (t *CaseSenseDetectionTask) Description() string {
	if t.isDirectory {
		return "Case sensitivity detection (directory)"
	}
	return "Case sensitivity detection (file)"
}

// FoundByName returns a short identifier for result attribution.
func (t *CaseSenseDetectionTask) FoundByName() string {
	return "casesense"
}

// PayloadProvider returns nil - special task, no standard iteration.
// Coordinator handles this task specially.
func (t *CaseSenseDetectionTask) PayloadProvider() payload.Provider { return nil }

// FullURL returns the discovered URL.
func (t *CaseSenseDetectionTask) FullURL() []byte {
	return []byte(t.discoveredURL.String())
}

// Extension returns empty string - not applicable.
func (t *CaseSenseDetectionTask) Extension() string { return "" }

// Depth returns 0 - not applicable.
func (t *CaseSenseDetectionTask) Depth() uint16 { return 0 }

// IsFromSpider returns false.
func (t *CaseSenseDetectionTask) IsFromSpider() bool { return false }

// Expand is a no-op for CaseSenseDetectionTask.
// CaseSenseDetectionTask is handled specially by coordinator - it doesn't generate
// URLs via standard expansion. Instead, it triggers case sensitivity detection
// using the provided callback.
func (t *CaseSenseDetectionTask) Expand(_ context.Context, _ func(url string, depth uint16)) error {
	return nil
}
