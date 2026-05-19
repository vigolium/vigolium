package discovery

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/fnv"
	"io"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
)

// spiderPathDepth calculates depth from path segments for spider URLs.
// Identical to pathDepth in engine_spider.go but local to avoid circular dependency.
func spiderPathDepth(path string) uint16 {
	path = strings.Trim(path, "/")
	if path == "" {
		return 0
	}
	return uint16(strings.Count(path, "/") + 1)
}

// SpiderTaskType identifies the specific spider task variant.
type SpiderTaskType uint8

const (
	// SpiderFiles tests spider-discovered files (no extension modification).
	SpiderFiles SpiderTaskType = iota
	// SpiderDirs tests spider-discovered directories.
	SpiderDirs
)

// SpiderTaskConfig contains configuration for creating a SpiderTask.
type SpiderTaskConfig struct {
	TaskType SpiderTaskType
	Provider payload.Provider
	BaseURL  []byte
	Depth    uint16 // Passed for informational purposes only, NOT incremented
}

// SpiderTask tests URLs discovered by spider link extraction.
// Unlike other tasks, SpiderTask:
// - Has highest priority (PrioritySpider = 0)
// - Does NOT increment depth during processing
// - Does NOT apply maxDepth validation
// - Bypasses module filtering (checked via type assertion)
//
// Hash is computed once at creation time to ensure deterministic deduplication.
type SpiderTask struct {
	taskType   SpiderTaskType
	provider   payload.Provider
	baseURL    []byte
	depth      uint16
	cachedHash uint64
}

// NewSpiderTask creates a new spider task with cached hash.
func NewSpiderTask(cfg *SpiderTaskConfig) *SpiderTask {
	baseURL := make([]byte, len(cfg.BaseURL))
	copy(baseURL, cfg.BaseURL)

	task := &SpiderTask{
		taskType: cfg.TaskType,
		provider: cfg.Provider,
		baseURL:  baseURL,
		depth:    cfg.Depth,
	}
	task.cachedHash = task.computeHash()
	return task
}

// Hash returns the cached hash computed at creation time.
func (t *SpiderTask) Hash() uint64 {
	return t.cachedHash
}

// Priority returns PrioritySpider (highest priority = 0).
func (t *SpiderTask) Priority() uint8 {
	return PrioritySpider
}

// Description returns a human-readable task description.
func (t *SpiderTask) Description() string {
	switch t.taskType {
	case SpiderFiles:
		return "Test spider-discovered files"
	case SpiderDirs:
		return "Test spider-discovered directories"
	default:
		return "Test spider task"
	}
}

// FoundByName returns a short identifier for result attribution.
func (t *SpiderTask) FoundByName() string {
	return "spider"
}

// computeHash computes the hash once at creation time.
func (t *SpiderTask) computeHash() uint64 {
	h := fnv.New64a()

	// Include task type marker to distinguish from other task types
	h.Write([]byte("spider"))
	h.Write([]byte{0})

	h.Write([]byte{byte(t.taskType)})
	h.Write([]byte{0})

	h.Write(t.baseURL)
	h.Write([]byte{0})

	// Capture provider state at creation time
	providerHash := t.provider.HashContent()
	_ = binary.Write(h, binary.LittleEndian, providerHash)

	return h.Sum64()
}

// PayloadProvider returns the provider for payload iteration.
func (t *SpiderTask) PayloadProvider() payload.Provider {
	return t.provider
}

// FullURL returns the full URL for this task.
func (t *SpiderTask) FullURL() []byte {
	return t.baseURL
}

// Extension returns empty string - spider tasks don't test extensions.
func (t *SpiderTask) Extension() string {
	return ""
}

// Depth returns the discovery depth.
// NOTE: This depth is informational only - spider tasks don't increment depth.
func (t *SpiderTask) Depth() uint16 {
	return t.depth
}

// TaskType returns the spider task type.
func (t *SpiderTask) TaskType() SpiderTaskType {
	return t.taskType
}

// IsFromSpider returns true - this is a spider task.
func (t *SpiderTask) IsFromSpider() bool {
	return true
}

// Expand iterates over spider-discovered payloads and generates URLs.
// CRITICAL: Preserves trailing slash for directory payloads.
// Each URL's depth is calculated from its path segments for accurate depth-band scheduling.
func (t *SpiderTask) Expand(ctx context.Context, callback func(url string, depth uint16)) error {
	if t.provider == nil {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		path, err := t.provider.Next(ctx)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			continue
		}

		url := t.buildURL(path)
		// Calculate depth from path for accurate scheduling
		urlDepth := spiderPathDepth(string(path))
		callback(url, urlDepth)
	}
}

// buildURL constructs URL preserving the payload's trailing slash.
// Spider-discovered paths may be directories (with trailing slash) or files.
// Unlike generic URL builders, this does NOT trim trailing slashes.
func (t *SpiderTask) buildURL(path []byte) string {
	var buf bytes.Buffer
	buf.Write(t.baseURL)

	// Trim only leading slashes to avoid double slashes
	p := bytes.TrimLeft(path, "/")

	// Add separator if needed
	if len(t.baseURL) > 0 && t.baseURL[len(t.baseURL)-1] != '/' && len(p) > 0 {
		buf.WriteByte('/')
	}

	// Write path WITHOUT trimming trailing slash - preserve directory markers
	buf.Write(p)

	return buf.String()
}
