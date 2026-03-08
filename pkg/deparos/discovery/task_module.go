package discovery

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
)

// ModuleTaskConfig contains configuration for creating a ModuleTask.
// SchemeHost and Path are separated to prevent query params from being passed.
type ModuleTaskConfig struct {
	Priority   uint8
	Provider   payload.Provider
	Extension  string
	SchemeHost []byte // scheme://host only (e.g., "http://example.com")
	Path       []byte // path only (e.g., "/api/v1/")
	Depth      uint16
}

// ModuleTask is for custom module-defined tasks with dynamic priority.
// Unlike WordlistTask, priority is user-configurable in module YAML.
// Hash is computed once at creation time to ensure deterministic deduplication.
//
// URL components are stored separately (schemeHost + path) to prevent query params
// from being accidentally passed to module tasks.
type ModuleTask struct {
	priority   uint8
	provider   payload.Provider
	extension  string
	schemeHost []byte // scheme://host only (e.g., "http://example.com")
	path       []byte // path only (e.g., "/api/v1/")
	depth      uint16
	cachedHash uint64
}

// NewModuleTask creates a new module task with cached hash.
func NewModuleTask(cfg *ModuleTaskConfig) *ModuleTask {
	schemeHost := make([]byte, len(cfg.SchemeHost))
	copy(schemeHost, cfg.SchemeHost)

	path := make([]byte, len(cfg.Path))
	copy(path, cfg.Path)

	task := &ModuleTask{
		priority:   cfg.Priority,
		provider:   cfg.Provider,
		extension:  cfg.Extension,
		schemeHost: schemeHost,
		path:       path,
		depth:      cfg.Depth,
	}
	task.cachedHash = task.computeHash()
	return task
}

// Hash returns the cached hash computed at creation time.
func (t *ModuleTask) Hash() uint64 {
	return t.cachedHash
}

// Priority returns the task's priority level (user-configurable).
func (t *ModuleTask) Priority() uint8 {
	return t.priority
}

// Description returns a human-readable task description.
func (t *ModuleTask) Description() string {
	return fmt.Sprintf("Test module files (priority %d)", t.priority)
}

// FoundByName returns a short identifier for result attribution.
func (t *ModuleTask) FoundByName() string {
	return "module"
}

// computeHash computes the hash once at creation time.
func (t *ModuleTask) computeHash() uint64 {
	h := fnv.New64a()

	// Use a marker byte to distinguish from other task types
	h.Write([]byte("module"))
	h.Write([]byte{0})

	h.Write([]byte{t.priority})
	h.Write([]byte{0})

	// Hash schemeHost + path for deduplication
	h.Write(t.schemeHost)
	h.Write(t.path)
	h.Write([]byte{0})

	h.Write([]byte(t.extension))
	h.Write([]byte{0})

	providerHash := t.provider.HashContent()
	_ = binary.Write(h, binary.LittleEndian, providerHash)

	return h.Sum64()
}

// PayloadProvider returns the provider for payload iteration.
func (t *ModuleTask) PayloadProvider() payload.Provider {
	return t.provider
}

// FullURL returns the full URL for this task (schemeHost + path).
func (t *ModuleTask) FullURL() []byte {
	result := make([]byte, 0, len(t.schemeHost)+len(t.path))
	result = append(result, t.schemeHost...)
	result = append(result, t.path...)
	return result
}

// Extension returns the extension to test per payload.
func (t *ModuleTask) Extension() string {
	return t.extension
}

// Depth returns the discovery depth.
func (t *ModuleTask) Depth() uint16 {
	return t.depth
}

// IsFromSpider returns false.
func (t *ModuleTask) IsFromSpider() bool { return false }

// Expand iterates over module payloads and generates URLs with the extension.
func (t *ModuleTask) Expand(ctx context.Context, callback func(url string, depth uint16)) error {
	if t.provider == nil {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		word, err := t.provider.Next(ctx)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			continue
		}

		url := t.buildURL(word, []byte(t.extension))
		callback(url, t.depth)
	}
}

// buildURL constructs URL for module testing.
// Format: schemeHost + path + word + extension
// Trims trailing slashes - module payloads are names, not paths.
func (t *ModuleTask) buildURL(word, extension []byte) string {
	var buf bytes.Buffer
	buf.Write(t.schemeHost)
	buf.Write(t.path)

	// Trim leading and trailing slashes from word
	w := bytes.TrimLeft(word, "/")
	w = bytes.TrimRight(w, "/")

	// Add separator if path doesn't end with /
	if len(t.path) > 0 && t.path[len(t.path)-1] != '/' && len(w) > 0 {
		buf.WriteByte('/')
	}

	buf.Write(w)

	if len(extension) > 0 {
		buf.WriteByte('.')
		buf.Write(extension)
	}

	return buf.String()
}
