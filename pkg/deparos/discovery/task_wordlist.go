package discovery

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/fnv"
	"io"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
)

// WordlistTaskType identifies the specific wordlist task variant.
type WordlistTaskType uint8

const (
	// Short wordlist tasks (Priority 5-6)
	ShortFilesNoExt       WordlistTaskType = iota // Priority 5: short wordlist, no extensions
	ShortFilesCustomExt                           // Priority 6: short wordlist + custom extensions
	ShortDirs                                     // Priority 6: short directory wordlist
	ShortFilesObservedExt                         // Priority 6: short wordlist + observed extensions

	// Long wordlist tasks (Priority 8-9, 11)
	LongFilesNoExt       // Priority 8: long wordlist, no extensions
	LongFilesCustomExt   // Priority 9: long wordlist + custom extensions
	LongDirs             // Priority 9: long directory wordlist
	LongFilesObservedExt // Priority 11: long wordlist + observed extensions
)

// WordlistTaskConfig contains configuration for creating a WordlistTask.
// SchemeHost and Path are separated to prevent query params from being passed.
type WordlistTaskConfig struct {
	TaskType   WordlistTaskType
	Provider   payload.Provider
	Extension  string
	SchemeHost []byte // scheme://host only (e.g., "http://example.com")
	Path       []byte // path only (e.g., "/api/v1/")
	Depth      uint16
}

// WordlistTask enumerates files or directories from a built-in wordlist.
// Task is immutable configuration - execution is handled by PayloadCoordinator.
// Hash is computed once at creation time to ensure deterministic deduplication.
//
// URL components are stored separately (schemeHost + path) to prevent query params
// from being accidentally passed to wordlist tasks.
type WordlistTask struct {
	taskType   WordlistTaskType
	provider   payload.Provider
	extension  string
	schemeHost []byte // scheme://host only (e.g., "http://example.com")
	path       []byte // path only (e.g., "/api/v1/")
	depth      uint16
	cachedHash uint64
}

// NewWordlistTask creates a new wordlist enumeration task with cached hash.
func NewWordlistTask(cfg *WordlistTaskConfig) *WordlistTask {
	schemeHost := make([]byte, len(cfg.SchemeHost))
	copy(schemeHost, cfg.SchemeHost)

	path := make([]byte, len(cfg.Path))
	copy(path, cfg.Path)

	task := &WordlistTask{
		taskType:   cfg.TaskType,
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
func (t *WordlistTask) Hash() uint64 {
	return t.cachedHash
}

// Priority returns the task's priority level based on task type.
// Uses centralized priority constants from task.go.
func (t *WordlistTask) Priority() uint8 {
	switch t.taskType {
	case ShortFilesNoExt:
		return PriorityShortFilesNoExt
	case ShortFilesCustomExt:
		return PriorityShortFilesCustomExt
	case ShortDirs:
		return PriorityShortDirs
	case ShortFilesObservedExt:
		return PriorityShortFilesObservedExt
	case LongFilesNoExt:
		return PriorityLongFilesNoExt
	case LongFilesCustomExt:
		return PriorityLongFilesCustomExt
	case LongDirs:
		return PriorityLongDirs
	case LongFilesObservedExt:
		return PriorityLongFilesObservedExt
	default:
		return PriorityShortFilesNoExt
	}
}

// Description returns a human-readable task description.
func (t *WordlistTask) Description() string {
	switch t.taskType {
	case ShortFilesNoExt:
		return "Test short file list (no extensions)"
	case ShortFilesCustomExt:
		return "Test short file list + custom extensions"
	case ShortDirs:
		return "Test short directory list"
	case ShortFilesObservedExt:
		return "Test short file list + observed extensions"
	case LongFilesNoExt:
		return "Test long file list (no extensions)"
	case LongFilesCustomExt:
		return "Test long file list + custom extensions"
	case LongDirs:
		return "Test long directory list"
	case LongFilesObservedExt:
		return "Test long file list + observed extensions"
	default:
		return "Test wordlist task"
	}
}

// FoundByName returns a short identifier for result attribution.
func (t *WordlistTask) FoundByName() string {
	switch t.taskType {
	case ShortFilesNoExt:
		return "short-file-no-ext"
	case ShortFilesCustomExt:
		return "short-file-custom-ext"
	case ShortDirs:
		return "short-dir"
	case ShortFilesObservedExt:
		return "short-file-observed-ext"
	case LongFilesNoExt:
		return "long-file-no-ext"
	case LongFilesCustomExt:
		return "long-file-custom-ext"
	case LongDirs:
		return "long-dir"
	case LongFilesObservedExt:
		return "long-file-observed-ext"
	default:
		return "wordlist"
	}
}

// computeHash computes the hash once at creation time.
func (t *WordlistTask) computeHash() uint64 {
	h := fnv.New64a()

	h.Write([]byte{byte(t.taskType)})
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
func (t *WordlistTask) PayloadProvider() payload.Provider {
	return t.provider
}

// FullURL returns the full URL for this task (schemeHost + path).
func (t *WordlistTask) FullURL() []byte {
	result := make([]byte, 0, len(t.schemeHost)+len(t.path))
	result = append(result, t.schemeHost...)
	result = append(result, t.path...)
	return result
}

// Extension returns the extension to test per payload.
func (t *WordlistTask) Extension() string {
	return t.extension
}

// Depth returns the discovery depth.
func (t *WordlistTask) Depth() uint16 {
	return t.depth
}

// TaskType returns the wordlist task type.
func (t *WordlistTask) TaskType() WordlistTaskType {
	return t.taskType
}

// IsFromSpider returns false.
func (t *WordlistTask) IsFromSpider() bool { return false }

// Expand iterates over wordlist payloads and generates URLs with the extension.
func (t *WordlistTask) Expand(ctx context.Context, callback func(url string, depth uint16)) error {
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

// buildURL constructs URL for wordlist testing.
// Format: schemeHost + path + word + extension + trailing slash (for dirs)
func (t *WordlistTask) buildURL(word, extension []byte) string {
	var buf bytes.Buffer
	buf.Write(t.schemeHost)
	buf.Write(t.path)

	// Trim leading and trailing slashes from word
	w := bytes.TrimLeft(word, "/")
	w = bytes.TrimRight(w, "/")

	// Add separator if needed
	if buf.Len() > 0 && buf.Bytes()[buf.Len()-1] != '/' && len(w) > 0 {
		buf.WriteByte('/')
	}

	buf.Write(w)

	// Add extension if provided
	if len(extension) > 0 {
		buf.WriteByte('.')
		buf.Write(extension)
	}

	// Add trailing slash for directory task types
	if t.taskType == ShortDirs || t.taskType == LongDirs {
		buf.WriteByte('/')
	}

	return buf.String()
}
