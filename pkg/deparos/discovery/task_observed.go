package discovery

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"io"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
)

// ObservedTaskType identifies the specific observed task variant.
type ObservedTaskType uint8

const (
	// ObservedFilesNoExt tests observed names with no extension (Priority 1).
	ObservedFilesNoExt ObservedTaskType = iota
	// ObservedFilesCustomExt tests observed names with custom extensions (Priority 2).
	ObservedFilesCustomExt
	// ObservedFilesLiteral tests full observed filenames as-is (Priority 2).
	// Unlike other observed tasks, this preserves exact filenames including hashes (e.g., "app.b5ca88ec.js").
	ObservedFilesLiteral
	// ObservedDirs tests observed names as directories (Priority 2).
	ObservedDirs
	// ObservedFilesObservedExt tests observed names with a single observed extension (Priority 3).
	ObservedFilesObservedExt
	// ObservedPaths tests full observed paths as directories (Priority 4).
	ObservedPaths
)

// ObservedTaskConfig contains configuration for creating an ObservedTask.
type ObservedTaskConfig struct {
	TaskType  ObservedTaskType
	Provider  payload.Provider
	Extension string // Extension to test (empty for no extension)
	BaseURL   []byte // scheme://host only (e.g., "http://example.com")
	DirPath   string // Directory path (e.g., "/api/v1/") - empty for root
	Depth     uint16
}

// ObservedTask tests observed names/paths discovered during spidering.
// Hash is computed once at creation time to ensure deterministic deduplication.
type ObservedTask struct {
	taskType   ObservedTaskType
	provider   payload.Provider
	extension  string // Extension to test (empty for no extension)
	baseURL    []byte // scheme://host only
	dirPath    string // Directory path (e.g., "/api/v1/")
	depth      uint16
	cachedHash uint64
}

// NewObservedTask creates a new observed task with cached hash.
func NewObservedTask(cfg *ObservedTaskConfig) *ObservedTask {
	baseURL := make([]byte, len(cfg.BaseURL))
	copy(baseURL, cfg.BaseURL)

	task := &ObservedTask{
		taskType:  cfg.TaskType,
		provider:  cfg.Provider,
		extension: cfg.Extension,
		baseURL:   baseURL,
		dirPath:   cfg.DirPath,
		depth:     cfg.Depth,
	}
	task.cachedHash = task.computeHash()
	return task
}

// Hash returns the cached hash computed at creation time.
func (t *ObservedTask) Hash() uint64 {
	return t.cachedHash
}

// Priority returns the task's priority level based on task type.
// Uses centralized priority constants from task.go.
func (t *ObservedTask) Priority() uint8 {
	switch t.taskType {
	case ObservedFilesNoExt:
		return PriorityObservedFilesNoExt
	case ObservedFilesCustomExt:
		return PriorityObservedFilesCustomExt
	case ObservedFilesLiteral:
		return PriorityObservedFilesLiteral
	case ObservedDirs:
		return PriorityObservedDirs
	case ObservedFilesObservedExt:
		return PriorityObservedFilesObservedExt
	case ObservedPaths:
		return PriorityObservedPaths
	default:
		return PriorityObservedFilesNoExt
	}
}

// Description returns a human-readable task description.
func (t *ObservedTask) Description() string {
	switch t.taskType {
	case ObservedFilesNoExt:
		return "Test observed names (no extension)"
	case ObservedFilesCustomExt:
		if t.extension != "" {
			return "Test observed names + ." + t.extension
		}
		return "Test observed names + custom extension"
	case ObservedFilesLiteral:
		return "Test observed full filenames"
	case ObservedDirs:
		return "Test observed names as directories"
	case ObservedFilesObservedExt:
		if t.extension != "" {
			return "Test observed names + ." + t.extension
		}
		return "Test observed names + observed extension"
	case ObservedPaths:
		return "Test observed paths as directories"
	default:
		return "Test observed task"
	}
}

// FoundByName returns a short identifier for result attribution.
func (t *ObservedTask) FoundByName() string {
	switch t.taskType {
	case ObservedFilesNoExt:
		return "observed-no-ext"
	case ObservedFilesCustomExt:
		return "observed-custom-ext"
	case ObservedFilesLiteral:
		return "observed-file"
	case ObservedDirs:
		return "observed-dir"
	case ObservedFilesObservedExt:
		return "observed-ext"
	case ObservedPaths:
		return "observed-path"
	default:
		return "observed"
	}
}

// computeHash computes the hash once at creation time.
func (t *ObservedTask) computeHash() uint64 {
	h := fnv.New64a()

	h.Write([]byte{byte(t.taskType)})
	h.Write([]byte{0})

	h.Write(t.baseURL)
	h.Write([]byte{0})

	// Include dirPath in hash for proper deduplication
	h.Write([]byte(t.dirPath))
	h.Write([]byte{0})

	h.Write([]byte(t.extension))
	h.Write([]byte{0})

	// Capture provider state at creation time
	providerHash := t.provider.HashContent()
	_ = binary.Write(h, binary.LittleEndian, providerHash)

	return h.Sum64()
}

// PayloadProvider returns the provider for payload iteration.
func (t *ObservedTask) PayloadProvider() payload.Provider {
	return t.provider
}

// FullURL returns the full URL for this task (baseURL + dirPath).
func (t *ObservedTask) FullURL() []byte {
	if t.dirPath == "" {
		return t.baseURL
	}
	result := make([]byte, 0, len(t.baseURL)+len(t.dirPath))
	result = append(result, t.baseURL...)
	result = append(result, t.dirPath...)
	return result
}

// Extension returns the extension to test per payload.
func (t *ObservedTask) Extension() string {
	return t.extension
}

// Depth returns the discovery depth.
func (t *ObservedTask) Depth() uint16 {
	return t.depth
}

// TaskType returns the observed task type.
func (t *ObservedTask) TaskType() ObservedTaskType {
	return t.taskType
}

// IsFromSpider returns false - observed tasks are not spider tasks.
func (t *ObservedTask) IsFromSpider() bool {
	return false
}

// Expand iterates over observed names/paths and generates URLs.
func (t *ObservedTask) Expand(ctx context.Context, callback func(url string, depth uint16)) error {
	if t.provider == nil {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		item, err := t.provider.Next(ctx)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			continue
		}

		// ObservedPaths may have trailing slashes (directories) - preserve them
		switch t.taskType {
		case ObservedPaths:
			url := t.buildPathURL(item)
			callback(url, t.depth)
		case ObservedFilesLiteral:
			// ObservedFilesLiteral uses full filename as-is (no extension appending)
			url := t.buildFileURL(item)
			callback(url, t.depth)
		default:
			url := t.buildNameURL(item, []byte(t.extension))
			callback(url, t.depth)
		}
	}
}

// buildPathURL constructs URL for observed paths.
// The path from LazyMergedPathProvider is already a FULL merged path (e.g., /api/v1/admin/).
// baseURL should be scheme://host only, and we just concatenate them.
func (t *ObservedTask) buildPathURL(path []byte) string {
	var buf bytes.Buffer
	buf.Write(t.baseURL)

	// Ensure proper slash handling between baseURL and path
	hasTrailingSlash := len(t.baseURL) > 0 && t.baseURL[len(t.baseURL)-1] == '/'
	hasLeadingSlash := len(path) > 0 && path[0] == '/'

	if hasTrailingSlash && hasLeadingSlash {
		// Both have slash - skip one
		buf.Write(path[1:])
	} else if !hasTrailingSlash && !hasLeadingSlash && len(path) > 0 {
		// Neither has slash - add one
		buf.WriteByte('/')
		buf.Write(path)
	} else {
		// One has slash - just concatenate
		buf.Write(path)
	}

	return buf.String()
}

// buildNameURL constructs URL for observed names.
// Combines baseURL (scheme://host) + dirPath + name + extension.
func (t *ObservedTask) buildNameURL(name, extension []byte) string {
	var buf bytes.Buffer

	// Write baseURL (scheme://host)
	buf.Write(t.baseURL)

	// Write dirPath (e.g., "/api/v1/")
	if t.dirPath != "" {
		// Ensure proper slash between baseURL and dirPath
		if len(t.baseURL) > 0 && t.baseURL[len(t.baseURL)-1] != '/' && t.dirPath[0] != '/' {
			buf.WriteByte('/')
		}
		buf.WriteString(t.dirPath)
	}

	// Trim leading and trailing slashes from name
	n := bytes.TrimLeft(name, "/")
	n = bytes.TrimRight(n, "/")

	// Ensure slash before name
	bufLen := buf.Len()
	if bufLen > 0 && buf.Bytes()[bufLen-1] != '/' && len(n) > 0 {
		buf.WriteByte('/')
	}

	buf.Write(n)

	if len(extension) > 0 {
		buf.WriteByte('.')
		buf.Write(extension)
	}

	// Add trailing slash for directory task type
	if t.taskType == ObservedDirs {
		buf.WriteByte('/')
	}

	return buf.String()
}

// buildFileURL constructs URL for observed full filenames.
// Combines baseURL (scheme://host) + dirPath + filename (no extension appending).
// Unlike buildNameURL, the filename is used as-is since it already includes the extension.
func (t *ObservedTask) buildFileURL(filename []byte) string {
	var buf bytes.Buffer

	// Write baseURL (scheme://host)
	buf.Write(t.baseURL)

	// Write dirPath (e.g., "/api/v1/")
	if t.dirPath != "" {
		if len(t.baseURL) > 0 && t.baseURL[len(t.baseURL)-1] != '/' && t.dirPath[0] != '/' {
			buf.WriteByte('/')
		}
		buf.WriteString(t.dirPath)
	}

	// Trim slashes from filename
	n := bytes.TrimLeft(filename, "/")
	n = bytes.TrimRight(n, "/")

	// Ensure slash before filename
	bufLen := buf.Len()
	if bufLen > 0 && buf.Bytes()[bufLen-1] != '/' && len(n) > 0 {
		buf.WriteByte('/')
	}

	buf.Write(n)
	// NO extension appending - use filename as-is

	return buf.String()
}
