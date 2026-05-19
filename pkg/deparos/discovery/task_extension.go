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

// ExtensionVariantTask tests discovered files with extension variants.
// Task is immutable configuration - execution is handled by PayloadCoordinator.
// Priority is always 7 (PriorityExtensionVariants).
//
// URL components are stored separately (schemeHost + path) to prevent query params
// from being accidentally passed to extension variant tasks.
type ExtensionVariantTask struct {
	schemeHost  []byte // scheme://host only (e.g., "http://example.com")
	path        []byte // path only (e.g., "/api/v1/")
	filename    []byte
	originalExt []byte
	fullName    []byte
	extProvider payload.Provider
	depth       uint16
}

// ExtensionVariantTaskConfig contains configuration for creating an ExtensionVariantTask.
// SchemeHost and Path are separated to prevent query params from being passed.
type ExtensionVariantTaskConfig struct {
	SchemeHost  []byte // scheme://host only (e.g., "http://example.com")
	Path        []byte // path only (e.g., "/api/v1/")
	Filename    []byte
	OriginalExt []byte
	FullName    []byte
	ExtProvider payload.Provider
	Depth       uint16
}

// NewExtensionVariantTask creates a new extension variant task.
func NewExtensionVariantTask(cfg *ExtensionVariantTaskConfig) *ExtensionVariantTask {
	return &ExtensionVariantTask{
		schemeHost:  copyBytes(cfg.SchemeHost),
		path:        copyBytes(cfg.Path),
		filename:    copyBytes(cfg.Filename),
		originalExt: copyBytes(cfg.OriginalExt),
		fullName:    copyBytes(cfg.FullName),
		extProvider: cfg.ExtProvider,
		depth:       cfg.Depth,
	}
}

// Hash returns a FNV-1a 64-bit hash for task deduplication.
func (e *ExtensionVariantTask) Hash() uint64 {
	h := fnv.New64a()

	h.Write([]byte{PriorityExtensionVariants})
	h.Write([]byte{0})

	// Hash schemeHost + path for deduplication
	h.Write(e.schemeHost)
	h.Write(e.path)
	h.Write([]byte{0})

	h.Write(e.fullName)
	h.Write([]byte{0})

	providerHash := e.extProvider.HashContent()
	_ = binary.Write(h, binary.LittleEndian, providerHash)

	return h.Sum64()
}

// Priority returns PriorityExtensionVariants (centralized in task.go).
func (e *ExtensionVariantTask) Priority() uint8 {
	return PriorityExtensionVariants
}

// Description returns a human-readable task description.
func (e *ExtensionVariantTask) Description() string {
	return fmt.Sprintf("Test extension variants on %s", string(e.fullName))
}

// FoundByName returns a short identifier for result attribution.
func (e *ExtensionVariantTask) FoundByName() string {
	return "ext-variant"
}

// PayloadProvider returns the provider for payload iteration.
func (e *ExtensionVariantTask) PayloadProvider() payload.Provider {
	return e.extProvider
}

// FullURL returns the full URL for this task (schemeHost + path).
func (e *ExtensionVariantTask) FullURL() []byte {
	result := make([]byte, 0, len(e.schemeHost)+len(e.path))
	result = append(result, e.schemeHost...)
	result = append(result, e.path...)
	return result
}

// Extension returns empty string (variants come from provider).
func (e *ExtensionVariantTask) Extension() string {
	return ""
}

// Depth returns the discovery depth.
func (e *ExtensionVariantTask) Depth() uint16 {
	return e.depth
}

// IsFromSpider returns false.
func (e *ExtensionVariantTask) IsFromSpider() bool { return false }

// Expand iterates over extension variants and generates URLs.
func (e *ExtensionVariantTask) Expand(ctx context.Context, callback func(url string, depth uint16)) error {
	if e.extProvider == nil {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		variant, err := e.extProvider.Next(ctx)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			continue
		}

		url := e.buildURL(variant)
		callback(url, e.depth)
	}
}

// buildURL constructs URL for extension variant testing.
// Format: schemeHost + path + filename.originalExt.variant
func (e *ExtensionVariantTask) buildURL(variant []byte) string {
	var buf bytes.Buffer
	buf.Write(e.schemeHost)
	buf.Write(e.path)

	// Add separator if path doesn't end with /
	if len(e.path) > 0 && e.path[len(e.path)-1] != '/' {
		buf.WriteByte('/')
	}

	buf.Write(e.filename)

	if len(e.originalExt) > 0 {
		buf.WriteByte('.')
		buf.Write(e.originalExt)
	}

	buf.WriteByte('.')
	buf.Write(variant)

	return buf.String()
}

// ShouldCreateVariantTask determines if an extension variant task should be created.
func ShouldCreateVariantTask(filename []byte) bool {
	lastDot := bytes.LastIndexByte(filename, '.')
	if lastDot == -1 || lastDot == 0 {
		return false
	}

	beforeLastDot := bytes.LastIndexByte(filename[:lastDot], '.')
	return beforeLastDot == -1
}

// ParseFilename splits a filename into name and extension.
func ParseFilename(filename []byte) (name []byte, ext []byte) {
	lastDot := bytes.LastIndexByte(filename, '.')
	if lastDot == -1 || lastDot == 0 {
		return filename, nil
	}

	return filename[:lastDot], filename[lastDot+1:]
}
