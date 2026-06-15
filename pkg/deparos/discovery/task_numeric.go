package discovery

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"strconv"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
)

// NumericFuzzTask tests numeric parameters by incrementing/decrementing.
// Task is immutable configuration - execution is handled by PayloadCoordinator.
// Priority is always 7.
//
// Note: NumericFuzzTask uses a special provider that generates ±10 values.
// The coordinator processes these values concurrently.
type NumericFuzzTask struct {
	baseURL       []byte // scheme://host
	pathTemplate  []byte // path only (offsets are relative to this)
	suffix        []byte
	extension     []byte
	originalValue int
	startOffset   int
	endOffset     int
	depth         uint16
	provider      payload.Provider
}

// NumericFuzzTaskConfig contains configuration for creating a NumericFuzzTask.
type NumericFuzzTaskConfig struct {
	BaseURL       []byte // scheme://host
	PathTemplate  []byte // path only (offsets are relative to this)
	Suffix        []byte
	Extension     []byte
	OriginalValue int
	StartOffset   int
	EndOffset     int
	Depth         uint16
}

// NewNumericFuzzTask creates a new numeric fuzzing task.
func NewNumericFuzzTask(cfg *NumericFuzzTaskConfig) *NumericFuzzTask {
	// Generate values: original-10 to original+10 (excluding original)
	values := make([][]byte, 0, 20)
	minValue := cfg.OriginalValue - 10
	if minValue < 0 {
		minValue = 0
	}
	maxValue := cfg.OriginalValue + 10

	for v := minValue; v <= maxValue; v++ {
		if v != cfg.OriginalValue {
			values = append(values, []byte(strconv.Itoa(v)))
		}
	}

	return &NumericFuzzTask{
		baseURL:       copyBytes(cfg.BaseURL),
		pathTemplate:  copyBytes(cfg.PathTemplate),
		suffix:        copyBytes(cfg.Suffix),
		extension:     copyBytes(cfg.Extension),
		originalValue: cfg.OriginalValue,
		startOffset:   cfg.StartOffset,
		endOffset:     cfg.EndOffset,
		depth:         cfg.Depth,
		provider:      payload.NewStaticProvider(values),
	}
}

// Hash returns a FNV-1a 64-bit hash for task deduplication.
func (n *NumericFuzzTask) Hash() uint64 {
	h := fnv.New64a()

	h.Write([]byte{PriorityNumericFuzz})
	h.Write([]byte{0})

	h.Write(n.baseURL)
	h.Write([]byte{0})

	h.Write(n.pathTemplate)
	h.Write([]byte{0})

	_ = binary.Write(h, binary.LittleEndian, int64(n.originalValue))

	return h.Sum64()
}

// Priority returns PriorityNumericFuzz (centralized in task.go).
func (n *NumericFuzzTask) Priority() uint8 {
	return PriorityNumericFuzz
}

// Description returns a human-readable task description.
func (n *NumericFuzzTask) Description() string {
	return fmt.Sprintf("Test numeric variants on %s", strconv.Itoa(n.originalValue))
}

// FoundByName returns a short identifier for result attribution.
func (n *NumericFuzzTask) FoundByName() string {
	return "numeric"
}

// PayloadProvider returns the provider for numeric values.
func (n *NumericFuzzTask) PayloadProvider() payload.Provider {
	return n.provider
}

// FullURL returns the full URL (scheme://host + path).
func (n *NumericFuzzTask) FullURL() []byte {
	result := make([]byte, 0, len(n.baseURL)+len(n.pathTemplate))
	result = append(result, n.baseURL...)
	result = append(result, n.pathTemplate...)
	return result
}

// Extension returns empty string (numeric fuzzing doesn't add extensions).
func (n *NumericFuzzTask) Extension() string {
	return ""
}

// Depth returns the discovery depth.
func (n *NumericFuzzTask) Depth() uint16 {
	return n.depth
}

// IsFromSpider returns false.
func (n *NumericFuzzTask) IsFromSpider() bool { return false }

// Expand iterates over numeric values and generates URLs.
func (n *NumericFuzzTask) Expand(ctx context.Context, callback func(url string, depth uint16)) error {
	if n.provider == nil {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		value, err := n.provider.Next(ctx)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			continue
		}

		urlBytes := n.buildURL(value)
		callback(string(urlBytes), n.depth)
	}
}

// buildURL constructs the full URL with the given numeric value.
func (n *NumericFuzzTask) buildURL(value []byte) []byte {
	var buf bytes.Buffer
	buf.Write(n.baseURL)
	buf.Write(n.pathTemplate[:n.startOffset])
	buf.Write(value)
	buf.Write(n.pathTemplate[n.endOffset:])

	if len(n.extension) > 0 {
		buf.WriteByte('.')
		buf.Write(n.extension)
	}

	buf.Write(n.suffix)
	return []byte(collapseDoubleSlashes(buf.String()))
}

// FindNumericParameter searches for a numeric parameter in a path.
func FindNumericParameter(path []byte) (startOffset int, endOffset int, value int, found bool) {
	start := -1
	for i := 0; i < len(path); i++ {
		if path[i] >= '0' && path[i] <= '9' {
			if start == -1 {
				start = i
			}
		} else {
			if start != -1 {
				numStr := string(path[start:i])
				if num, err := strconv.Atoi(numStr); err == nil {
					return start, i, num, true
				}
				start = -1
			}
		}
	}

	if start != -1 {
		numStr := string(path[start:])
		if num, err := strconv.Atoi(numStr); err == nil {
			return start, len(path), num, true
		}
	}

	return 0, 0, 0, false
}
