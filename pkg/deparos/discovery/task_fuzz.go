package discovery

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"io"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
)

// FuzzTask replaces the FUZZ marker in a URL template with each word from a wordlist.
// Unlike WordlistTask (which appends words to a base path), FuzzTask performs
// string replacement anywhere in the URL — path, query, or fragment.
//
// Task is immutable configuration - execution is handled by PayloadCoordinator.
// Hash is computed once at creation time to ensure deterministic deduplication.
type FuzzTask struct {
	urlTemplate string // URL containing FUZZ marker (e.g., "http://example.com/FUZZ/page")
	provider    payload.Provider
	depth       uint16
	cachedHash  uint64
}

// FuzzTaskConfig contains configuration for creating a FuzzTask.
type FuzzTaskConfig struct {
	URLTemplate string
	Provider    payload.Provider
	Depth       uint16
}

// NewFuzzTask creates a new fuzz task with cached hash.
func NewFuzzTask(cfg *FuzzTaskConfig) *FuzzTask {
	task := &FuzzTask{
		urlTemplate: cfg.URLTemplate,
		provider:    cfg.Provider,
		depth:       cfg.Depth,
	}
	task.cachedHash = task.computeHash()
	return task
}

// Hash returns the cached hash computed at creation time.
func (t *FuzzTask) Hash() uint64 {
	return t.cachedHash
}

// Priority returns PriorityFuzzer (12) — lowest priority, runs after all other wordlists.
func (t *FuzzTask) Priority() uint8 {
	return PriorityFuzzer
}

// Description returns a human-readable task description.
func (t *FuzzTask) Description() string {
	return "Fuzz URL template with custom wordlist"
}

// FoundByName returns "fuzzer" for result attribution.
func (t *FuzzTask) FoundByName() string {
	return "fuzzer"
}

// PayloadProvider returns the provider for payload iteration.
func (t *FuzzTask) PayloadProvider() payload.Provider {
	return t.provider
}

// FullURL returns the URL template as bytes.
func (t *FuzzTask) FullURL() []byte {
	return []byte(t.urlTemplate)
}

// Extension returns empty string — FuzzTask doesn't use extensions.
func (t *FuzzTask) Extension() string {
	return ""
}

// Depth returns the discovery depth.
func (t *FuzzTask) Depth() uint16 {
	return t.depth
}

// IsFromSpider returns false.
func (t *FuzzTask) IsFromSpider() bool { return false }

// Expand iterates over wordlist payloads, replacing FUZZ in the URL template.
func (t *FuzzTask) Expand(ctx context.Context, callback func(url string, depth uint16)) error {
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
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			continue
		}

		replaced := strings.ReplaceAll(t.urlTemplate, "FUZZ", string(word))

		// Validate the resulting URL
		if _, err := url.Parse(replaced); err != nil {
			continue
		}

		callback(replaced, t.depth)
	}
}

// computeHash computes the hash once at creation time.
func (t *FuzzTask) computeHash() uint64 {
	h := fnv.New64a()

	h.Write([]byte("fuzz:"))
	h.Write([]byte(t.urlTemplate))
	h.Write([]byte{0})

	providerHash := t.provider.HashContent()
	_ = binary.Write(h, binary.LittleEndian, providerHash)

	return h.Sum64()
}
