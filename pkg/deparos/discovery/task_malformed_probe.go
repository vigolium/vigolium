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

// MalformedPathProbeTask replaces the FUZZ marker in a URL template with each
// payload from the embedded fuzz.txt wordlist. Unlike FuzzTask (which runs only
// against the start URL at priority 12), MalformedPathProbeTask runs against
// every discovered directory at priority 10.
//
// Payloads include path traversals, dotfiles, sensitive config files, backup
// probes, etc. The FUZZ replacement preserves malformed paths as-is (no slash
// trimming).
type MalformedPathProbeTask struct {
	urlTemplate string // URL containing FUZZ marker (e.g., "http://example.com/app/FUZZ")
	provider    payload.Provider
	depth       uint16
	cachedHash  uint64
}

// MalformedPathProbeTaskConfig contains configuration for creating a MalformedPathProbeTask.
type MalformedPathProbeTaskConfig struct {
	URLTemplate string
	Provider    payload.Provider
	Depth       uint16
}

// NewMalformedPathProbeTask creates a new malformed path probe task with cached hash.
func NewMalformedPathProbeTask(cfg *MalformedPathProbeTaskConfig) *MalformedPathProbeTask {
	task := &MalformedPathProbeTask{
		urlTemplate: cfg.URLTemplate,
		provider:    cfg.Provider,
		depth:       cfg.Depth,
	}
	task.cachedHash = task.computeHash()
	return task
}

// Hash returns the cached hash computed at creation time.
func (t *MalformedPathProbeTask) Hash() uint64 {
	return t.cachedHash
}

// Priority returns PriorityMalformedPathProbe (10).
func (t *MalformedPathProbeTask) Priority() uint8 {
	return PriorityMalformedPathProbe
}

// Description returns a human-readable task description.
func (t *MalformedPathProbeTask) Description() string {
	return "Malformed path probe (fuzz.txt)"
}

// FoundByName returns "malformed-path-probe" for result attribution.
func (t *MalformedPathProbeTask) FoundByName() string {
	return "malformed-path-probe"
}

// PayloadProvider returns the provider for payload iteration.
func (t *MalformedPathProbeTask) PayloadProvider() payload.Provider {
	return t.provider
}

// FullURL returns the URL template as bytes.
func (t *MalformedPathProbeTask) FullURL() []byte {
	return []byte(t.urlTemplate)
}

// Extension returns empty string - MalformedPathProbeTask doesn't use extensions.
func (t *MalformedPathProbeTask) Extension() string {
	return ""
}

// Depth returns the discovery depth.
func (t *MalformedPathProbeTask) Depth() uint16 {
	return t.depth
}

// IsFromSpider returns false.
func (t *MalformedPathProbeTask) IsFromSpider() bool { return false }

// Expand iterates over payloads, replacing FUZZ in the URL template.
func (t *MalformedPathProbeTask) Expand(ctx context.Context, callback func(url string, depth uint16)) error {
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

		replaced := strings.ReplaceAll(t.urlTemplate, fuzzMarker, string(word))

		// Validate the resulting URL
		if _, err := url.Parse(replaced); err != nil {
			continue
		}

		callback(replaced, t.depth)
	}
}

// computeHash computes the hash once at creation time.
func (t *MalformedPathProbeTask) computeHash() uint64 {
	h := fnv.New64a()

	h.Write([]byte("malformed-path-probe:"))
	h.Write([]byte(t.urlTemplate))
	h.Write([]byte{0})

	providerHash := t.provider.HashContent()
	_ = binary.Write(h, binary.LittleEndian, providerHash)

	return h.Sum64()
}
