package builtin

import (
	"context"
	"regexp"
	"sync"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/module"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/module/wildcard"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/queue"
	"go.uber.org/zap"
)

// WildcardModule detects and handles wildcard prefix responses.
// Uses count-based detection: if N paths share the same prefix, assume wildcard.
//
// When a server returns responses for /admin, /adminxyz, /admin123,
// this module detects the pattern and blocks further tasks with that prefix.
type WildcardModule struct {
	*module.BaseModule

	// Track discovered paths by common prefix
	prefixTracker *wildcard.PrefixTracker

	// Threshold: if N paths with same prefix -> wildcard
	threshold int

	// Detected wildcard prefixes for blocking
	wildcardPrefixes sync.Map // map[string]struct{}

	logger *zap.Logger
}

// NewWildcardModule creates a new wildcard detection module.
func NewWildcardModule() *WildcardModule {
	// This module matches all paths (it observes everything)
	patterns := []module.Pattern{
		module.NewPattern(module.PatternPathRegex, ".*"),
	}

	return &WildcardModule{
		BaseModule: module.NewBaseModule(
			"wildcard",
			"Detect and block wildcard prefix responses",
			5, // Run early (before other modules)
			patterns,
		),
		prefixTracker: wildcard.NewPrefixTracker(),
		threshold:     3, // Need 3 paths with same prefix
		logger:        zap.NewNop(),
	}
}

// OnDirectoryMatch analyzes discovered directories for wildcard patterns.
func (m *WildcardModule) OnDirectoryMatch(ctx context.Context, event *module.DirectoryEvent) (*module.ModuleResult, error) {
	// Extract potential prefix from path
	prefix := m.prefixTracker.ExtractCommonPrefix(event.Path)
	if prefix == "" {
		// No common prefix found yet, just record this path
		// Use event.Path for both arguments since ExtractCommonPrefix compares paths
		m.prefixTracker.Add(event.Path, event.Path)
		return nil, nil
	}

	// Track this discovery with fingerprint
	// Use event.Path as fullPath for consistent path comparison
	stats := m.prefixTracker.AddWithFingerprint(prefix, event.Path, event.ResponseFingerprint)

	// Check if threshold reached
	if stats.Count >= m.threshold {
		// Check fingerprint similarity if we have fingerprints
		if m.allFingerprintsSimilar(stats) {
			m.logger.Warn("Wildcard prefix CONFIRMED",
				zap.String("prefix", prefix),
				zap.Int("count", stats.Count),
				zap.Float64("avg_similarity", stats.AvgSimilarity))

			// Mark as wildcard
			m.prefixTracker.MarkWildcard(prefix)
			m.wildcardPrefixes.Store(prefix, struct{}{})

			// Queue cleanup is handled by engine via QueueCleanup in result
			return &module.ModuleResult{
				StopRecursion:    true,
				SkipDefaultLogic: true,
				BlockTaskPatterns: []string{
					regexp.QuoteMeta(prefix) + ".*",
				},
				QueueCleanup: &module.QueueCleanupRequest{
					Pattern: regexp.QuoteMeta(prefix) + ".*",
					Action:  module.QueueActionRemoveKeepOne,
				},
			}, nil
		}
	}

	return nil, nil
}

// ShouldAddTask is called for EVERY task being added.
// Blocks tasks if their baseURL matches a known wildcard prefix.
func (m *WildcardModule) ShouldAddTask(task queue.TaskInfo) bool {
	baseURL := string(task.FullURL())

	// Check if this path matches any known wildcard prefix
	if m.prefixTracker.IsWildcard(baseURL) {
		m.logger.Debug("Task blocked by wildcard module",
			zap.String("baseURL", baseURL))
		return false
	}

	// Also check our local cache
	blocked := false
	m.wildcardPrefixes.Range(func(key, _ interface{}) bool {
		prefix, ok := key.(string)
		if !ok {
			return true
		}
		if len(baseURL) >= len(prefix) && baseURL[:len(prefix)] == prefix {
			blocked = true
			return false // Stop iteration
		}
		return true
	})

	return !blocked
}

// allFingerprintsSimilar checks if paths with same prefix indicate a wildcard.
// Uses count-based detection: if enough paths share the same prefix, assume wildcard.
func (m *WildcardModule) allFingerprintsSimilar(stats *wildcard.PrefixStats) bool {
	return stats.Count >= m.threshold
}

// SetThreshold sets the detection threshold.
func (m *WildcardModule) SetThreshold(threshold int) {
	m.threshold = threshold
}

// GetWildcardPrefixes returns all detected wildcard prefixes.
func (m *WildcardModule) GetWildcardPrefixes() []string {
	return m.prefixTracker.GetWildcardPrefixes()
}

// Stats returns module statistics.
func (m *WildcardModule) Stats() (prefixCount, wildcardCount int) {
	return m.prefixTracker.PrefixCount(), m.prefixTracker.WildcardCount()
}
