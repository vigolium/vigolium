package modkit

import (
	"strings"
	"sync"
)

// TechRegistry tracks technology stack detections per host during a scan.
// Passive fingerprint modules publish detections (e.g. "nextjs", "spring") and
// the executor consults it before dispatching tech-gated active modules.
//
// Thread-safe for concurrent reads and writes.
type TechRegistry struct {
	mu     sync.RWMutex
	byHost map[string]map[string]struct{}

	// OnDetect fires exactly once per (host, tag) pair on first observation.
	// The callback runs without the registry lock held; implementations must
	// not call back into the registry from inside the callback.
	OnDetect func(host, tag string)
}

// NewTechRegistry returns an empty registry.
func NewTechRegistry() *TechRegistry {
	return &TechRegistry{byHost: make(map[string]map[string]struct{})}
}

// Mark records that the given tech tag was observed for host.
// Tag is normalized to lowercase. Empty host or tag is a no-op.
func (r *TechRegistry) Mark(host, tag string) {
	if r == nil {
		return
	}
	host = strings.ToLower(strings.TrimSpace(host))
	tag = strings.ToLower(strings.TrimSpace(tag))
	if host == "" || tag == "" {
		return
	}
	r.mu.Lock()
	set, ok := r.byHost[host]
	if !ok {
		set = make(map[string]struct{})
		r.byHost[host] = set
	}
	_, already := set[tag]
	if !already {
		set[tag] = struct{}{}
	}
	r.mu.Unlock()
	if !already && r.OnDetect != nil {
		r.OnDetect(host, tag)
	}
}

// Has reports whether the given tech tag is detected for host.
func (r *TechRegistry) Has(host, tag string) bool {
	if r == nil {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	tag = strings.ToLower(strings.TrimSpace(tag))
	if host == "" || tag == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	set, ok := r.byHost[host]
	if !ok {
		return false
	}
	_, ok = set[tag]
	return ok
}

// HasAny reports whether any of the given tech tags is detected for host.
// Returns false when tags is empty.
func (r *TechRegistry) HasAny(host string, tags []string) bool {
	if r == nil || len(tags) == 0 {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	set, ok := r.byHost[host]
	if !ok || len(set) == 0 {
		return false
	}
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if _, ok := set[t]; ok {
			return true
		}
	}
	return false
}

// Allows is the dispatch-hot-path query: returns true iff the host is unknown
// (fail-open) OR has at least one of the candidate tech tags. Candidates MUST
// already be normalized (lowercase, trimmed, non-empty) — passing raw input
// here will silently miss matches.
//
// Combining the host-known and any-match check under a single RLock is the
// hot-path's primary cost saving: one map lookup, no double normalization.
func (r *TechRegistry) Allows(host string, candidates []string) bool {
	if r == nil || host == "" || len(candidates) == 0 {
		return true
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	set, ok := r.byHost[host]
	if !ok || len(set) == 0 {
		return true // fail-open: host unknown
	}
	for _, t := range candidates {
		if _, ok := set[t]; ok {
			return true
		}
	}
	return false
}

// HostKnown reports whether any tech has been detected for host yet.
func (r *TechRegistry) HostKnown(host string) bool {
	if r == nil {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	set, ok := r.byHost[host]
	return ok && len(set) > 0
}
