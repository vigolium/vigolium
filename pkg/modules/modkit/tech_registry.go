package modkit

import (
	"sort"
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// RegistryHostKey returns the per-host key used by every registry in this
// package — TechRegistry, ContentClassRegistry, WAFRegistry. It is the URL host:
// the bare hostname plus ":port" for non-default ports.
//
// Read and write paths MUST agree on this key or detections silently go missing,
// so it lives here rather than being re-derived per caller. The port is part of
// the key on purpose: keying on the bare hostname let a stack detected on :443
// gate modules on :8443 and dropped every non-default-port detection outright.
// Falls back to the bare service host only when the URL cannot be parsed.
func RegistryHostKey(item *httpmsg.HttpRequestResponse) string {
	if item == nil {
		return ""
	}
	if u, err := item.URL(); err == nil && u != nil && u.Host != "" {
		return u.Host
	}
	if svc := item.Service(); svc != nil {
		return svc.Host()
	}
	return ""
}

// TechRegistry tracks technology detections per host during a scan. Passive
// fingerprint modules publish detections (e.g. "nextjs", "spring") and the
// executor consults it before dispatching tech-gated active modules.
//
// Each host keeps two sets: STACK tags (IsStackTag: frameworks, languages,
// platforms, servers — what the gate reasons about) and DESCRIPTIVE tags
// (spa, angular, javascript, … — recorded, never gating). Mark routes a tag to
// the right set. A host is "known" only once it has a stack tag: an Angular
// front end publishing {angular, spa} says nothing about the backend, and
// gating on it used to skip every Spring/Java module on an Angular-on-Spring
// host (MISS-21).
//
// Thread-safe for concurrent reads and writes.
type TechRegistry struct {
	mu     sync.RWMutex
	byHost *lru.Cache[string, *hostTech] // bounded: see perHostRegistryCacheSize

	// OnDetect fires exactly once per (host, tag) pair on first observation.
	// The callback runs without the registry lock held; implementations must
	// not call back into the registry from inside the callback.
	OnDetect func(host, tag string)
}

// hostTech is one host's detections.
type hostTech struct {
	stack map[string]struct{}
	desc  map[string]struct{}
}

func (h *hostTech) has(tag string) bool {
	if _, ok := h.stack[tag]; ok {
		return true
	}
	_, ok := h.desc[tag]
	return ok
}

// NewTechRegistry returns an empty registry. The host map is a bounded LRU so a
// long-lived executor can't grow it per distinct host without limit; an evicted
// host simply reads as unknown (fail-open) until re-fingerprinted.
func NewTechRegistry() *TechRegistry {
	c, _ := lru.New[string, *hostTech](perHostRegistryCacheSize)
	return &TechRegistry{byHost: c}
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
	ht, ok := r.byHost.Get(host)
	if !ok {
		ht = &hostTech{stack: make(map[string]struct{}), desc: make(map[string]struct{})}
		r.byHost.Add(host, ht)
	}
	set := ht.desc
	if IsStackTag(tag) {
		set = ht.stack
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

// Has reports whether the given tech tag (stack or descriptive) is detected for host.
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
	// Peek, not Get: Get takes the LRU's internal write lock to bump recency,
	// which would serialize concurrent read-only queries despite the outer RLock.
	ht, ok := r.byHost.Peek(host)
	if !ok {
		return false
	}
	return ht.has(tag)
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
	ht, ok := r.byHost.Peek(host) // Peek: see Has (avoid LRU write-lock on the read path)
	if !ok {
		return false
	}
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if ht.has(t) {
			return true
		}
	}
	return false
}

// Allows is the dispatch-hot-path query. Candidates are the module's required
// stack tags and MUST already be normalized (lowercase, trimmed, non-empty).
//
// It returns false (skip the module) only on a positive contradiction: the
// host has a stack tag in the category of one of the candidates, and none of
// the candidates is detected on the host. Every other case runs the module —
// an unknown host, a host known only by descriptive tags, a host whose known
// stack is in another category (a Next.js front end says nothing about the
// backend), and server tags (a reverse proxy's banner never excludes).
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
	ht, ok := r.byHost.Peek(host) // Peek: see Has (avoid LRU write-lock on the read path)
	if !ok || len(ht.stack) == 0 {
		return true // fail-open: stack unknown
	}
	for _, t := range candidates {
		if _, ok := ht.stack[t]; ok {
			return true
		}
	}
	// No candidate matched. Skip only when the host is positively identified
	// in one of the candidates' (exclusive) categories.
	for _, t := range candidates {
		cat := TechCategoryOf(t)
		if cat == "" || cat == TechCategoryServer {
			continue
		}
		for have := range ht.stack {
			if TechCategoryOf(have) == cat {
				return false
			}
		}
	}
	return true
}

// Tags returns every tech tag detected for host (stack and descriptive),
// sorted, or nil when the host is unknown. Sorted because the result is
// persisted to http_records.technology and exported: an unstable order would
// make two identical scans diff.
//
// The returned slice is a copy - the registry's own sets stay private, so a
// caller cannot mutate another module's gating data by holding onto it.
func (r *TechRegistry) Tags(host string) []string {
	if r == nil {
		return nil
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil
	}
	r.mu.RLock()
	ht, ok := r.byHost.Peek(host) // Peek: see Has (avoid LRU write-lock on the read path)
	if !ok || len(ht.stack)+len(ht.desc) == 0 {
		r.mu.RUnlock()
		return nil
	}
	tags := make([]string, 0, len(ht.stack)+len(ht.desc))
	for tag := range ht.stack {
		tags = append(tags, tag)
	}
	for tag := range ht.desc {
		tags = append(tags, tag)
	}
	r.mu.RUnlock()
	sort.Strings(tags)
	return tags
}

// HostKnown reports whether a STACK tag has been detected for host yet.
// Descriptive tags (spa, angular, …) do not make a host known.
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
	ht, ok := r.byHost.Peek(host)
	return ok && len(ht.stack) > 0
}
