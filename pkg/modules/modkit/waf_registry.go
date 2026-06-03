package modkit

import (
	"strings"
	"sync"
)

// WAFRegistry tracks the WAF/CDN fronting each host, observed during a scan.
// XSS modules that hit a block response classify it (via pkg/deparos/waf) and
// publish the type here so later insertion points — and other modules on the
// same host — can pick WAF-specific evasion variants without re-detecting.
//
// One specific WAF per host is the common reality; a specific detection is
// never overwritten by the "generic" fallback. Thread-safe.
type WAFRegistry struct {
	mu     sync.RWMutex
	byHost map[string]string
}

// NewWAFRegistry returns an empty registry.
func NewWAFRegistry() *WAFRegistry {
	return &WAFRegistry{byHost: make(map[string]string)}
}

// Mark records that wafType was observed fronting host. Both are normalized to
// lowercase; empty values are a no-op. A previously recorded specific WAF is
// kept rather than being downgraded to "generic".
func (r *WAFRegistry) Mark(host, wafType string) {
	if r == nil {
		return
	}
	host = strings.ToLower(strings.TrimSpace(host))
	wafType = strings.ToLower(strings.TrimSpace(wafType))
	if host == "" || wafType == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.byHost[host]
	if !ok || existing == "" || (existing == "generic" && wafType != "generic") {
		r.byHost[host] = wafType
	}
}

// Get returns the WAF type recorded for host, or "" if none was observed.
func (r *WAFRegistry) Get(host string) string {
	if r == nil {
		return ""
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byHost[host]
}
