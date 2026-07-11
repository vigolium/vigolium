package scope

import (
	"net"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"
)

// Mode defines how URL scope validation behaves.
type Mode string

const (
	ModeAny       Mode = "any"       // No scope checking, allow all URLs
	ModeSubdomain Mode = "subdomain" // Same main domain (eTLD+1) - e.g., example.com
	ModeExact     Mode = "exact"     // Exact host match only - e.g., api.example.com
)

// Config defines the scope configuration for URL filtering.
type Config struct {
	// TargetHost is the primary host being scanned
	TargetHost string

	// Mode is the scope checking mode
	Mode Mode

	// ExcludePatterns are URL patterns to exclude (simple substring matching)
	ExcludePatterns []string
}

// Checker validates URL scope.
type Checker struct {
	config           Config
	targetMainDomain string // eTLD+1 of target (e.g., example.com)

	// hostScope memoizes isHostInScope by raw host. IsInScope runs per
	// discovered link/JS-URL/form-action/redirect, almost always for the same
	// handful of hosts, so caching avoids recomputing the eTLD+1 public-suffix
	// lookup (and the lowercase/strip-port) on every call. A scope run touches
	// a bounded host set, so unbounded growth isn't a concern.
	hostScope sync.Map // host(string) → bool
}

// NewChecker creates a new scope checker with the given configuration.
func NewChecker(config Config) *Checker {
	// Normalize target host
	targetHost := strings.ToLower(stripPort(config.TargetHost))
	config.TargetHost = targetHost

	// Extract main domain (eTLD+1) for subdomain mode
	mainDomain, _ := publicsuffix.EffectiveTLDPlusOne(targetHost)

	return &Checker{
		config:           config,
		targetMainDomain: mainDomain,
	}
}

// IsInScope returns true if the URL should be included in discovery.
func (s *Checker) IsInScope(u *url.URL) bool {
	if u == nil {
		return false
	}

	// Any mode (or unset) - allow all URLs
	if s.config.Mode == ModeAny || s.config.Mode == "" {
		return true
	}

	// Check host
	if !s.isHostInScope(u.Host) {
		return false
	}

	// Check exclude patterns (only serialize the URL when there are patterns).
	if len(s.config.ExcludePatterns) > 0 && s.matchesExcludePattern(u.String()) {
		return false
	}

	return true
}

// isHostInScope checks if the host matches the target, memoizing the decision on
// the normalized (lowercased, port-stripped) host so the eTLD+1 lookup runs at
// most once per distinct host and case/port variants collapse to one entry.
func (s *Checker) isHostInScope(host string) bool {
	if s.config.TargetHost == "" {
		return true // No target host configured, allow all
	}

	key := strings.ToLower(stripPort(host))
	if v, ok := s.hostScope.Load(key); ok {
		return v.(bool)
	}
	result := s.computeHostInScope(key)
	s.hostScope.Store(key, result)
	return result
}

// computeHostInScope performs the actual (uncached) host scope decision on an
// already-normalized (lowercased, port-stripped) host.
func (s *Checker) computeHostInScope(hostLower string) bool {
	switch s.config.Mode {
	case ModeAny:
		return true

	case ModeSubdomain:
		// Same main domain (eTLD+1)
		// e.g., target=www.example.com → allows api.example.com, example.com
		//
		// IPs and single-label hosts (localhost) have no meaningful eTLD+1 —
		// publicsuffix maps BOTH 127.0.0.1 and 192.168.0.1 to "0.1" (last label
		// treated as an unmanaged TLD), which would wrongly place unrelated
		// addresses in the same scope, and an unparseable host yields "" that
		// matches any other "" host. Compare such hosts EXACTLY instead.
		if isIPOrLocalhost(hostLower) || isIPOrLocalhost(s.config.TargetHost) {
			return hostLower == s.config.TargetHost
		}
		hostMainDomain, err := publicsuffix.EffectiveTLDPlusOne(hostLower)
		if err != nil || hostMainDomain == "" || s.targetMainDomain == "" {
			return hostLower == s.config.TargetHost
		}
		return hostMainDomain == s.targetMainDomain

	case ModeExact:
		// Exact host match only
		// e.g., target=api.example.com → allows ONLY api.example.com
		// NOT admin.api.example.com (child subdomain), NOT www.example.com (sibling)
		return hostLower == s.config.TargetHost
	}

	return false
}

// matchesExcludePattern checks if the URL matches any exclude pattern.
func (s *Checker) matchesExcludePattern(urlStr string) bool {
	for _, pattern := range s.config.ExcludePatterns {
		if strings.Contains(urlStr, pattern) {
			return true
		}
	}
	return false
}

// isIPOrLocalhost reports whether host is an IP literal (v4 or v6) or
// "localhost" — hosts with no meaningful public-suffix/eTLD+1 that must be
// scope-compared exactly rather than by main domain. host is expected already
// lowercased and port-stripped.
func isIPOrLocalhost(host string) bool {
	if host == "localhost" {
		return true
	}
	// stripPort leaves IPv6 literals bracketed (e.g. "[::1]"); net.ParseIP wants
	// the bare address.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	return net.ParseIP(host) != nil
}

// stripPort removes the port from a host string.
func stripPort(host string) string {
	// Handle IPv6 addresses
	if strings.HasPrefix(host, "[") {
		if idx := strings.LastIndex(host, "]:"); idx != -1 {
			return host[:idx+1]
		}
		return host
	}

	// Handle IPv4 and hostnames
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}

	return host
}
