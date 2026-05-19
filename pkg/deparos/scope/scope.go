package scope

import (
	"net/url"
	"strings"

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

	// Check exclude patterns
	if s.matchesExcludePattern(u.String()) {
		return false
	}

	return true
}

// isHostInScope checks if the host matches the target.
func (s *Checker) isHostInScope(host string) bool {
	if s.config.TargetHost == "" {
		return true // No target host configured, allow all
	}

	hostLower := strings.ToLower(stripPort(host))

	switch s.config.Mode {
	case ModeAny:
		return true

	case ModeSubdomain:
		// Same main domain (eTLD+1)
		// e.g., target=www.example.com → allows api.example.com, example.com
		hostMainDomain, _ := publicsuffix.EffectiveTLDPlusOne(hostLower)
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
