package storage

import (
	"net/url"
	"strconv"
	"strings"
)

// HostnameInfo contains parsed hostname components
type HostnameInfo struct {
	Full     string // Full host:port string (original)
	Hostname string // Hostname only (lowercase)
	Port     int    // Port number (always populated: 443 for https, 80 for http, or explicit port)
}

// ParseHostname extracts hostname components from a URL.
// Port normalization - always returns actual port:
//   - https without port → Port=443
//   - https://example.com:443 → Port=443
//   - https://example.com:8443 → Port=8443
//   - http without port → Port=80
//   - http://example.com:80 → Port=80
//   - http://example.com:8080 → Port=8080
func ParseHostname(u *url.URL) HostnameInfo {
	if u == nil {
		return HostnameInfo{}
	}

	info := HostnameInfo{
		Full:     u.Host,
		Hostname: strings.ToLower(u.Hostname()),
	}

	// Extract port - always populate with actual value
	portStr := u.Port()
	if portStr != "" {
		info.Port, _ = strconv.Atoi(portStr)
	} else {
		// Infer from scheme
		switch strings.ToLower(u.Scheme) {
		case "https":
			info.Port = 443
		case "http":
			info.Port = 80
		default:
			info.Port = 0 // Unknown scheme
		}
	}

	return info
}

// ParseHostnameFromURL extracts hostname from a URL string
func ParseHostnameFromURL(urlStr string) HostnameInfo {
	u, err := url.Parse(urlStr)
	if err != nil {
		return HostnameInfo{}
	}
	return ParseHostname(u)
}

// ExtractHostname is a convenience function that returns just the hostname string
func ExtractHostname(urlStr string) string {
	return ParseHostnameFromURL(urlStr).Hostname
}
