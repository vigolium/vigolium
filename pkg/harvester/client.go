package harvester

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"
)

// NewHTTPClient creates an HTTP client with optional proxy support.
// Used by harvester sources to share proxy configuration.
func NewHTTPClient(timeout time.Duration, proxyURL string) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if proxyURL != "" {
		if parsed, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(parsed)
		}
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}
