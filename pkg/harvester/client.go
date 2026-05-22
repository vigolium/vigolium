package harvester

import (
	"net/http"
	"net/url"
	"time"
)

// NewHTTPClient creates an HTTP client with optional proxy support, shared by
// harvester sources.
//
// Unlike scanner traffic — which deliberately tolerates broken/self-signed certs
// because targets often have them (see pkg/http) — harvester sources only query
// trusted third-party OSINT APIs (VirusTotal, urlscan.io, AlienVault OTX, Common
// Crawl, the Wayback Machine). So this client verifies TLS certificates using
// Go's secure default (no InsecureSkipVerify). Verification protects the API keys
// some sources put in the request (e.g. the VirusTotal apikey query parameter)
// and the integrity of harvested data against a man-in-the-middle.
func NewHTTPClient(timeout time.Duration, proxyURL string) *http.Client {
	transport := &http.Transport{}
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
