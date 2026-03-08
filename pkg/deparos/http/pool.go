// Package http provides HTTP client infrastructure with middleware support.
package http

import (
	"crypto/tls"
	"net"
	nethttp "net/http"
	"net/url"
	"time"
)

// PoolConfig defines connection pool configuration for the HTTP client.
// Matches Burp Suite's connection pool behavior (cq5.java).
type PoolConfig struct {
	// MaxIdleConns controls the maximum number of idle connections across all hosts.
	// Burp default: 100
	MaxIdleConns int

	// MaxIdleConnsPerHost controls the maximum idle connections per host.
	// Burp default: 10
	MaxIdleConnsPerHost int

	// IdleConnTimeout is the maximum time an idle connection will remain idle before closing.
	// Default: 90 seconds
	IdleConnTimeout time.Duration

	// DialTimeout is the maximum time to wait for a dial to complete.
	// Default: 30 seconds
	DialTimeout time.Duration

	// KeepAlive specifies the interval between keep-alive probes.
	// Default: 30 seconds
	KeepAlive time.Duration

	// TLSHandshakeTimeout specifies the maximum time waiting for a TLS handshake.
	// Default: 10 seconds
	TLSHandshakeTimeout time.Duration

	// DisableTLSVerification disables TLS certificate verification.
	// Should be true for content discovery to test arbitrary targets.
	DisableTLSVerification bool

	// ResponseHeaderTimeout specifies the maximum time to wait for a server's
	// response headers after fully writing the request.
	// Default: 0 (no timeout)
	ResponseHeaderTimeout time.Duration

	// ExpectContinueTimeout specifies the maximum time to wait for a server's
	// first response headers after fully writing the request headers if the
	// request has an "Expect: 100-continue" header.
	// Default: 1 second
	ExpectContinueTimeout time.Duration

	// ProxyURL is the HTTP proxy URL to route all requests through.
	// Empty string means no proxy.
	ProxyURL string
}

// DefaultPoolConfig returns the default connection pool configuration.
// Matches Burp Suite's defaults from cq5.java.
func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		MaxIdleConns:           100,
		MaxIdleConnsPerHost:    10,
		IdleConnTimeout:        90 * time.Second,
		DialTimeout:            30 * time.Second,
		KeepAlive:              30 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		DisableTLSVerification: true, // Required for content discovery
		ResponseHeaderTimeout:  0,
		ExpectContinueTimeout:  1 * time.Second,
	}
}

// NewTransport creates an nethttp.Transport with the specified pool configuration.
func (c *PoolConfig) NewTransport() *nethttp.Transport {
	t := &nethttp.Transport{
		// Connection pooling
		MaxIdleConns:        c.MaxIdleConns,
		MaxIdleConnsPerHost: c.MaxIdleConnsPerHost,
		IdleConnTimeout:     c.IdleConnTimeout,

		// Dialer configuration
		DialContext: (&net.Dialer{
			Timeout:   c.DialTimeout,
			KeepAlive: c.KeepAlive,
		}).DialContext,

		// TLS configuration
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: c.DisableTLSVerification,
		},
		TLSHandshakeTimeout: c.TLSHandshakeTimeout,

		// Timeouts
		ResponseHeaderTimeout: c.ResponseHeaderTimeout,
		ExpectContinueTimeout: c.ExpectContinueTimeout,

		// Force HTTP/1.1 for compatibility (Burp behavior)
		ForceAttemptHTTP2: false,
	}

	if c.ProxyURL != "" {
		if parsed, err := url.Parse(c.ProxyURL); err == nil {
			t.Proxy = nethttp.ProxyURL(parsed)
		}
	}

	return t
}
