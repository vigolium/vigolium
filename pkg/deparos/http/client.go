package http

import (
	"context"
	"fmt"
	nethttp "net/http"
	"time"

	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// Client wraps nethttp.Client with middleware chain support.
// Implements the HTTPClient interface.
type Client struct {
	client     *nethttp.Client
	middleware []Middleware
}

// Middleware represents an HTTP middleware function.
// It wraps an nethttp.RoundTripper to add functionality (retry, timeout, rate-limit).
type Middleware func(nethttp.RoundTripper) nethttp.RoundTripper

// ClientConfig configures the HTTP client.
type ClientConfig struct {
	// PoolConfig configures connection pooling
	PoolConfig *PoolConfig

	// Middleware chain (applied in order)
	Middleware []Middleware

	// MaxRedirects limits the number of redirects to follow
	// 0 means no redirects, -1 means unlimited
	// Default: 10
	MaxRedirects int

	// DisableAutoRedirect completely disables automatic redirect following
	// When true, the client will return the redirect response instead of following it
	// This allows manual redirect handling for trailing slash detection
	DisableAutoRedirect bool

	// RequestTimeout is the maximum duration for a request (entire round trip).
	// Default: 0 (no timeout) unless provided by caller (e.g., config.Engine.Timeout).
	RequestTimeout time.Duration

	// Jar specifies the cookie jar for storing and sending cookies.
	// If nil, cookies are not sent with requests and not stored from responses.
	Jar nethttp.CookieJar
}

// DefaultClientConfig returns default client configuration.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		PoolConfig:   DefaultPoolConfig(),
		Middleware:   []Middleware{},
		MaxRedirects: 10,
		// RequestTimeout defaults to 0 (use nethttp.Client default) so we defer to caller configuration.
	}
}

// NewClient creates a new HTTP client with the specified configuration.
func NewClient(config *ClientConfig) *Client {
	if config == nil {
		config = DefaultClientConfig()
	}
	if config.PoolConfig == nil {
		config.PoolConfig = DefaultPoolConfig()
	}

	// Create base transport
	transport := config.PoolConfig.NewTransport()

	// Apply middleware chain (reverse order so they execute in config order)
	var rt nethttp.RoundTripper = transport
	for i := len(config.Middleware) - 1; i >= 0; i-- {
		rt = config.Middleware[i](rt)
	}

	// Create nethttp.Client
	client := &nethttp.Client{
		Transport: rt,
		Timeout:   config.RequestTimeout,
		Jar:       config.Jar,
		CheckRedirect: func(req *nethttp.Request, via []*nethttp.Request) error {
			// If auto-redirect is disabled, never follow redirects
			if config.DisableAutoRedirect {
				return nethttp.ErrUseLastResponse
			}
			// Follow redirects up to MaxRedirects
			if config.MaxRedirects >= 0 && len(via) >= config.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", config.MaxRedirects)
			}
			return nil
		},
	}

	return &Client{
		client:     client,
		middleware: config.Middleware,
	}
}

// HTTPClient returns the underlying *nethttp.Client.
// This is useful for components that need direct access to the standard library client.
func (c *Client) HTTPClient() *nethttp.Client {
	return c.client
}

// Send sends an HTTP request and returns a ResponseChain.
// Implements domainhttp.HTTPClient interface.
// CRITICAL: Caller MUST call Close() on the returned ResponseChain when done.
func (c *Client) Send(ctx context.Context, req *nethttp.Request) (*responsechain.ResponseChain, error) {
	// Set default User-Agent if not already set (Chrome-like for WAF bypass)
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	}

	// Execute request
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, &RequestError{
			URL: req.URL.String(),
			Err: err,
		}
	}

	// Create ResponseChain and fill buffers
	rc := responsechain.NewResponseChain(resp, 0)
	if err := rc.Fill(); err != nil {
		rc.Close()
		return nil, &RequestError{
			URL: req.URL.String(),
			Err: err,
		}
	}

	return rc, nil // Caller owns rc, MUST call Close()
}
