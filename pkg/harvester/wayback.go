package harvester

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

const (
	waybackBaseURL    = "http://web.archive.org"
	waybackTimeout    = 60 * time.Second
	waybackMaxRetries = 3
	waybackRetryDelay = 1 * time.Second
	waybackMaxBackoff = 4 * time.Second
)

// waybackAPIError represents an error from the Wayback Machine CDX API.
type waybackAPIError struct {
	StatusCode int
	Status     string
	URL        string
}

func (e *waybackAPIError) Error() string {
	return fmt.Sprintf("wayback API error: %s for %s", e.Status, e.URL)
}

// waybackClient fetches URLs from the Wayback Machine CDX API.
type waybackClient struct {
	httpClient *http.Client
	baseURL    string
	userAgent  string
	maxRetries int
	retryDelay time.Duration
	maxBackoff time.Duration
}

func newWaybackClient(proxyURL ...string) *waybackClient {
	var proxy string
	if len(proxyURL) > 0 {
		proxy = proxyURL[0]
	}
	return &waybackClient{
		httpClient: NewHTTPClient(waybackTimeout, proxy),
		baseURL:    waybackBaseURL,
		userAgent:  httpmsg.DefaultUserAgent(),
		maxRetries: waybackMaxRetries,
		retryDelay: waybackRetryDelay,
		maxBackoff: waybackMaxBackoff,
	}
}

// fetch retrieves historical URLs for the given domain from Wayback Machine.
// It streams results line-by-line and sends each URL string to the results channel.
func (c *waybackClient) fetch(ctx context.Context, domain string, results chan<- Result, sourceName string) error {
	if domain == "" {
		return errors.New("domain cannot be empty")
	}

	apiURL := fmt.Sprintf("%s/cdx/search/cdx?url=*.%s/*&output=txt&fl=original&collapse=urlkey",
		c.baseURL, domain)

	resp, err := c.fetchWithRetry(ctx, apiURL)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case results <- Result{Source: sourceName, URL: line}:
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	return nil
}

func (c *waybackClient) fetchWithRetry(ctx context.Context, apiURL string) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			delay := c.retryDelay * time.Duration(1<<(attempt-1))
			if delay > c.maxBackoff {
				delay = c.maxBackoff
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("User-Agent", c.userAgent)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden {
			lastErr = &waybackAPIError{
				StatusCode: resp.StatusCode,
				Status:     resp.Status,
				URL:        apiURL,
			}
			continue
		}

		return nil, &waybackAPIError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			URL:        apiURL,
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
	}

	return nil, errors.New("max retries exceeded")
}

// WaybackSource collects URLs from the Wayback Machine CDX API.
type WaybackSource struct {
	client *waybackClient
}

// NewWaybackSource creates a new Wayback Machine harvester source.
// proxyURL is optional; pass "" for no proxy.
func NewWaybackSource(proxyURL ...string) *WaybackSource {
	return &WaybackSource{
		client: newWaybackClient(proxyURL...),
	}
}

func (s *WaybackSource) Name() string   { return "wayback" }
func (s *WaybackSource) NeedsKey() bool { return false }

// Run fetches historical URLs for the domain from Wayback Machine.
func (s *WaybackSource) Run(ctx context.Context, domain string) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		if err := s.client.fetch(ctx, domain, results, s.Name()); err != nil {
			select {
			case <-ctx.Done():
			case results <- Result{Source: s.Name(), Error: err}:
			}
		}
	}()

	return results
}
