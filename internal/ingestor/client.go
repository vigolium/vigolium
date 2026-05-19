package ingestor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// IngestRequest is the request body for remote ingestion via POST /api/ingest-http.
type IngestRequest struct {
	URL           string            `json:"url,omitempty"`
	Request       *IngestRawRequest `json:"request,omitempty"`
	EnableModules []string          `json:"enable_modules,omitempty"`
	WebhookURL    string            `json:"webhook_url,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// IngestRawRequest holds a raw HTTP request for remote ingestion.
type IngestRawRequest struct {
	Raw string `json:"raw,omitempty"`
}

// IngestResponse is the response for remote ingestion requests.
type IngestResponse struct {
	TaskID    string `json:"task_id"`
	Status    string `json:"status"`
	QueueSize int64  `json:"queue_size,omitempty"`
	Message   string `json:"message,omitempty"`
}

// ErrorResponse is returned for error conditions.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// Client is an HTTP client for the Vigolium server API.
type Client struct {
	baseURL     string
	apiKey      string
	httpClient  *http.Client
	rateLimiter *rate.Limiter
}

// NewClient creates a new Vigolium API client.
func NewClient(baseURL, apiKey string, rateLimit int) *Client {
	// Normalize base URL
	baseURL = strings.TrimSuffix(baseURL, "/")

	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		rateLimiter: rate.NewLimiter(rate.Limit(rateLimit), rateLimit),
	}
}

// Submit sends an ingestion request to the server.
func (c *Client) Submit(ctx context.Context, req *IngestRequest) (*IngestResponse, error) {
	// Wait for rate limiter
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}

	// Marshal request body
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/ingest-http", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	// Send request
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Handle non-success status codes
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error != "" {
			return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, errResp.Error)
		}
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(respBody))
	}

	// Parse success response
	var ingestResp IngestResponse
	if err := json.Unmarshal(respBody, &ingestResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &ingestResp, nil
}
