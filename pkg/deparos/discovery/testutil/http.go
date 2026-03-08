package testutil

import (
	"context"
	"io"
	stdhttp "net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// MockHTTPClient provides a configurable mock HTTP client for testing.
// Thread-safe for concurrent access.
type MockHTTPClient struct {
	mu sync.Mutex

	// Requests stores all requests made
	Requests []*stdhttp.Request

	// ResponseFunc allows custom response logic - returns ResponseChain
	ResponseFunc func(req *stdhttp.Request) (*responsechain.ResponseChain, error)

	// RequestCount tracks the number of requests
	RequestCount atomic.Int32
}

// NewMockHTTPClient creates a mock HTTP client.
func NewMockHTTPClient() *MockHTTPClient {
	return &MockHTTPClient{
		Requests: make([]*stdhttp.Request, 0),
		ResponseFunc: func(req *stdhttp.Request) (*responsechain.ResponseChain, error) {
			// Default: return 404 for all requests
			return NewMockResponseChain(404, "Not Found"), nil
		},
	}
}

// Send sends an HTTP request and returns a ResponseChain.
// Thread-safe for concurrent access.
func (m *MockHTTPClient) Send(ctx context.Context, req *stdhttp.Request) (*responsechain.ResponseChain, error) {
	m.RequestCount.Add(1)

	m.mu.Lock()
	m.Requests = append(m.Requests, req)
	responseFunc := m.ResponseFunc
	m.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if responseFunc != nil {
		return responseFunc(req)
	}

	return NewMockResponseChain(404, "Not Found"), nil
}

// SetResponse configures the client to return a specific status code.
// Thread-safe.
func (m *MockHTTPClient) SetResponse(statusCode int, bodyStr string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ResponseFunc = func(req *stdhttp.Request) (*responsechain.ResponseChain, error) {
		return NewMockResponseChain(statusCode, bodyStr), nil
	}
}

// GetRequests returns a copy of all recorded requests.
// Thread-safe.
func (m *MockHTTPClient) GetRequests() []*stdhttp.Request {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]*stdhttp.Request, len(m.Requests))
	copy(result, m.Requests)
	return result
}

// MockAnalyzer provides a simple mock analyzer for testing.
type MockAnalyzer struct {
	// AnalyzeFunc allows custom analysis logic
	AnalyzeFunc func(ctx context.Context, req *stdhttp.Request, rc *responsechain.ResponseChain) (bool, error)
}

// NewMockAnalyzer creates a mock analyzer with simple logic:
// - 404 -> false (not found)
// - everything else -> true (found).
func NewMockAnalyzer() *MockAnalyzer {
	return &MockAnalyzer{
		AnalyzeFunc: func(ctx context.Context, req *stdhttp.Request, rc *responsechain.ResponseChain) (bool, error) {
			if rc == nil || !rc.Has() {
				return true, nil // error responses are "found" for discovery purposes
			}
			resp := rc.Response()
			if resp.StatusCode == 404 {
				return false, nil
			}
			return true, nil
		},
	}
}

// Analyze analyzes a response and returns whether it was found.
func (m *MockAnalyzer) Analyze(ctx context.Context, req *stdhttp.Request, rc *responsechain.ResponseChain) (bool, error) {
	if m.AnalyzeFunc != nil {
		return m.AnalyzeFunc(ctx, req, rc)
	}
	return false, nil
}

// NewMockResponseChain creates a ResponseChain from status code and body string for testing.
func NewMockResponseChain(statusCode int, body string) *responsechain.ResponseChain {
	resp := &stdhttp.Response{
		StatusCode: statusCode,
		Header:     stdhttp.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	rc := responsechain.NewResponseChain(resp, 0)
	_ = rc.Fill() // Fill the body
	return rc
}

// NewMockRedirectResponse creates a ResponseChain for a redirect response.
func NewMockRedirectResponse(statusCode int, location string, body string) *responsechain.ResponseChain {
	resp := &stdhttp.Response{
		StatusCode: statusCode,
		Header: stdhttp.Header{
			"Content-Type": []string{"text/html"},
			"Location":     []string{location},
		},
		Body: io.NopCloser(strings.NewReader(body)),
	}
	rc := responsechain.NewResponseChain(resp, 0)
	_ = rc.Fill()
	return rc
}

// MockComparator provides a configurable mock fingerprint comparator for testing.
type MockComparator struct {
	// CompareFunc allows custom comparison logic
	CompareFunc func(ctx context.Context, req *stdhttp.Request, rc *responsechain.ResponseChain) (fingerprint.MatchResult, error)
}

// NewMockComparator creates a mock comparator that returns the specified result.
func NewMockComparator(result fingerprint.MatchResult) *MockComparator {
	return &MockComparator{
		CompareFunc: func(ctx context.Context, req *stdhttp.Request, rc *responsechain.ResponseChain) (fingerprint.MatchResult, error) {
			return result, nil
		},
	}
}

// Compare implements the comparison method.
func (m *MockComparator) Compare(ctx context.Context, req *stdhttp.Request, rc *responsechain.ResponseChain) (fingerprint.MatchResult, error) {
	if m.CompareFunc != nil {
		return m.CompareFunc(ctx, req, rc)
	}
	return fingerprint.Unknown, nil
}
