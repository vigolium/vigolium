package integration_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"
)

// RequestLog captures information about a received request.
type RequestLog struct {
	Path        string
	Method      string
	Body        string
	ContentType string
	Query       url.Values
	Timestamp   time.Time
}

// TestServer wraps httptest.Server with dynamic routing based on ResponseScenario.
type TestServer struct {
	Server     *httptest.Server
	scenarios  map[string]ResponseScenario
	requestLog []RequestLog
	mu         sync.RWMutex
}

// NewTestServer creates a test server with the given response scenarios.
// Routes are matched by exact path. Unmatched routes return 404.
func NewTestServer(scenarios []ResponseScenario) *TestServer {
	ts := &TestServer{
		scenarios:  make(map[string]ResponseScenario),
		requestLog: make([]RequestLog, 0),
	}

	// Index scenarios by path
	for _, s := range scenarios {
		ts.scenarios[s.Path] = s
	}

	// Create HTTP handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log the request
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body)) // Reset body for potential re-read

		ts.mu.Lock()
		ts.requestLog = append(ts.requestLog, RequestLog{
			Path:        r.URL.Path,
			Method:      r.Method,
			Body:        string(body),
			ContentType: r.Header.Get("Content-Type"),
			Query:       r.URL.Query(),
			Timestamp:   time.Now(),
		})
		ts.mu.Unlock()

		ts.mu.RLock()
		scenario, found := ts.scenarios[r.URL.Path]
		ts.mu.RUnlock()

		if !found {
			// Default 404 for unmatched routes
			http.NotFound(w, r)
			return
		}

		// Check method if specified
		if scenario.Method != "" && scenario.Method != r.Method {
			http.NotFound(w, r)
			return
		}

		// Set response headers
		for key, value := range scenario.Headers {
			w.Header().Set(key, value)
		}

		// Set status code (default 200)
		statusCode := scenario.StatusCode
		if statusCode == 0 {
			statusCode = http.StatusOK
		}
		w.WriteHeader(statusCode)

		// Write body
		if scenario.Body != "" {
			_, _ = w.Write([]byte(scenario.Body))
		}
	})

	ts.Server = httptest.NewServer(handler)
	return ts
}

// URL returns the base URL of the test server.
func (ts *TestServer) URL() string {
	return ts.Server.URL
}

// Close shuts down the test server.
func (ts *TestServer) Close() {
	ts.Server.Close()
}

// AddScenario adds or updates a response scenario dynamically.
func (ts *TestServer) AddScenario(s ResponseScenario) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.scenarios[s.Path] = s
}

// RemoveScenario removes a scenario by path.
func (ts *TestServer) RemoveScenario(path string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	delete(ts.scenarios, path)
}

// GetRequests returns all logged requests.
func (ts *TestServer) GetRequests() []RequestLog {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	result := make([]RequestLog, len(ts.requestLog))
	copy(result, ts.requestLog)
	return result
}

// GetRequestsForPath returns all requests made to a specific path.
func (ts *TestServer) GetRequestsForPath(path string) []RequestLog {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	var result []RequestLog
	for _, req := range ts.requestLog {
		if req.Path == path {
			result = append(result, req)
		}
	}
	return result
}

// ClearRequestLog clears the request log.
func (ts *TestServer) ClearRequestLog() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.requestLog = make([]RequestLog, 0)
}
