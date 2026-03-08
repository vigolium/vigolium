package network

import "time"

// TrafficEntry represents a single HTTP request/response captured from the browser.
type TrafficEntry struct {
	Timestamp    time.Time     `json:"timestamp"`
	Hash         string        `json:"hash"`
	Request      RequestData   `json:"request"`
	Response     *ResponseData `json:"response,omitempty"`
	ResourceType string        `json:"resourceType"`
	Error        string        `json:"error,omitempty"`

	// httpx computed fields (populated at capture time)
	Host          string `json:"-"`
	Port          string `json:"-"`
	Scheme        string `json:"-"`
	Path          string `json:"-"`
	ContentType   string `json:"-"`
	WebServer     string `json:"-"`
	ContentLength int    `json:"-"`
	Words         int    `json:"-"`
	Lines         int    `json:"-"`
	TargetHost    string `json:"-"`
}

// RequestData contains HTTP request information.
type RequestData struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body,omitempty"`
}

// ResponseData contains HTTP response information.
type ResponseData struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
}

