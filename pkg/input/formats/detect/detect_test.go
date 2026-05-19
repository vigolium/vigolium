package detect

import (
	"testing"
)

func TestDetectStdinFormat_RawHTTP(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    StdinFormat
	}{
		{
			name:    "GET request",
			content: "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want:    FormatRawHTTP,
		},
		{
			name:    "POST request",
			content: "POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nuser=admin",
			want:    FormatRawHTTP,
		},
		{
			name:    "HTTP/2",
			content: "GET /path HTTP/2\r\nHost: example.com\r\n\r\n",
			want:    FormatRawHTTP,
		},
		{
			name:    "leading whitespace",
			content: "\n  \nGET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want:    FormatRawHTTP,
		},
		{
			name:    "PUT request",
			content: "PUT /resource HTTP/1.0\r\nHost: api.example.com\r\n\r\n",
			want:    FormatRawHTTP,
		},
		{
			name:    "DELETE request",
			content: "DELETE /item/123 HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
			want:    FormatRawHTTP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectStdinFormat(tt.content)
			if got != tt.want {
				t.Errorf("DetectStdinFormat() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectStdinFormat_Curl(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    StdinFormat
	}{
		{
			name:    "simple curl",
			content: "curl https://example.com",
			want:    FormatCurl,
		},
		{
			name:    "curl with flags",
			content: "curl -X POST -H 'Content-Type: application/json' https://example.com/api",
			want:    FormatCurl,
		},
		{
			name:    "curl with dollar prompt",
			content: "$ curl https://example.com",
			want:    FormatCurl,
		},
		{
			name:    "curl with leading whitespace",
			content: "\n\n  curl https://example.com",
			want:    FormatCurl,
		},
		{
			name:    "dollar prompt with spaces",
			content: "$ curl -s -o /dev/null https://example.com",
			want:    FormatCurl,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectStdinFormat(tt.content)
			if got != tt.want {
				t.Errorf("DetectStdinFormat() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectStdinFormat_URLs(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    StdinFormat
	}{
		{
			name:    "single URL",
			content: "https://example.com",
			want:    FormatURLs,
		},
		{
			name:    "multiple URLs",
			content: "https://example.com\nhttps://test.com/api\nhttps://other.com/path",
			want:    FormatURLs,
		},
		{
			name:    "empty content",
			content: "",
			want:    FormatURLs,
		},
		{
			name:    "only whitespace",
			content: "   \n  \n  ",
			want:    FormatURLs,
		},
		{
			name:    "URL with path",
			content: "http://localhost:8080/api/v1/users?page=1",
			want:    FormatURLs,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectStdinFormat(tt.content)
			if got != tt.want {
				t.Errorf("DetectStdinFormat() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectStdinFormat_BurpPair(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    StdinFormat
	}{
		{
			name:    "LF separator",
			content: "GET / HTTP/1.1\nHost: example.com\n\n***\nHTTP/1.1 200 OK\nContent-Length: 2\n\nhi",
			want:    FormatBurpPair,
		},
		{
			name:    "CRLF separator",
			content: "GET / HTTP/2\r\nHost: example.com\r\n\r\n***\r\nHTTP/2 200 OK\r\nContent-Length: 2\r\n\r\nhi",
			want:    FormatBurpPair,
		},
		{
			name:    "no separator stays raw_http",
			content: "GET / HTTP/1.1\nHost: example.com\n\n",
			want:    FormatRawHTTP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectStdinFormat(tt.content)
			if got != tt.want {
				t.Errorf("DetectStdinFormat() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseStdinContent_BurpPair(t *testing.T) {
	content := "GET /order/details?orderId=42 HTTP/2\nHost: example.com\nReferer: https://example.com/foo\n\n***\nHTTP/2 200 OK\nContent-Type: text/html\nContent-Length: 5\n\nhello"
	items, err := ParseStdinContent(content, FormatBurpPair)
	if err != nil {
		t.Fatalf("ParseStdinContent: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("want 1 item, got %d", len(items))
	}
	rr := items[0]
	if !rr.HasResponse() {
		t.Fatal("expected response attached")
	}
	if got := rr.Response().StatusCode(); got != 200 {
		t.Errorf("status = %d, want 200", got)
	}
	if got, want := string(rr.Response().Body()), "hello"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	u, err := rr.URL()
	if err != nil {
		t.Fatalf("URL: %v", err)
	}
	if u.Scheme != "https" || u.Host != "example.com" {
		t.Errorf("URL = %s, want https://example.com/...", u.String())
	}
}

func TestFirstNonEmptyLine(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"empty", "", ""},
		{"single line", "hello", "hello"},
		{"leading empty lines", "\n\n\nhello\nworld", "hello"},
		{"whitespace lines", "  \n  \n  hello  ", "hello"},
		{"all empty", "\n\n\n", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firstNonEmptyLine(tt.content)
			if got != tt.want {
				t.Errorf("firstNonEmptyLine() = %q, want %q", got, tt.want)
			}
		})
	}
}
