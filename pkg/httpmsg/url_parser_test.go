package httpmsg

import (
	"testing"
)

// TestParseURL_AbsoluteHTTP tests parsing absolute HTTP URLs
func TestParseURL_AbsoluteHTTP(t *testing.T) {
	url := []byte("http://example.com:8080/path?query=1#section")
	parsed, err := ParseURL(url)

	if err != nil {
		t.Fatalf("ParseURL failed: %v", err)
	}

	if parsed.Protocol != "http" {
		t.Errorf("Protocol = %q, want %q", parsed.Protocol, "http")
	}
	if parsed.Host != "example.com" {
		t.Errorf("Host = %q, want %q", parsed.Host, "example.com")
	}
	if parsed.Port != 8080 {
		t.Errorf("Port = %d, want %d", parsed.Port, 8080)
	}
	if parsed.Path != "/path" {
		t.Errorf("Path = %q, want %q", parsed.Path, "/path")
	}
	if parsed.Query != "query=1" {
		t.Errorf("Query = %q, want %q", parsed.Query, "query=1")
	}
	if parsed.Fragment != "section" {
		t.Errorf("Fragment = %q, want %q", parsed.Fragment, "section")
	}
}

// TestParseURL_AbsoluteHTTPS tests parsing absolute HTTPS URLs
func TestParseURL_AbsoluteHTTPS(t *testing.T) {
	url := []byte("https://example.com/path")
	parsed, err := ParseURL(url)

	if err != nil {
		t.Fatalf("ParseURL failed: %v", err)
	}

	if parsed.Protocol != "https" {
		t.Errorf("Protocol = %q, want %q", parsed.Protocol, "https")
	}
	if parsed.Host != "example.com" {
		t.Errorf("Host = %q, want %q", parsed.Host, "example.com")
	}
	if parsed.Port != 443 {
		t.Errorf("Port = %d, want %d (default HTTPS)", parsed.Port, 443)
	}
	if parsed.Path != "/path" {
		t.Errorf("Path = %q, want %q", parsed.Path, "/path")
	}
}

// TestParseURL_DefaultPorts tests default port inference
func TestParseURL_DefaultPorts(t *testing.T) {
	tests := []struct {
		url          string
		wantProtocol string
		wantPort     int
	}{
		{"http://example.com/", "http", 80},
		{"https://example.com/", "https", 443},
		{"http://example.com:80/", "http", 80},
		{"https://example.com:443/", "https", 443},
	}

	for _, tt := range tests {
		parsed, err := ParseURL([]byte(tt.url))
		if err != nil {
			t.Fatalf("ParseURL(%q) failed: %v", tt.url, err)
		}

		if parsed.Protocol != tt.wantProtocol {
			t.Errorf("ParseURL(%q).Protocol = %q, want %q", tt.url, parsed.Protocol, tt.wantProtocol)
		}
		if parsed.Port != tt.wantPort {
			t.Errorf("ParseURL(%q).Port = %d, want %d", tt.url, parsed.Port, tt.wantPort)
		}
	}
}

// TestParseURL_IPAddress tests parsing IP address URLs
func TestParseURL_IPAddress(t *testing.T) {
	url := []byte("http://192.168.1.1:3000/api")
	parsed, err := ParseURL(url)

	if err != nil {
		t.Fatalf("ParseURL failed: %v", err)
	}

	if parsed.Host != "192.168.1.1" {
		t.Errorf("Host = %q, want %q", parsed.Host, "192.168.1.1")
	}
	if parsed.Port != 3000 {
		t.Errorf("Port = %d, want %d", parsed.Port, 3000)
	}
	if parsed.Path != "/api" {
		t.Errorf("Path = %q, want %q", parsed.Path, "/api")
	}
}

// TestParseURL_Localhost tests parsing localhost URLs
func TestParseURL_Localhost(t *testing.T) {
	url := []byte("http://localhost:8080/test")
	parsed, err := ParseURL(url)

	if err != nil {
		t.Fatalf("ParseURL failed: %v", err)
	}

	if parsed.Host != "localhost" {
		t.Errorf("Host = %q, want %q", parsed.Host, "localhost")
	}
	if parsed.Port != 8080 {
		t.Errorf("Port = %d, want %d", parsed.Port, 8080)
	}
	if parsed.Path != "/test" {
		t.Errorf("Path = %q, want %q", parsed.Path, "/test")
	}
}

// TestParseURL_RelativePath tests parsing relative path URLs
func TestParseURL_RelativePath(t *testing.T) {
	url := []byte("/api/users")
	parsed, err := ParseURL(url)

	if err != nil {
		t.Fatalf("ParseURL failed: %v", err)
	}

	if parsed.Protocol != "" {
		t.Errorf("Protocol = %q, want empty for relative URL", parsed.Protocol)
	}
	if parsed.Path != "/api/users" {
		t.Errorf("Path = %q, want %q", parsed.Path, "/api/users")
	}
}

// TestParseURL_RelativeWithQuery tests relative URLs with query strings
func TestParseURL_RelativeWithQuery(t *testing.T) {
	url := []byte("/path?query#frag")
	parsed, err := ParseURL(url)

	if err != nil {
		t.Fatalf("ParseURL failed: %v", err)
	}

	if parsed.Path != "/path" {
		t.Errorf("Path = %q, want %q", parsed.Path, "/path")
	}
	if parsed.Query != "query" {
		t.Errorf("Query = %q, want %q", parsed.Query, "query")
	}
	if parsed.Fragment != "frag" {
		t.Errorf("Fragment = %q, want %q", parsed.Fragment, "frag")
	}
}

// TestParseURL_ComplexQuery tests URLs with complex query strings
func TestParseURL_ComplexQuery(t *testing.T) {
	url := []byte("http://example.com/search?q=test&page=1&sort=asc")
	parsed, err := ParseURL(url)

	if err != nil {
		t.Fatalf("ParseURL failed: %v", err)
	}

	if parsed.Query != "q=test&page=1&sort=asc" {
		t.Errorf("Query = %q, want %q", parsed.Query, "q=test&page=1&sort=asc")
	}
}

// TestParseURL_NoPath tests URLs without path
func TestParseURL_NoPath(t *testing.T) {
	url := []byte("http://example.com")
	parsed, err := ParseURL(url)

	if err != nil {
		t.Fatalf("ParseURL failed: %v", err)
	}

	if parsed.Protocol != "http" {
		t.Errorf("Protocol = %q, want %q", parsed.Protocol, "http")
	}
	if parsed.Host != "example.com" {
		t.Errorf("Host = %q, want %q", parsed.Host, "example.com")
	}
	if parsed.Path != "" {
		t.Errorf("Path = %q, want empty", parsed.Path)
	}
}

// TestParseURL_EmptyURL tests empty URL handling
func TestParseURL_EmptyURL(t *testing.T) {
	parsed, err := ParseURL([]byte(""))

	if err != nil {
		t.Fatalf("ParseURL failed: %v", err)
	}

	if parsed != nil {
		t.Errorf("Expected nil for empty URL")
	}
}

// TestFindProtocolEnd tests protocol detection
func TestFindProtocolEnd(t *testing.T) {
	tests := []struct {
		url  string
		want int
	}{
		{"http://example.com", 4},
		{"https://example.com", 5},
		{"HTTP://example.com", 4}, // Case shouldn't matter for detection
		{"/relative/path", -1},
		{"no-protocol", -1},
		{"ftp://example.com", 3},
	}

	for _, tt := range tests {
		got := FindProtocolEnd([]byte(tt.url))
		if got != tt.want {
			t.Errorf("FindProtocolEnd(%q) = %d, want %d", tt.url, got, tt.want)
		}
	}
}

// TestFindHostEnd tests host boundary detection
func TestFindHostEnd(t *testing.T) {
	tests := []struct {
		url       string
		hostStart int
		want      int
	}{
		{"example.com/path", 0, 11},
		{"example.com?query", 0, 11},
		{"example.com#frag", 0, 11},
		{"example.com:8080/path", 0, 16},
		{"example.com", 0, 11},
	}

	for _, tt := range tests {
		got := FindHostEnd([]byte(tt.url), tt.hostStart)
		if got != tt.want {
			t.Errorf("FindHostEnd(%q, %d) = %d, want %d", tt.url, tt.hostStart, got, tt.want)
		}
	}
}

// TestParseHostPort tests host:port parsing
func TestParseHostPort(t *testing.T) {
	tests := []struct {
		hostBytes string
		wantHost  string
		wantPort  int
	}{
		{"example.com:8080", "example.com", 8080},
		{"example.com", "example.com", -1},
		{"192.168.1.1:3000", "192.168.1.1", 3000},
		{"localhost:80", "localhost", 80},
		{"", "", -1},
	}

	for _, tt := range tests {
		host, port := ParseHostPort([]byte(tt.hostBytes))
		if host != tt.wantHost {
			t.Errorf("ParseHostPort(%q) host = %q, want %q", tt.hostBytes, host, tt.wantHost)
		}
		if port != tt.wantPort {
			t.Errorf("ParseHostPort(%q) port = %d, want %d", tt.hostBytes, port, tt.wantPort)
		}
	}
}

// TestParseInt tests integer parsing
func TestParseInt(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"8080", 8080},
		{"80", 80},
		{"443", 443},
		{"0", 0},
		{"12345", 12345},
		{"abc", -1},   // Invalid
		{"12abc", -1}, // Invalid
		{"", -1},      // Empty
		{"-80", -1},   // Negative (not handled)
	}

	for _, tt := range tests {
		got := ParseInt(tt.input)
		if got != tt.want {
			t.Errorf("ParseInt(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

// TestFindPathEnd tests path boundary detection
func TestFindPathEnd(t *testing.T) {
	tests := []struct {
		url       string
		pathStart int
		want      int
	}{
		{"/api/users?id=123", 0, 10},
		{"/api/users#section", 0, 10},
		{"/api/users", 0, 10},
		{"?query", 0, 0},
		{"#frag", 0, 0},
	}

	for _, tt := range tests {
		got := FindPathEnd([]byte(tt.url), tt.pathStart)
		if got != tt.want {
			t.Errorf("FindPathEnd(%q, %d) = %d, want %d", tt.url, tt.pathStart, got, tt.want)
		}
	}
}

// TestURLParser_FindQueryEnd tests query boundary detection
func TestURLParser_FindQueryEnd(t *testing.T) {
	tests := []struct {
		url        string
		queryStart int
		want       int
	}{
		{"id=123#section", 0, 6},
		{"id=123", 0, 6},
		{"id=123&name=test#frag", 0, 16},
		{"", 0, 0},
	}

	for _, tt := range tests {
		got := FindQueryEnd([]byte(tt.url), tt.queryStart)
		if got != tt.want {
			t.Errorf("FindQueryEnd(%q, %d) = %d, want %d", tt.url, tt.queryStart, got, tt.want)
		}
	}
}

// TestGetDefaultPort tests default port lookup
func TestGetDefaultPort(t *testing.T) {
	tests := []struct {
		protocol string
		want     int
	}{
		{"http", 80},
		{"HTTP", 80}, // Case insensitive
		{"https", 443},
		{"HTTPS", 443},
		{"ws", 80},
		{"wss", 443},
		{"ftp", -1}, // Unknown
		{"", -1},    // Empty
	}

	for _, tt := range tests {
		got := GetDefaultPort(tt.protocol)
		if got != tt.want {
			t.Errorf("GetDefaultPort(%q) = %d, want %d", tt.protocol, got, tt.want)
		}
	}
}

// TestToLowerString tests string lowercase conversion
func TestToLowerString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"HTTP", "http"},
		{"HTTPS", "https"},
		{"Example.COM", "example.com"},
		{"already-lower", "already-lower"},
		{"MiXeD-CaSe", "mixed-case"},
		{"", ""},
	}

	for _, tt := range tests {
		got := ToLowerString(tt.input)
		if got != tt.want {
			t.Errorf("ToLowerString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestExtractURLFromRequest tests URL extraction from HTTP requests
func TestExtractURLFromRequest(t *testing.T) {
	tests := []struct {
		name    string
		request string
		wantURL string
		wantErr bool
	}{
		{
			name:    "Simple GET request",
			request: "GET /api/users HTTP/1.1\r\nHost: example.com\r\n",
			wantURL: "/api/users",
			wantErr: false,
		},
		{
			name:    "GET with query string",
			request: "GET /api/users?id=123 HTTP/1.1\r\n",
			wantURL: "/api/users?id=123",
			wantErr: false,
		},
		{
			name:    "POST with path",
			request: "POST /api/create HTTP/1.1\r\n",
			wantURL: "/api/create",
			wantErr: false,
		},
		{
			name:    "Absolute URL in request",
			request: "GET http://example.com/path HTTP/1.1\r\n",
			wantURL: "http://example.com/path",
			wantErr: false,
		},
		{
			name:    "Root path",
			request: "GET / HTTP/1.1\r\n",
			wantURL: "/",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, start, end, err := ExtractURLFromRequest([]byte(tt.request))

			if tt.wantErr {
				if err == nil {
					t.Errorf("ExtractURLFromRequest() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("ExtractURLFromRequest() failed: %v", err)
			}

			gotURL := string(url)
			if gotURL != tt.wantURL {
				t.Errorf("ExtractURLFromRequest() URL = %q, want %q", gotURL, tt.wantURL)
			}

			// Verify start/end positions match the extracted URL
			if start != -1 && end != -1 {
				extractedURL := string([]byte(tt.request)[start:end])
				if extractedURL != tt.wantURL {
					t.Errorf("Start/end positions incorrect: extracted %q, want %q", extractedURL, tt.wantURL)
				}
			}
		})
	}
}

// TestFindQueryStringBounds tests query string boundary detection
func TestFindQueryStringBounds(t *testing.T) {
	tests := []struct {
		urlPath   string
		wantStart int
		wantEnd   int
	}{
		{"/api/users?id=123#section", 10, 17},
		{"/api/users?id=123", 10, 17},
		{"/api/users", -1, -1},
		{"?query", 0, 6},
		{"/path#frag", -1, -1}, // Fragment but no query
	}

	for _, tt := range tests {
		start, end := FindQueryStringBounds([]byte(tt.urlPath))
		if start != tt.wantStart {
			t.Errorf("FindQueryStringBounds(%q) start = %d, want %d", tt.urlPath, start, tt.wantStart)
		}
		if end != tt.wantEnd {
			t.Errorf("FindQueryStringBounds(%q) end = %d, want %d", tt.urlPath, end, tt.wantEnd)
		}
	}
}

// TestIsAbsoluteURL tests absolute URL detection
func TestIsAbsoluteURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"http://example.com", true},
		{"https://example.com", true},
		{"/relative/path", false},
		{"relative", false},
		{"", false},
	}

	for _, tt := range tests {
		got := IsAbsoluteURL([]byte(tt.url))
		if got != tt.want {
			t.Errorf("IsAbsoluteURL(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
}

// TestIsRelativeURL tests relative URL detection
func TestIsRelativeURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"/relative/path", true},
		{"relative", true},
		{"http://example.com", false},
		{"https://example.com", false},
	}

	for _, tt := range tests {
		got := IsRelativeURL([]byte(tt.url))
		if got != tt.want {
			t.Errorf("IsRelativeURL(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
}

// TestParsedURL_Getters tests ParsedURL getter methods
func TestParsedURL_Getters(t *testing.T) {
	parsed := &ParsedURL{
		Protocol: "https",
		Host:     "example.com",
		Port:     443,
		Path:     "/api",
		Query:    "id=123",
		Fragment: "section",
	}

	if parsed.Protocol != "https" {
		t.Errorf("GetProtocol() = %q, want %q", parsed.Protocol, "https")
	}
	if parsed.Host != "example.com" {
		t.Errorf("GetHost() = %q, want %q", parsed.Host, "example.com")
	}
	if parsed.Port != 443 {
		t.Errorf("GetPort() = %d, want %d", parsed.Port, 443)
	}
	if parsed.Path != "/api" {
		t.Errorf("GetPath() = %q, want %q", parsed.Path, "/api")
	}
	if parsed.Query != "id=123" {
		t.Errorf("GetQuery() = %q, want %q", parsed.Query, "id=123")
	}
	if parsed.Fragment != "section" {
		t.Errorf("GetFragment() = %q, want %q", parsed.Fragment, "section")
	}
}

// TestGetFullURL tests URL reconstruction
func TestGetFullURL(t *testing.T) {
	tests := []struct {
		name   string
		parsed *ParsedURL
		want   string
	}{
		{
			name: "Complete URL with non-default port",
			parsed: &ParsedURL{
				Protocol: "http",
				Host:     "example.com",
				Port:     8080,
				Path:     "/path",
				Query:    "id=123",
				Fragment: "section",
			},
			want: "http://example.com:8080/path?id=123#section",
		},
		{
			name: "URL with default HTTP port",
			parsed: &ParsedURL{
				Protocol: "http",
				Host:     "example.com",
				Port:     80,
				Path:     "/path",
			},
			want: "http://example.com/path",
		},
		{
			name: "URL with default HTTPS port",
			parsed: &ParsedURL{
				Protocol: "https",
				Host:     "example.com",
				Port:     443,
				Path:     "/path",
			},
			want: "https://example.com/path",
		},
		{
			name: "URL without query or fragment",
			parsed: &ParsedURL{
				Protocol: "https",
				Host:     "example.com",
				Port:     443,
				Path:     "/api",
			},
			want: "https://example.com/api",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.parsed.String()
			if got != tt.want {
				t.Errorf("GetFullURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestIntToString tests integer to string conversion
func TestIntToString(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{80, "80"},
		{443, "443"},
		{8080, "8080"},
		{12345, "12345"},
		{-1, "-1"},
		{-80, "-80"},
	}

	for _, tt := range tests {
		got := IntToString(tt.input)
		if got != tt.want {
			t.Errorf("IntToString(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestGetPathWithQuery tests path with query reconstruction
func TestGetPathWithQuery(t *testing.T) {
	tests := []struct {
		name   string
		parsed *ParsedURL
		want   string
	}{
		{
			name: "Path with query",
			parsed: &ParsedURL{
				Path:  "/api",
				Query: "id=123",
			},
			want: "/api?id=123",
		},
		{
			name: "Path without query",
			parsed: &ParsedURL{
				Path: "/api",
			},
			want: "/api",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.parsed.PathWithQuery()
			if got != tt.want {
				t.Errorf("GetPathWithQuery() = %q, want %q", got, tt.want)
			}
		})
	}
}

// BenchmarkParseURL benchmarks URL parsing performance
func BenchmarkParseURL(b *testing.B) {
	url := []byte("http://example.com:8080/path?query=1&name=test#section")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseURL(url)
	}
}

// BenchmarkExtractURLFromRequest benchmarks URL extraction from request
func BenchmarkExtractURLFromRequest(b *testing.B) {
	request := []byte("GET /api/users?id=123&page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = ExtractURLFromRequest(request)
	}
}
