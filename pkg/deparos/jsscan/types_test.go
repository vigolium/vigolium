package jsscan

import (
	"testing"
	"time"
)

func TestScanResult_HasRequests(t *testing.T) {
	tests := []struct {
		name   string
		result *ScanResult
		want   bool
	}{
		{
			name:   "nil requests",
			result: &ScanResult{Requests: nil},
			want:   false,
		},
		{
			name:   "empty requests",
			result: &ScanResult{Requests: []ExtractedRequest{}},
			want:   false,
		},
		{
			name: "with requests",
			result: &ScanResult{
				Requests: []ExtractedRequest{
					{URL: "/api/test", Method: "GET"},
				},
			},
			want: true,
		},
		{
			name: "multiple requests",
			result: &ScanResult{
				Requests: []ExtractedRequest{
					{URL: "/api/v1", Method: "GET"},
					{URL: "/api/v2", Method: "POST"},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.HasRequests(); got != tt.want {
				t.Errorf("HasRequests() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScanResult_HasCode(t *testing.T) {
	tests := []struct {
		name   string
		result *ScanResult
		want   bool
	}{
		{
			name:   "nil code",
			result: &ScanResult{Code: nil},
			want:   false,
		},
		{
			name: "with code",
			result: &ScanResult{
				Code: &CodeRecord{
					Filename: "test.js",
					Content:  "function test() {}",
				},
			},
			want: true,
		},
		{
			name: "empty code content",
			result: &ScanResult{
				Code: &CodeRecord{
					Filename: "",
					Content:  "",
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.HasCode(); got != tt.want {
				t.Errorf("HasCode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	if cfg.CacheDir != "" {
		t.Errorf("DefaultConfig().CacheDir = %q, want empty string", cfg.CacheDir)
	}
}

func TestExtractedRequest_Fields(t *testing.T) {
	req := ExtractedRequest{
		URL:     "/api/users",
		Method:  "POST",
		Params:  "page=1&limit=10",
		Body:    `{"name":"test"}`,
		Headers: []string{"Content-Type: application/json", "Authorization: Bearer token"},
		Cookies: []string{"session=abc123"},
	}

	if req.URL != "/api/users" {
		t.Errorf("URL = %q, want /api/users", req.URL)
	}
	if req.Method != "POST" {
		t.Errorf("Method = %q, want POST", req.Method)
	}
	if req.Params != "page=1&limit=10" {
		t.Errorf("Params = %q, want page=1&limit=10", req.Params)
	}
	if req.Body != `{"name":"test"}` {
		t.Errorf("Body = %q, want {\"name\":\"test\"}", req.Body)
	}
	if len(req.Headers) != 2 {
		t.Errorf("len(Headers) = %d, want 2", len(req.Headers))
	}
	if len(req.Cookies) != 1 {
		t.Errorf("len(Cookies) = %d, want 1", len(req.Cookies))
	}
}

func TestCodeRecord_Fields(t *testing.T) {
	code := CodeRecord{
		Filename: "bundle.js",
		Content:  "var x = 1;",
	}

	if code.Filename != "bundle.js" {
		t.Errorf("Filename = %q, want bundle.js", code.Filename)
	}
	if code.Content != "var x = 1;" {
		t.Errorf("Content = %q, want var x = 1;", code.Content)
	}
}

func TestCachedBinary_Fields(t *testing.T) {
	now := time.Now()
	cached := CachedBinary{
		Path:        "/tmp/jsscan",
		Checksum:    "abc123def456",
		ExtractedAt: now,
	}

	if cached.Path != "/tmp/jsscan" {
		t.Errorf("Path = %q, want /tmp/jsscan", cached.Path)
	}
	if cached.Checksum != "abc123def456" {
		t.Errorf("Checksum = %q, want abc123def456", cached.Checksum)
	}
	if !cached.ExtractedAt.Equal(now) {
		t.Errorf("ExtractedAt = %v, want %v", cached.ExtractedAt, now)
	}
}

func TestScanResult_AllFields(t *testing.T) {
	result := ScanResult{
		Requests: []ExtractedRequest{
			{URL: "/api/test", Method: "GET"},
		},
		Code: &CodeRecord{
			Filename: "test.js",
			Content:  "code",
		},
		ScanDuration: 100 * time.Millisecond,
		BytesScanned: 1024,
	}

	if len(result.Requests) != 1 {
		t.Errorf("len(Requests) = %d, want 1", len(result.Requests))
	}
	if result.Code == nil {
		t.Error("Code is nil, want non-nil")
	}
	if result.ScanDuration != 100*time.Millisecond {
		t.Errorf("ScanDuration = %v, want 100ms", result.ScanDuration)
	}
	if result.BytesScanned != 1024 {
		t.Errorf("BytesScanned = %d, want 1024", result.BytesScanned)
	}
}

func TestErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrBinaryNotFound",
			err:  ErrBinaryNotFound,
			want: "jsscan binary not found",
		},
		{
			name: "ErrExtractionFailed",
			err:  ErrExtractionFailed,
			want: "failed to extract jsscan binary",
		},
		{
			name: "ErrScanFailed",
			err:  ErrScanFailed,
			want: "jsscan scan failed",
		},
		{
			name: "ErrUnsupportedPlatform",
			err:  ErrUnsupportedPlatform,
			want: "unsupported platform for jsscan",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}
