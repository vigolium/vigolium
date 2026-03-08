package httpmsg

import "testing"

// TestExtractHostname tests the extractHostname function.
func TestExtractHostname(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// No port
		{"example.com", "example.com"},
		{"192.168.1.1", "192.168.1.1"},

		// With port
		{"example.com:8080", "example.com"},
		{"192.168.1.1:3000", "192.168.1.1"},
		{"localhost:80", "localhost"},
		{"host:", "host"},

		// IPv6 with brackets
		{"[::1]:8080", "::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[::1]", "::1"},
		{"[2001:db8::1]", "2001:db8::1"},

		// Edge cases
		{"", ""},
		{"[malformed", "[malformed"}, // malformed IPv6, return as-is
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractHostname(tt.input)
			if got != tt.want {
				t.Errorf("extractHostname(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestNewService tests the NewService function.
func TestNewService(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		port        int
		protocol    string
		wantHost    string
		wantPort    int
		wantProto   string
		wantErr     bool
		errContains string
	}{
		{
			name:      "valid https service",
			host:      "example.com",
			port:      443,
			protocol:  "https",
			wantHost:  "example.com",
			wantPort:  443,
			wantProto: "https",
			wantErr:   false,
		},
		{
			name:      "valid http service",
			host:      "example.com",
			port:      80,
			protocol:  "http",
			wantHost:  "example.com",
			wantPort:  80,
			wantProto: "http",
			wantErr:   false,
		},
		{
			name:      "custom port https",
			host:      "api.example.com",
			port:      8443,
			protocol:  "https",
			wantHost:  "api.example.com",
			wantPort:  8443,
			wantProto: "https",
			wantErr:   false,
		},
		{
			name:      "custom port http",
			host:      "localhost",
			port:      8080,
			protocol:  "http",
			wantHost:  "localhost",
			wantPort:  8080,
			wantProto: "http",
			wantErr:   false,
		},
		{
			name:      "case insensitive HTTPS",
			host:      "example.com",
			port:      443,
			protocol:  "HTTPS",
			wantHost:  "example.com",
			wantPort:  443,
			wantProto: "https",
			wantErr:   false,
		},
		{
			name:      "case insensitive HTTP",
			host:      "example.com",
			port:      80,
			protocol:  "HTTP",
			wantHost:  "example.com",
			wantPort:  80,
			wantProto: "http",
			wantErr:   false,
		},
		{
			name:        "empty host",
			host:        "",
			port:        443,
			protocol:    "https",
			wantErr:     true,
			errContains: "host cannot be null",
		},
		{
			name:        "invalid protocol",
			host:        "example.com",
			port:        443,
			protocol:    "ftp",
			wantErr:     true,
			errContains: "invalid protocol",
		},
		{
			name:        "empty protocol",
			host:        "example.com",
			port:        443,
			protocol:    "",
			wantErr:     true,
			errContains: "invalid protocol",
		},
		{
			name:      "IPv4 address",
			host:      "192.168.1.1",
			port:      443,
			protocol:  "https",
			wantHost:  "192.168.1.1",
			wantPort:  443,
			wantProto: "https",
			wantErr:   false,
		},
		{
			name:      "IPv6 address",
			host:      "2001:db8::1",
			port:      443,
			protocol:  "https",
			wantHost:  "2001:db8::1",
			wantPort:  443,
			wantProto: "https",
			wantErr:   false,
		},
		// Host normalization tests (remove port suffix)
		{
			name:      "host with port suffix - should normalize",
			host:      "192.168.1.1:3000",
			port:      3000,
			protocol:  "http",
			wantHost:  "192.168.1.1",
			wantPort:  3000,
			wantProto: "http",
			wantErr:   false,
		},
		{
			name:      "host with different port suffix",
			host:      "example.com:8080",
			port:      443,
			protocol:  "https",
			wantHost:  "example.com",
			wantPort:  443,
			wantProto: "https",
			wantErr:   false,
		},
		{
			name:      "IPv6 with brackets and port",
			host:      "[::1]:8080",
			port:      8080,
			protocol:  "http",
			wantHost:  "::1",
			wantPort:  8080,
			wantProto: "http",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewService(tt.host, tt.port, tt.protocol)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewService() expected error, got nil")
					return
				}
				if tt.errContains != "" {
					errMsg := err.Error()
					if !contains(errMsg, tt.errContains) {
						t.Errorf("NewService() error = %v, want error containing %v", errMsg, tt.errContains)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("NewService() unexpected error: %v", err)
				return
			}

			if service.Host() != tt.wantHost {
				t.Errorf("NewService() host = %v, want %v", service.Host(), tt.wantHost)
			}
			if service.Port() != tt.wantPort {
				t.Errorf("NewService() port = %v, want %v", service.Port(), tt.wantPort)
			}
			if service.Protocol() != tt.wantProto {
				t.Errorf("NewService() protocol = %v, want %v", service.Protocol(), tt.wantProto)
			}
		})
	}
}

// TestNewServiceSecure tests the NewServiceSecure function.
func TestNewServiceSecure(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		port      int
		useHTTPS  bool
		wantHost  string
		wantPort  int
		wantProto string
	}{
		{
			name:      "secure service (https)",
			host:      "example.com",
			port:      443,
			useHTTPS:  true,
			wantHost:  "example.com",
			wantPort:  443,
			wantProto: "https",
		},
		{
			name:      "insecure service (http)",
			host:      "example.com",
			port:      80,
			useHTTPS:  false,
			wantHost:  "example.com",
			wantPort:  80,
			wantProto: "http",
		},
		{
			name:      "custom port with https",
			host:      "api.example.com",
			port:      8443,
			useHTTPS:  true,
			wantHost:  "api.example.com",
			wantPort:  8443,
			wantProto: "https",
		},
		{
			name:      "custom port with http",
			host:      "localhost",
			port:      8080,
			useHTTPS:  false,
			wantHost:  "localhost",
			wantPort:  8080,
			wantProto: "http",
		},
		// Host normalization tests (remove port suffix)
		{
			name:      "host with port suffix - should normalize",
			host:      "125.212.198.16:3000",
			port:      3000,
			useHTTPS:  false,
			wantHost:  "125.212.198.16",
			wantPort:  3000,
			wantProto: "http",
		},
		{
			name:      "host with different port suffix",
			host:      "example.com:8080",
			port:      443,
			useHTTPS:  true,
			wantHost:  "example.com",
			wantPort:  443,
			wantProto: "https",
		},
		{
			name:      "IPv6 with brackets and port",
			host:      "[::1]:8080",
			port:      8080,
			useHTTPS:  false,
			wantHost:  "::1",
			wantPort:  8080,
			wantProto: "http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewServiceSecure(tt.host, tt.port, tt.useHTTPS)

			if service.Host() != tt.wantHost {
				t.Errorf("NewServiceSecure() host = %v, want %v", service.Host(), tt.wantHost)
			}
			if service.Port() != tt.wantPort {
				t.Errorf("NewServiceSecure() port = %v, want %v", service.Port(), tt.wantPort)
			}
			if service.Protocol() != tt.wantProto {
				t.Errorf("NewServiceSecure() protocol = %v, want %v", service.Protocol(), tt.wantProto)
			}
		})
	}
}

// TestParseService tests URL parsing.
func TestParseService(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		wantHost    string
		wantPort    int
		wantProto   string
		wantErr     bool
		errContains string
	}{
		{
			name:      "https with default port",
			url:       "https://example.com/path",
			wantHost:  "example.com",
			wantPort:  443,
			wantProto: "https",
			wantErr:   false,
		},
		{
			name:      "http with default port",
			url:       "http://example.com/path",
			wantHost:  "example.com",
			wantPort:  80,
			wantProto: "http",
			wantErr:   false,
		},
		{
			name:      "https with custom port",
			url:       "https://example.com:8443/path",
			wantHost:  "example.com",
			wantPort:  8443,
			wantProto: "https",
			wantErr:   false,
		},
		{
			name:      "http with custom port",
			url:       "http://localhost:8080/api",
			wantHost:  "localhost",
			wantPort:  8080,
			wantProto: "http",
			wantErr:   false,
		},
		{
			name:      "no path",
			url:       "https://example.com",
			wantHost:  "example.com",
			wantPort:  443,
			wantProto: "https",
			wantErr:   false,
		},
		{
			name:      "no path with port",
			url:       "https://example.com:9443",
			wantHost:  "example.com",
			wantPort:  9443,
			wantProto: "https",
			wantErr:   false,
		},
		{
			name:      "IPv4 address",
			url:       "http://192.168.1.1:8080/test",
			wantHost:  "192.168.1.1",
			wantPort:  8080,
			wantProto: "http",
			wantErr:   false,
		},
		{
			name:      "subdomain",
			url:       "https://api.example.com:443/v1/users",
			wantHost:  "api.example.com",
			wantPort:  443,
			wantProto: "https",
			wantErr:   false,
		},
		{
			name:      "query parameters",
			url:       "http://example.com:80/search?q=test",
			wantHost:  "example.com",
			wantPort:  80,
			wantProto: "http",
			wantErr:   false,
		},
		{
			name:        "empty URL",
			url:         "",
			wantErr:     true,
			errContains: "URL cannot be empty",
		},
		{
			name:        "missing protocol",
			url:         "example.com/path",
			wantErr:     true,
			errContains: "URL must contain protocol",
		},
		{
			name:        "invalid protocol",
			url:         "ftp://example.com/path",
			wantErr:     true,
			errContains: "protocol must be http or https",
		},
		{
			name:        "missing host",
			url:         "http:///path",
			wantErr:     true,
			errContains: "URL must contain host",
		},
		{
			name:        "invalid port",
			url:         "http://example.com:abc/path",
			wantErr:     true,
			errContains: "invalid port number",
		},
		{
			name:        "protocol only",
			url:         "http://",
			wantErr:     true,
			errContains: "URL must contain host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := ParseService(tt.url)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseService() expected error, got nil")
					return
				}
				if tt.errContains != "" {
					errMsg := err.Error()
					if !contains(errMsg, tt.errContains) {
						t.Errorf("ParseService() error = %v, want error containing %v", errMsg, tt.errContains)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("ParseService() unexpected error: %v", err)
				return
			}

			if service.Host() != tt.wantHost {
				t.Errorf("ParseService() host = %v, want %v", service.Host(), tt.wantHost)
			}
			if service.Port() != tt.wantPort {
				t.Errorf("ParseService() port = %v, want %v", service.Port(), tt.wantPort)
			}
			if service.Protocol() != tt.wantProto {
				t.Errorf("ParseService() protocol = %v, want %v", service.Protocol(), tt.wantProto)
			}
		})
	}
}

// TestEqualsIgnoreCase tests case-insensitive string comparison.
func TestEqualsIgnoreCase(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{
			name: "exact match",
			a:    "hello",
			b:    "hello",
			want: true,
		},
		{
			name: "case insensitive match",
			a:    "Hello",
			b:    "hello",
			want: true,
		},
		{
			name: "all uppercase",
			a:    "HELLO",
			b:    "hello",
			want: true,
		},
		{
			name: "mixed case",
			a:    "HeLLo",
			b:    "hEllO",
			want: true,
		},
		{
			name: "different strings",
			a:    "hello",
			b:    "world",
			want: false,
		},
		{
			name: "different lengths",
			a:    "hello",
			b:    "helloworld",
			want: false,
		},
		{
			name: "empty strings",
			a:    "",
			b:    "",
			want: true,
		},
		{
			name: "one empty",
			a:    "hello",
			b:    "",
			want: false,
		},
		{
			name: "http vs HTTP",
			a:    "http",
			b:    "HTTP",
			want: true,
		},
		{
			name: "https vs HTTPS",
			a:    "https",
			b:    "HTTPS",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EqualsIgnoreCase(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("EqualsIgnoreCase(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// Helper function to check if string contains substring.
func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}

	for i := 0; i <= len(s)-len(substr); i++ {
		matched := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}

	return false
}
