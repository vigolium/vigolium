package scope

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChecker_IsInScope(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		urlStr   string
		expected bool
	}{
		// ModeAny tests
		{
			name: "any mode - allow all",
			config: Config{
				TargetHost: "example.com",
				Mode:       ModeAny,
			},
			urlStr:   "https://other.com/api",
			expected: true,
		},

		// ModeSubdomain tests (same main domain - eTLD+1)
		{
			name: "subdomain mode - exact host match",
			config: Config{
				TargetHost: "example.com",
				Mode:       ModeSubdomain,
			},
			urlStr:   "https://example.com/api",
			expected: true,
		},
		{
			name: "subdomain mode - subdomain allowed (same main domain)",
			config: Config{
				TargetHost: "www.example.com",
				Mode:       ModeSubdomain,
			},
			urlStr:   "https://api.example.com/users",
			expected: true,
		},
		{
			name: "subdomain mode - different subdomain allowed (same main domain)",
			config: Config{
				TargetHost: "admin.example.com",
				Mode:       ModeSubdomain,
			},
			urlStr:   "https://api.example.com/users",
			expected: true,
		},
		{
			name: "subdomain mode - root domain from subdomain target",
			config: Config{
				TargetHost: "www.example.com",
				Mode:       ModeSubdomain,
			},
			urlStr:   "https://example.com/api",
			expected: true,
		},
		{
			name: "subdomain mode - different domain rejected",
			config: Config{
				TargetHost: "example.com",
				Mode:       ModeSubdomain,
			},
			urlStr:   "https://other.com/api",
			expected: false,
		},
		{
			name: "subdomain mode - similar domain rejected",
			config: Config{
				TargetHost: "example.com",
				Mode:       ModeSubdomain,
			},
			urlStr:   "https://notexample.com/api",
			expected: false,
		},

		// ModeExact tests (exact host match only)
		{
			name: "exact mode - exact match allowed",
			config: Config{
				TargetHost: "api.example.com",
				Mode:       ModeExact,
			},
			urlStr:   "https://api.example.com/users",
			expected: true,
		},
		{
			name: "exact mode - child subdomain rejected",
			config: Config{
				TargetHost: "api.example.com",
				Mode:       ModeExact,
			},
			urlStr:   "https://admin.api.example.com/users",
			expected: false,
		},
		{
			name: "exact mode - sibling subdomain rejected",
			config: Config{
				TargetHost: "api.example.com",
				Mode:       ModeExact,
			},
			urlStr:   "https://www.example.com/users",
			expected: false,
		},
		{
			name: "exact mode - parent domain rejected",
			config: Config{
				TargetHost: "api.example.com",
				Mode:       ModeExact,
			},
			urlStr:   "https://example.com/users",
			expected: false,
		},
		{
			name: "exact mode - different domain rejected",
			config: Config{
				TargetHost: "example.com",
				Mode:       ModeExact,
			},
			urlStr:   "https://other.com/api",
			expected: false,
		},

		// Exclude patterns
		{
			name: "exclude pattern match",
			config: Config{
				TargetHost:      "example.com",
				Mode:            ModeSubdomain,
				ExcludePatterns: []string{"/logout", "/admin"},
			},
			urlStr:   "https://example.com/admin/users",
			expected: false,
		},
		{
			name: "exclude pattern no match",
			config: Config{
				TargetHost:      "example.com",
				Mode:            ModeSubdomain,
				ExcludePatterns: []string{"/logout", "/admin"},
			},
			urlStr:   "https://example.com/api/users",
			expected: true,
		},

		// Case insensitive
		{
			name: "case insensitive host",
			config: Config{
				TargetHost: "EXAMPLE.COM",
				Mode:       ModeSubdomain,
			},
			urlStr:   "https://Example.Com/api",
			expected: true,
		},

		// Empty target
		{
			name: "no target host (allow all)",
			config: Config{
				TargetHost: "",
				Mode:       ModeExact,
			},
			urlStr:   "https://any.com/api",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewChecker(tt.config)
			u, err := url.Parse(tt.urlStr)
			require.NoError(t, err)

			result := checker.IsInScope(u)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestChecker_StripPort(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "hostname with port",
			input:    "example.com:8080",
			expected: "example.com",
		},
		{
			name:     "hostname without port",
			input:    "example.com",
			expected: "example.com",
		},
		{
			name:     "IPv4 with port",
			input:    "192.168.1.1:8080",
			expected: "192.168.1.1",
		},
		{
			name:     "IPv6 with port",
			input:    "[::1]:8080",
			expected: "[::1]",
		},
		{
			name:     "IPv6 without port",
			input:    "[::1]",
			expected: "[::1]",
		},
		{
			name:     "IPv6 full address with port",
			input:    "[2001:db8::1]:443",
			expected: "[2001:db8::1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripPort(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestChecker_NilURL(t *testing.T) {
	checker := NewChecker(Config{
		TargetHost: "example.com",
		Mode:       ModeSubdomain,
	})

	result := checker.IsInScope(nil)
	assert.False(t, result)
}

// TestChecker_IPAndLocalhostScope guards the subdomain-mode fix for hosts with
// no meaningful eTLD+1. publicsuffix maps every IPv4 to "0.1", so without an
// explicit IP/localhost path two unrelated addresses would share scope.
func TestChecker_IPAndLocalhostScope(t *testing.T) {
	cases := []struct {
		name       string
		targetHost string
		urlStr     string
		want       bool
	}{
		{"same IPv4 in scope", "127.0.0.1", "http://127.0.0.1/api", true},
		{"different IPv4 out of scope", "127.0.0.1", "http://192.168.0.1/api", false},
		{"IPv4 vs domain out of scope", "example.com", "http://127.0.0.1/api", false},
		{"domain vs IPv4 out of scope", "127.0.0.1", "http://example.com/api", false},
		{"same localhost in scope", "localhost", "http://localhost/api", true},
		{"localhost vs IPv4 out of scope", "localhost", "http://127.0.0.1/api", false},
		{"same IPv4 with differing ports in scope", "127.0.0.1:8080", "http://127.0.0.1:3000/api", true},
		{"same IPv6 in scope", "[::1]", "http://[::1]:9000/api", true},
		{"different IPv6 out of scope", "[::1]", "http://[2001:db8::1]/api", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checker := NewChecker(Config{TargetHost: tc.targetHost, Mode: ModeSubdomain})
			u, err := url.Parse(tc.urlStr)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.urlStr, err)
			}
			if got := checker.IsInScope(u); got != tc.want {
				t.Errorf("IsInScope(target=%q, url=%q) = %v, want %v", tc.targetHost, tc.urlStr, got, tc.want)
			}
		})
	}
}

func BenchmarkChecker_IsInScope(b *testing.B) {
	checker := NewChecker(Config{
		TargetHost: "example.com",
		Mode:       ModeSubdomain,
	})

	u, _ := url.Parse("https://api.example.com/users")

	b.ResetTimer()
	for b.Loop() {
		_ = checker.IsInScope(u)
	}
}
