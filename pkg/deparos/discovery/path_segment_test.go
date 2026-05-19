package discovery

import "testing"

func TestContainsUselessPathSegment(t *testing.T) {
	tests := []struct {
		name     string
		urlPath  string
		expected bool
	}{
		// Basic useless patterns - should be rejected
		{name: "single dot", urlPath: "/./admin/", expected: true},
		{name: "double dot", urlPath: "/../config/", expected: true},
		{name: "dot only", urlPath: "/./", expected: true},
		{name: "double dot only", urlPath: "/../", expected: true},
		{name: "trailing double dot", urlPath: "/admin/../", expected: true},
		{name: "middle double dot", urlPath: "/admin/../config/", expected: true},
		{name: "multiple double dots", urlPath: "/../../admin/", expected: true},

		// URL-encoded patterns - should be rejected
		{name: "encoded dot", urlPath: "/%2e/admin/", expected: true},
		{name: "encoded double dot", urlPath: "/%2e%2e/config/", expected: true},
		{name: "uppercase encoded dot", urlPath: "/%2E/admin/", expected: true},
		{name: "uppercase encoded double dot", urlPath: "/%2E%2E/config/", expected: true},
		{name: "mixed case encoded", urlPath: "/%2e%2E/config/", expected: true},

		// Double-encoded patterns - should be rejected
		{name: "double encoded dot", urlPath: "/%252e/admin/", expected: true},
		{name: "double encoded double dot", urlPath: "/%252e%252e/config/", expected: true},

		// Bypass patterns - should be ALLOWED
		{name: "semicolon bypass", urlPath: "/..;/admin/", expected: false},
		{name: "null byte bypass", urlPath: "/..%00/config/", expected: false},
		{name: "param bypass", urlPath: "/..;param/admin/", expected: false},
		{name: "dot semicolon", urlPath: "/.;/admin/", expected: false},

		// Valid paths - should be ALLOWED
		{name: "normal path", urlPath: "/admin/test/", expected: false},
		{name: "hidden dir", urlPath: "/.hidden/admin/", expected: false},
		{name: "git dir", urlPath: "/.git/config/", expected: false},
		{name: "double dot prefix name", urlPath: "/..htaccess/", expected: false},
		{name: "dotfile", urlPath: "/.htaccess", expected: false},
		{name: "config prefix", urlPath: "/..config/test/", expected: false},
		{name: "root path", urlPath: "/", expected: false},
		{name: "simple file", urlPath: "/index.html", expected: false},
		{name: "nested path", urlPath: "/api/v1/users/", expected: false},
		{name: "path with numbers", urlPath: "/user/123/profile/", expected: false},
		{name: "triple dot name", urlPath: "/...test/", expected: false},

		// Suffix patterns - should be rejected
		{name: "suffix single dot", urlPath: "/admin/./", expected: true},
		{name: "suffix double dot", urlPath: "/admin/../", expected: true},
		{name: "suffix encoded dot", urlPath: "/admin/%2e/", expected: true},
		{name: "suffix encoded double dot", urlPath: "/admin/%2e%2e/", expected: true},
		{name: "suffix no trailing slash dot", urlPath: "/admin/.", expected: true},
		{name: "suffix no trailing slash double dot", urlPath: "/admin/..", expected: true},
		{name: "deep suffix double dot", urlPath: "/api/v1/users/../", expected: true},
		{name: "deep suffix dot", urlPath: "/api/v1/users/./", expected: true},

		// Edge cases
		{name: "empty path", urlPath: "", expected: false},
		{name: "just root", urlPath: "/", expected: false},
		{name: "encoded slash", urlPath: "/admin%2ftest/", expected: false},

		// Consecutive duplicate patterns - should be REJECTED (> 2 consecutive)
		{name: "3 consecutive duplicates", urlPath: "/backup/backup/backup/", expected: true},
		{name: "4 consecutive duplicates", urlPath: "/admin/admin/admin/admin/", expected: true},
		{name: "3 consecutive in middle", urlPath: "/api/test/test/test/users/", expected: true},
		{name: "3 consecutive encoded", urlPath: "/backup/%62ackup/backup/", expected: true},
		{name: "3 consecutive mixed encoding", urlPath: "/data/%64ata/data/", expected: true},
		{name: "5 consecutive deep", urlPath: "/a/a/a/a/a/", expected: true},

		// Consecutive duplicate patterns - should be ALLOWED (≤ 2 consecutive)
		{name: "2 consecutive duplicates", urlPath: "/backup/backup/", expected: false},
		{name: "2 consecutive in middle", urlPath: "/api/test/test/users/", expected: false},
		{name: "2 consecutive encoded", urlPath: "/backup/%62ackup/", expected: false},
		{name: "non-consecutive duplicates", urlPath: "/backup/other/backup/", expected: false},
		{name: "2 pairs non-consecutive", urlPath: "/a/a/b/b/", expected: false},
		{name: "case sensitive different", urlPath: "/Backup/backup/BACKUP/", expected: false},
		{name: "similar but different", urlPath: "/backup/backup1/backup2/", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsUselessPathSegment(tt.urlPath)
			if result != tt.expected {
				t.Errorf("containsUselessPathSegment(%q) = %v, want %v", tt.urlPath, result, tt.expected)
			}
		})
	}
}
