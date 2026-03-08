package backup_file_discovery

import (
	"testing"
)

func TestGenerateStems(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     []string // stems that must be present
	}{
		{
			name:     "simple domain",
			hostname: "example.com",
			want:     []string{"example", "example-com", "example.com"},
		},
		{
			name:     "subdomain",
			hostname: "sub.example.com",
			want:     []string{"example", "sub", "sub-example", "sub.example", "sub-example-com", "sub.example.com"},
		},
		{
			name:     "deep subdomain",
			hostname: "api.staging.example.com",
			want:     []string{"example", "api", "staging", "api-staging-example-com"},
		},
		{
			name:     "with port",
			hostname: "example.com:8080",
			want:     []string{"example", "example-com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stems := generateStems(tt.hostname)
			stemSet := make(map[string]bool, len(stems))
			for _, s := range stems {
				stemSet[s] = true
			}

			for _, w := range tt.want {
				if !stemSet[w] {
					t.Errorf("generateStems(%q) missing expected stem %q, got: %v", tt.hostname, w, stems)
				}
			}

			// Should also include static stems
			if !stemSet["backup"] {
				t.Errorf("generateStems(%q) missing static stem 'backup'", tt.hostname)
			}
			if !stemSet["www"] {
				t.Errorf("generateStems(%q) missing static stem 'www'", tt.hostname)
			}
		})
	}
}

func TestGenerateStems_YearVariants(t *testing.T) {
	stems := generateStems("example.com")
	stemSet := make(map[string]bool, len(stems))
	for _, s := range stems {
		stemSet[s] = true
	}

	// Should contain year variants (we can't hardcode the year, but check the pattern exists)
	hasYear := false
	for _, s := range stems {
		if len(s) > 7 && s[:7] == "example" && s[7] >= '0' && s[7] <= '9' {
			hasYear = true
			break
		}
	}
	if !hasYear {
		t.Error("generateStems should produce year variants like example2025")
	}
}

func TestGenerateStems_NoDuplicates(t *testing.T) {
	stems := generateStems("sub.example.com")
	seen := make(map[string]bool)
	for _, s := range stems {
		if seen[s] {
			t.Errorf("duplicate stem: %q", s)
		}
		seen[s] = true
	}
}

func TestGeneratePaths(t *testing.T) {
	paths := generatePaths("sub.example.com")

	if len(paths) == 0 {
		t.Fatal("generatePaths returned no paths")
	}

	// Check a few expected paths exist
	pathSet := make(map[string]bool, len(paths))
	for _, p := range paths {
		pathSet[p] = true
	}

	expected := []string{
		"/example.zip",
		"/backup.tar.gz",
		"/sub-example-backup.zip",
		"/backup-www.zip",
		"/database.sql",
	}
	for _, e := range expected {
		if !pathSet[e] {
			t.Errorf("missing expected path %q", e)
		}
	}

	// All paths should start with /
	for _, p := range paths {
		if p[0] != '/' {
			t.Errorf("path should start with /, got: %q", p)
		}
	}

	// No duplicates
	seen := make(map[string]bool)
	for _, p := range paths {
		if seen[p] {
			t.Errorf("duplicate path: %q", p)
		}
		seen[p] = true
	}

	t.Logf("Generated %d paths for sub.example.com", len(paths))
}
