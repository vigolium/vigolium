package runner

import (
	"sort"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

func TestBuildSPATargetsFromPaths(t *testing.T) {
	tests := []struct {
		name  string
		paths []database.PathTarget
		want  []string
	}{
		{
			name:  "empty input",
			paths: nil,
			want:  nil,
		},
		{
			name: "root path",
			paths: []database.PathTarget{
				{Scheme: "http", Hostname: "localhost", Port: 3000, Path: "/"},
			},
			want: []string{"http://localhost:3000/"},
		},
		{
			name: "empty path normalizes to root",
			paths: []database.PathTarget{
				{Scheme: "http", Hostname: "localhost", Port: 3000, Path: ""},
			},
			want: []string{"http://localhost:3000/"},
		},
		{
			name: "strip last segment",
			paths: []database.PathTarget{
				{Scheme: "http", Hostname: "localhost", Port: 3000, Path: "/ftp/file.txt"},
			},
			want: []string{"http://localhost:3000/ftp"},
		},
		{
			name: "path ending with slash kept as-is",
			paths: []database.PathTarget{
				{Scheme: "http", Hostname: "localhost", Port: 3000, Path: "/ftp/"},
			},
			want: []string{"http://localhost:3000/ftp"},
		},
		{
			name: "file at root strips to root",
			paths: []database.PathTarget{
				{Scheme: "http", Hostname: "localhost", Port: 3000, Path: "/file.txt"},
			},
			want: []string{"http://localhost:3000/"},
		},
		{
			name: "deep path strips last segment",
			paths: []database.PathTarget{
				{Scheme: "https", Hostname: "example.com", Port: 443, Path: "/a/b/c/d.js"},
			},
			want: []string{"https://example.com/a/b/c"},
		},
		{
			name: "query string stripped",
			paths: []database.PathTarget{
				{Scheme: "http", Hostname: "localhost", Port: 80, Path: "/search?q=foo"},
			},
			want: []string{"http://localhost/"},
		},
		{
			name: "standard ports omitted",
			paths: []database.PathTarget{
				{Scheme: "http", Hostname: "example.com", Port: 80, Path: "/"},
				{Scheme: "https", Hostname: "example.com", Port: 443, Path: "/api/v1/users"},
			},
			want: []string{"http://example.com/", "https://example.com/api/v1"},
		},
		{
			name: "deduplication",
			paths: []database.PathTarget{
				{Scheme: "http", Hostname: "localhost", Port: 3000, Path: "/ftp/file1.txt"},
				{Scheme: "http", Hostname: "localhost", Port: 3000, Path: "/ftp/file2.txt"},
				{Scheme: "http", Hostname: "localhost", Port: 3000, Path: "/"},
			},
			want: []string{"http://localhost:3000/ftp", "http://localhost:3000/"},
		},
		{
			name: "fragment stripped",
			paths: []database.PathTarget{
				{Scheme: "http", Hostname: "localhost", Port: 8080, Path: "/page#section"},
			},
			want: []string{"http://localhost:8080/"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSPATargetsFromPaths(tt.paths)

			if len(got) != len(tt.want) {
				t.Fatalf("got %d targets, want %d\ngot:  %v\nwant: %v", len(got), len(tt.want), got, tt.want)
			}

			// Sort both for stable comparison
			sort.Strings(got)
			wantSorted := make([]string, len(tt.want))
			copy(wantSorted, tt.want)
			sort.Strings(wantSorted)

			for i := range got {
				if got[i] != wantSorted[i] {
					t.Errorf("target[%d] = %q, want %q", i, got[i], wantSorted[i])
				}
			}
		})
	}
}

func TestBuildSPAHostTargets(t *testing.T) {
	tests := []struct {
		name  string
		paths []database.PathTarget
		want  []string
	}{
		{
			name:  "empty input",
			paths: nil,
			want:  nil,
		},
		{
			name: "deduplicates to host only",
			paths: []database.PathTarget{
				{Scheme: "http", Hostname: "localhost", Port: 3000, Path: "/rest/products/search"},
				{Scheme: "http", Hostname: "localhost", Port: 3000, Path: "/api/Challenges/"},
				{Scheme: "http", Hostname: "localhost", Port: 3000, Path: "/"},
			},
			want: []string{"http://localhost:3000/"},
		},
		{
			name: "multiple hosts",
			paths: []database.PathTarget{
				{Scheme: "http", Hostname: "localhost", Port: 3000, Path: "/a"},
				{Scheme: "https", Hostname: "example.com", Port: 443, Path: "/b/c"},
			},
			want: []string{"http://localhost:3000/", "https://example.com/"},
		},
		{
			name: "standard ports omitted",
			paths: []database.PathTarget{
				{Scheme: "http", Hostname: "example.com", Port: 80, Path: "/foo"},
				{Scheme: "https", Hostname: "example.com", Port: 443, Path: "/bar"},
			},
			want: []string{"http://example.com/", "https://example.com/"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSPAHostTargets(tt.paths)

			if len(got) != len(tt.want) {
				t.Fatalf("got %d targets, want %d\ngot:  %v\nwant: %v", len(got), len(tt.want), got, tt.want)
			}

			sort.Strings(got)
			wantSorted := make([]string, len(tt.want))
			copy(wantSorted, tt.want)
			sort.Strings(wantSorted)

			for i := range got {
				if got[i] != wantSorted[i] {
					t.Errorf("target[%d] = %q, want %q", i, got[i], wantSorted[i])
				}
			}
		})
	}
}
