package cftbrowser

import (
	"path/filepath"
	"testing"
)

// TestPlatformKeyConsistency ensures IsSupported and PlatformKey agree on the
// current platform without hard-coding which OS/arch the test runs on.
func TestPlatformKeyConsistency(t *testing.T) {
	key, err := PlatformKey()
	if IsSupported() {
		if err != nil {
			t.Errorf("IsSupported()=true but PlatformKey() errored: %v", err)
		}
		if key == "" {
			t.Error("supported platform returned empty key")
		}
	} else {
		if err == nil {
			t.Error("IsSupported()=false but PlatformKey() returned no error")
		}
	}
}

func TestParseMissingLib(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			"typical",
			"./chrome: error while loading shared libraries: libnss3.so: cannot open shared object file",
			"libnss3.so",
		},
		{
			"versioned",
			"error while loading shared libraries: libfoo.so.1: cannot open shared object file: No such file",
			"libfoo.so.1",
		},
		{"no marker", "command not found", ""},
		{"marker without trailing colon", "error while loading shared libraries: libfoo.so", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseMissingLib(tt.output); got != tt.want {
				t.Errorf("parseMissingLib(%q) = %q, want %q", tt.output, got, tt.want)
			}
		})
	}
}

func TestIsInsideDir(t *testing.T) {
	base := filepath.FromSlash("/tmp/extract-base")
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"child file", filepath.Join(base, "sub", "file.txt"), true},
		{"equal to base", base, true},
		{"parent escape", filepath.Join(base, "..", "escape.txt"), false},
		// Prefix-trick: a sibling whose name starts with base must NOT be
		// considered inside (the impl guards this by requiring a separator).
		{"sibling prefix", filepath.FromSlash("/tmp/extract-base-sibling/file"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isInsideDir(tt.path, base); got != tt.want {
				t.Errorf("isInsideDir(%q, %q) = %v, want %v", tt.path, base, got, tt.want)
			}
		})
	}
}
