package sensitive_file_discovery

import (
	"strings"
	"testing"
)

func TestSensitiveFilesHaveMarkers(t *testing.T) {
	for _, sf := range sensitiveFiles {
		if len(sf.markers) == 0 {
			t.Errorf("sensitive file %q (%s) has no markers", sf.path, sf.name)
		}
		if sf.path == "" {
			t.Error("sensitive file has empty path")
		}
		if sf.name == "" {
			t.Error("sensitive file has empty name")
		}
		if sf.desc == "" {
			t.Errorf("sensitive file %q has empty description", sf.path)
		}
	}
}

func TestNotFoundFingerprint(t *testing.T) {
	fp := &notFoundFingerprint{
		status:   404,
		bodyHash: "abc123",
		bodyLen:  100,
	}

	if fp.status != 404 {
		t.Errorf("expected status 404, got %d", fp.status)
	}
	if fp.bodyLen != 100 {
		t.Errorf("expected body length 100, got %d", fp.bodyLen)
	}
}

func TestNotFoundFingerprintContentType(t *testing.T) {
	fp := &notFoundFingerprint{
		status:      404,
		bodyHash:    "abc123",
		bodyLen:     100,
		contentType: "text/html; charset=utf-8",
	}

	if fp.contentType != "text/html; charset=utf-8" {
		t.Errorf("expected contentType 'text/html; charset=utf-8', got %q", fp.contentType)
	}

	fpPlain := &notFoundFingerprint{
		status:      404,
		bodyHash:    "def456",
		bodyLen:     50,
		contentType: "text/plain",
	}

	if fpPlain.contentType != "text/plain" {
		t.Errorf("expected contentType 'text/plain', got %q", fpPlain.contentType)
	}
}

func TestGenericFilePathsNotEmpty(t *testing.T) {
	if len(genericFileCategories) == 0 {
		t.Fatal("genericFileCategories is empty")
	}

	for _, cat := range genericFileCategories {
		if cat.name == "" {
			t.Error("category has empty name")
		}
		if cat.desc == "" {
			t.Errorf("category %q has empty description", cat.name)
		}
		if len(cat.paths) == 0 {
			t.Errorf("category %q has no paths", cat.name)
		}
	}
}

func TestGenericFilePathsHaveLeadingSlash(t *testing.T) {
	for _, cat := range genericFileCategories {
		for _, path := range cat.paths {
			if !strings.HasPrefix(path, "/") {
				t.Errorf("category %q: path %q does not start with /", cat.name, path)
			}
		}
	}
}

func TestGenericFilePathsNoDuplicates(t *testing.T) {
	seen := make(map[string]string) // path -> category name
	for _, cat := range genericFileCategories {
		for _, path := range cat.paths {
			if prev, ok := seen[path]; ok {
				t.Errorf("duplicate path %q found in %q and %q", path, prev, cat.name)
			}
			seen[path] = cat.name
		}
	}
}

func TestGenericFilePathsNoOverlapWithMarkerBased(t *testing.T) {
	markerPaths := markerBasedPaths()
	for _, cat := range genericFileCategories {
		for _, path := range cat.paths {
			if markerPaths[path] {
				t.Errorf("category %q: path %q overlaps with marker-based sensitiveFiles", cat.name, path)
			}
		}
	}
}

func TestGenericFalsePositivesAreLowercase(t *testing.T) {
	for _, fp := range genericFalsePositives {
		if fp != strings.ToLower(fp) {
			t.Errorf("false positive %q is not lowercase", fp)
		}
	}
}
