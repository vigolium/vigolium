package cli

import (
	"testing"
	"time"
)

func TestParseRecordsFromSpec(t *testing.T) {
	const project = "00000000-0000-0000-0000-000000000001"

	t.Run("empty spec keeps only project scope", func(t *testing.T) {
		filters, err := parseRecordsFromSpec("", project)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if filters.ProjectUUID != project {
			t.Errorf("project_uuid = %q, want %q", filters.ProjectUUID, project)
		}
		if filters.HostPattern != "" || len(filters.Methods) != 0 || len(filters.StatusCodes) != 0 {
			t.Errorf("expected zero-value filters, got %+v", filters)
		}
	})

	t.Run("simple host+status", func(t *testing.T) {
		filters, err := parseRecordsFromSpec("host=example.com,status=200", project)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if filters.HostPattern != "example.com" {
			t.Errorf("host = %q", filters.HostPattern)
		}
		if len(filters.StatusCodes) != 1 || filters.StatusCodes[0] != 200 {
			t.Errorf("status codes = %v", filters.StatusCodes)
		}
	})

	t.Run("multi-value status with pipe", func(t *testing.T) {
		filters, err := parseRecordsFromSpec("status=200|302|500", project)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(filters.StatusCodes) != 3 {
			t.Fatalf("expected 3 status codes, got %v", filters.StatusCodes)
		}
	})

	t.Run("multi-value method with pipe", func(t *testing.T) {
		filters, err := parseRecordsFromSpec("method=GET|POST", project)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(filters.Methods) != 2 || filters.Methods[0] != "GET" || filters.Methods[1] != "POST" {
			t.Errorf("methods = %v", filters.Methods)
		}
	})

	t.Run("since accepts YYYY-MM-DD", func(t *testing.T) {
		filters, err := parseRecordsFromSpec("since=2026-04-01", project)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if filters.DateFrom == nil {
			t.Fatal("DateFrom should be set")
		}
		want := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
		if !filters.DateFrom.Equal(want) {
			t.Errorf("DateFrom = %v, want %v", *filters.DateFrom, want)
		}
	})

	t.Run("since accepts RFC3339", func(t *testing.T) {
		filters, err := parseRecordsFromSpec("since=2026-04-01T12:00:00Z", project)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if filters.DateFrom == nil {
			t.Fatal("DateFrom should be set")
		}
	})

	t.Run("rejects unknown key", func(t *testing.T) {
		_, err := parseRecordsFromSpec("hostt=example.com", project)
		if err == nil {
			t.Fatal("expected error for unknown key, got nil")
		}
	})

	t.Run("rejects malformed entry", func(t *testing.T) {
		_, err := parseRecordsFromSpec("host", project)
		if err == nil {
			t.Fatal("expected error for entry without =, got nil")
		}
	})

	t.Run("rejects empty value", func(t *testing.T) {
		_, err := parseRecordsFromSpec("host=", project)
		if err == nil {
			t.Fatal("expected error for empty value, got nil")
		}
	})

	t.Run("rejects non-integer status", func(t *testing.T) {
		_, err := parseRecordsFromSpec("status=oops", project)
		if err == nil {
			t.Fatal("expected error for non-integer status, got nil")
		}
	})
}

func TestDedupeStrings(t *testing.T) {
	got := dedupeStrings([]string{"a", "b", "a", "c", "b", "d"})
	want := []string{"a", "b", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}
}
