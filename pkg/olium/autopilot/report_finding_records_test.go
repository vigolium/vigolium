package autopilot

import (
	"slices"
	"strconv"
	"testing"
)

func TestParseRecordUUIDs(t *testing.T) {
	t.Run("json array of strings", func(t *testing.T) {
		got := parseRecordUUIDs([]any{"a", "b", "c"})
		if want := []string{"a", "b", "c"}; !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("trims, drops empties, dedupes", func(t *testing.T) {
		got := parseRecordUUIDs([]any{" a ", "a", "", "  ", "b"})
		if want := []string{"a", "b"}; !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("ignores non-string elements", func(t *testing.T) {
		got := parseRecordUUIDs([]any{"a", 42, nil, "b"})
		if want := []string{"a", "b"}; !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("accepts []string", func(t *testing.T) {
		got := parseRecordUUIDs([]string{"x", "x", "y"})
		if want := []string{"x", "y"}; !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("nil / wrong type yields non-nil empty", func(t *testing.T) {
		for _, in := range []any{nil, "not-an-array", 5} {
			got := parseRecordUUIDs(in)
			if got == nil {
				t.Errorf("parseRecordUUIDs(%v) = nil, want non-nil empty slice", in)
			}
			if len(got) != 0 {
				t.Errorf("parseRecordUUIDs(%v) = %v, want empty", in, got)
			}
		}
	})

	t.Run("caps at maxEvidenceRecords", func(t *testing.T) {
		in := make([]any, maxEvidenceRecords+25)
		for i := range in {
			in[i] = "uuid-" + strconv.Itoa(i) // unique per element
		}
		got := parseRecordUUIDs(in)
		if len(got) != maxEvidenceRecords {
			t.Errorf("len = %d, want cap %d", len(got), maxEvidenceRecords)
		}
	})
}
