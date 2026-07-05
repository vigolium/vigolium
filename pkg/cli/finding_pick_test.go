package cli

import (
	"slices"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

func TestParsePositionSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []int
		wantErr bool
	}{
		{"single", "2", []int{2}, false},
		{"list", "1,3", []int{1, 3}, false},
		{"range", "2-4", []int{2, 3, 4}, false},
		{"list and range", "1,3-4,7", []int{1, 3, 4, 7}, false},
		{"order preserved", "3,1", []int{3, 1}, false},
		{"whitespace tolerated", " 1 , 2 - 3 ", []int{1, 2, 3}, false},
		{"single-element range", "5-5", []int{5}, false},
		{"empty", "", nil, true},
		{"only commas", ",,", nil, true},
		{"zero", "0", nil, true},
		{"negative single", "-1", nil, true},
		{"non-numeric", "abc", nil, true},
		{"reversed range", "4-2", nil, true},
		{"zero in range", "0-2", nil, true},
		{"open range", "2-", nil, true},
		{"range over cap rejected", "1-10001", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePositionSpec(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parsePositionSpec(%q) = %v, want error", tt.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePositionSpec(%q) unexpected error: %v", tt.spec, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("parsePositionSpec(%q) = %v, want %v", tt.spec, got, tt.want)
			}
		})
	}

	t.Run("range at cap expands fully", func(t *testing.T) {
		got, err := parsePositionSpec("1-10000")
		if err != nil {
			t.Fatalf("unexpected error at cap: %v", err)
		}
		if len(got) != maxPickPositions {
			t.Fatalf("got %d positions, want %d", len(got), maxPickPositions)
		}
	})
}

func TestSelectFindingsByPosition(t *testing.T) {
	findings := []*database.Finding{
		{ID: 10}, {ID: 20}, {ID: 30}, {ID: 40}, {ID: 50},
	}

	t.Run("single 1-based", func(t *testing.T) {
		got, err := selectFindingsByPosition(findings, "2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0].ID != 20 {
			t.Fatalf("got %v, want [20]", ids(got))
		}
	})

	t.Run("range", func(t *testing.T) {
		got, err := selectFindingsByPosition(findings, "2-4")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := []int64{20, 30, 40}; !slices.Equal(ids(got), want) {
			t.Fatalf("got %v, want %v", ids(got), want)
		}
	})

	t.Run("order preserved and deduped", func(t *testing.T) {
		got, err := selectFindingsByPosition(findings, "3,1,3")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := []int64{30, 10}; !slices.Equal(ids(got), want) {
			t.Fatalf("got %v, want %v", ids(got), want)
		}
	})

	t.Run("partial out of range keeps valid", func(t *testing.T) {
		got, err := selectFindingsByPosition(findings, "4,9")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := []int64{40}; !slices.Equal(ids(got), want) {
			t.Fatalf("got %v, want %v", ids(got), want)
		}
	})

	t.Run("all out of range errors", func(t *testing.T) {
		if _, err := selectFindingsByPosition(findings, "8,9"); err == nil {
			t.Fatal("expected error when every position is out of range")
		}
	})

	t.Run("empty input list is a no-op", func(t *testing.T) {
		got, err := selectFindingsByPosition(nil, "2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %d findings, want 0", len(got))
		}
	})

	t.Run("invalid spec errors", func(t *testing.T) {
		if _, err := selectFindingsByPosition(findings, "0"); err == nil {
			t.Fatal("expected error for 1-based zero position")
		}
	})
}

func ids(fs []*database.Finding) []int64 {
	out := make([]int64, len(fs))
	for i, f := range fs {
		out[i] = f.ID
	}
	return out
}
