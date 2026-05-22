package agent

import (
	"strings"
	"testing"
)

func TestDiffSignatures(t *testing.T) {
	cases := []struct {
		name       string
		before     []string
		after      []string
		wantGap    []string
		wantLen    int
		wantSubset string // substring expected in first gap entry (sanity check)
	}{
		{
			name:    "empty-before-returns-everything",
			before:  nil,
			after:   []string{"GET /a", "POST /b"},
			wantGap: []string{"GET /a", "POST /b"},
			wantLen: 2,
		},
		{
			name:    "empty-after-returns-nil",
			before:  []string{"GET /a"},
			after:   nil,
			wantGap: nil,
			wantLen: 0,
		},
		{
			name:    "identical-sets-no-gap",
			before:  []string{"GET /a", "POST /b"},
			after:   []string{"GET /a", "POST /b"},
			wantGap: nil,
			wantLen: 0,
		},
		{
			name:       "after-has-one-new",
			before:     []string{"GET /a"},
			after:      []string{"GET /a", "GET /b"},
			wantLen:    1,
			wantSubset: "GET /b",
		},
		{
			name:    "after-missing-some-from-before-not-counted",
			before:  []string{"GET /a", "POST /b", "GET /c"},
			after:   []string{"GET /a", "GET /b"}, // "POST /b" gone, but "GET /b" is new
			wantLen: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := diffSignatures(tc.before, tc.after)
			if tc.wantLen != len(got) {
				t.Fatalf("len=%d, want %d (got=%v)", len(got), tc.wantLen, got)
			}
			if tc.wantGap != nil {
				for i, w := range tc.wantGap {
					if i >= len(got) || got[i] != w {
						t.Errorf("got[%d]=%q, want %q (full=%v)", i, got[i], w, got)
					}
				}
			}
			if tc.wantSubset != "" && len(got) > 0 {
				if !strings.Contains(got[0], tc.wantSubset) {
					t.Errorf("first gap entry %q missing substring %q", got[0], tc.wantSubset)
				}
			}
		})
	}
}

func TestExtractHostname(t *testing.T) {
	cases := []struct {
		in   string
		want string
		err  bool
	}{
		{"https://example.com/path", "example.com", false},
		{"http://example.com:8080/path", "example.com", false},
		{"example.com", "example.com", false},
		{"example.com:8080", "example.com", false},
		{"", "", true},
		{"   ", "", true},
		{"https://", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := extractHostname(tc.in)
			if tc.err {
				if err == nil {
					t.Fatalf("want error, got host=%q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
