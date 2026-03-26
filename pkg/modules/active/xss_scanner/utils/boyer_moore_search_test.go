package utils

import (
	"bytes"
	"reflect" // Not strictly needed for these tests
	"testing"
)

// Helper to compare bcShift arrays (int[256])
func compareBcShift(a, b [256]int) bool {
	for i := 0; i < 256; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestNewBoyerMooreSearcher(t *testing.T) {
	tests := []struct {
		name          string
		pattern       []byte
		caseSensitive bool
		wantPattern   []byte
		wantCaseSens  bool
	}{
		{
			name:          "nil pattern",
			pattern:       nil,
			caseSensitive: true,
			wantPattern:   nil,
			wantCaseSens:  true,
		},
		{
			name:          "empty pattern",
			pattern:       []byte{},
			caseSensitive: true,
			wantPattern:   []byte{},
			wantCaseSens:  true,
		},
		{
			name:          "simple pattern case sensitive",
			pattern:       []byte("Test"),
			caseSensitive: true,
			wantPattern:   []byte("Test"),
			wantCaseSens:  true,
		},
		{
			name:          "simple pattern case insensitive",
			pattern:       []byte("Test"),
			caseSensitive: false,
			wantPattern:   []byte("test"),
			wantCaseSens:  false,
		},
		{
			name:          "pattern with mixed case, case insensitive",
			pattern:       []byte("TeStInG"),
			caseSensitive: false,
			wantPattern:   []byte("testing"),
			wantCaseSens:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			searcher := NewBoyerMooreSearcher(tt.pattern, tt.caseSensitive)
			kwSearcher, ok := searcher.(*BoyerMooreSearcher)
			if !ok {
				t.Fatalf("NewBoyerMooreSearcher did not return a *BoyerMooreSearcher")
			}

			if !bytes.Equal(kwSearcher.pattern, tt.wantPattern) {
				t.Errorf(
					"NewBoyerMooreSearcher().pattern = %v (%s), want %v (%s)",
					kwSearcher.pattern,
					string(kwSearcher.pattern),
					tt.wantPattern,
					string(tt.wantPattern),
				)
			}
			if kwSearcher.caseSensitive != tt.wantCaseSens {
				t.Errorf(
					"NewBoyerMooreSearcher().caseSensitive = %v, want %v",
					kwSearcher.caseSensitive,
					tt.wantCaseSens,
				)
			}
			if len(tt.pattern) > 0 {
				if kwSearcher.bcShift == [256]int{} {
					t.Error("NewBoyerMooreSearcher().bcShift was not initialized for non-empty pattern")
				}
				if kwSearcher.gsShift == nil {
					t.Error(
						"NewBoyerMooreSearcher().gsShift was not initialized (nil) for non-empty pattern",
					)
				} else if len(kwSearcher.gsShift) != len(tt.pattern) {
					t.Errorf("NewBoyerMooreSearcher().gsShift length = %d, want %d", len(kwSearcher.gsShift), len(tt.pattern))
				}
			} else {
				if len(kwSearcher.gsShift) != 0 {
					t.Errorf("NewBoyerMooreSearcher().gsShift should be nil or empty for nil/empty pattern, got %v", kwSearcher.gsShift)
				}
			}
		})
	}
}

func TestKwComputeBcShift(t *testing.T) {
	tests := []struct {
		name    string
		pattern []byte
		want    [256]int
	}{
		{
			name:    "pattern ABC",
			pattern: []byte("ABC"),
			want: func() [256]int {
				var shift [256]int
				for i := range shift {
					shift[i] = 3
				}
				shift[byte('A')] = 2
				shift[byte('B')] = 1
				shift[byte('C')] = 0
				return shift
			}(),
		},
		{
			name:    "pattern ABABA",
			pattern: []byte("ABABA"),
			want: func() [256]int {
				var shift [256]int
				for i := range shift {
					shift[i] = 5
				}
				shift[byte('A')] = 0
				shift[byte('B')] = 1
				return shift
			}(),
		},
		{
			name:    "pattern AAAAA",
			pattern: []byte("AAAAA"),
			want: func() [256]int {
				var shift [256]int
				for i := range shift {
					shift[i] = 5
				}
				shift[byte('A')] = 0
				return shift
			}(),
		},
		{
			name:    "empty pattern",
			pattern: []byte(""),
			want: func() [256]int {
				var shift [256]int
				return shift
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := kwComputeBcShift(tt.pattern); !compareBcShift(got, tt.want) {
				t.Errorf(
					"kwComputeBcShift() for pattern '%s' did not produce the expected bad character shift table.",
					string(tt.pattern),
				)
			}
		})
	}
}

func TestKwIsPrefix(t *testing.T) {
	tests := []struct {
		name             string
		pattern          []byte
		suffixStartIndex int
		want             bool
	}{
		{"ABABA, suffix from 0", []byte("ABABA"), 0, true},
		{"ABABA, suffix from 1", []byte("ABABA"), 1, false},
		{"ABABA, suffix from 2", []byte("ABABA"), 2, true},
		{"ABABA, suffix from 3", []byte("ABABA"), 3, false},
		{"ABABA, suffix from 4", []byte("ABABA"), 4, true},
		{"ABABA, suffix from 5 (empty suffix)", []byte("ABABA"), 5, true},
		{"AAAAA, suffix from 1", []byte("AAAAA"), 1, true},
		{"ABCDE, suffix from 1", []byte("ABCDE"), 1, false},
		{"ABCDE, suffix from 5 (empty suffix)", []byte("ABCDE"), 5, true},
		{"empty pattern, suffix from 0 (empty suffix)", []byte(""), 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := kwIsPrefix(tt.pattern, tt.suffixStartIndex); got != tt.want {
				t.Errorf(
					"kwIsPrefix(%s, %d) = %v, want %v",
					string(tt.pattern),
					tt.suffixStartIndex,
					got,
					tt.want,
				)
			}
		})
	}
}

func TestKwSuffixLength(t *testing.T) {
	tests := []struct {
		name              string
		pattern           []byte
		endIndexInPattern int
		want              int
	}{
		{"ABABA, endIdx 0 (P[0]='A')", []byte("ABABA"), 0, 1},
		{"ABABA, endIdx 1 (P[0..1]='AB')", []byte("ABABA"), 1, 0},
		{"ABABA, endIdx 2 (P[0..2]='ABA')", []byte("ABABA"), 2, 3},
		{"ABABA, endIdx 3 (P[0..3]='ABAB')", []byte("ABABA"), 3, 0},
		{"ABABA, endIdx 4 (P[0..4]='ABABA')", []byte("ABABA"), 4, 5},
		{"AAAAA, endIdx 0", []byte("AAAAA"), 0, 1},
		{"AAAAA, endIdx 1", []byte("AAAAA"), 1, 2},
		{"AAAAA, endIdx 2", []byte("AAAAA"), 2, 3},
		{"AAAAA, endIdx 3", []byte("AAAAA"), 3, 4},
		{"AAAAA, endIdx 4", []byte("AAAAA"), 4, 5},
		{"ABCDE, endIdx 0 (A)", []byte("ABCDE"), 0, 0},
		{"ABCDE, endIdx 4 (E)", []byte("ABCDE"), 4, 5},
		{"empty pattern, endIdx -1 (invalid)", []byte(""), -1, 0},
		{"A, endIdx 0", []byte("A"), 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := kwSuffixLength(tt.pattern, tt.endIndexInPattern); got != tt.want {
				t.Errorf(
					"kwSuffixLength(%s, %d) = %v, want %v",
					string(tt.pattern),
					tt.endIndexInPattern,
					got,
					tt.want,
				)
			}
		})
	}
}

func TestKwComputeGsShift(t *testing.T) {
	tests := []struct {
		name        string
		pattern     []byte
		wantGsShift []int
	}{
		{
			name:        "pattern ABC",
			pattern:     []byte("ABC"),
			wantGsShift: []int{1, 4, 5},
		},
		{
			name:        "pattern ABABA",
			pattern:     []byte("ABABA"),
			wantGsShift: []int{1, 5, 6, 5, 6},
		},
		{
			name:        "pattern AAAAA",
			pattern:     []byte("AAAAA"),
			wantGsShift: []int{5, 5, 5, 5, 5},
		},
		{
			name:        "pattern ANPANMAN",
			pattern:     []byte("ANPANMAN"),
			wantGsShift: []int{1, 9, 5, 9, 10, 11, 12, 13},
		},
		{
			name:        "pattern EXAMPLE",
			pattern:     []byte("EXAMPLE"),
			wantGsShift: []int{1, 7, 8, 9, 10, 11, 12},
		},
		{
			name:        "pattern BABAB",
			pattern:     []byte("BABAB"),
			wantGsShift: []int{1, 5, 6, 5, 6},
		},
		{
			name:        "pattern TEST",
			pattern:     []byte("TEST"),
			wantGsShift: []int{1, 4, 5, 6},
		},
		{
			name:        "pattern ABA",
			pattern:     []byte("ABA"),
			wantGsShift: []int{1, 3, 4},
		},
		{
			name:        "pattern GCAGAGAG",
			pattern:     []byte("GCAGAGAG"),
			wantGsShift: []int{1, 8, 6, 10, 6, 12, 13, 14},
		},
		{
			name:        "pattern ABABCABAB",
			pattern:     []byte("ABABCABAB"),
			wantGsShift: []int{1, 10, 4, 10, 9, 10, 11, 12, 13},
		},
		{
			name:        "pattern PATTERN",
			pattern:     []byte("PATTERN"),
			wantGsShift: []int{1, 8, 9, 10, 11, 12, 13},
		},
		{
			name:        "single char pattern A",
			pattern:     []byte("A"),
			wantGsShift: []int{1},
		},
		{
			name:        "empty pattern",
			pattern:     []byte(""),
			wantGsShift: []int{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := kwComputeGsShift(tt.pattern)
			if !reflect.DeepEqual(got, tt.wantGsShift) {
				t.Errorf(
					"kwComputeGsShift() for pattern '%s' = %v, want %v",
					string(tt.pattern),
					got,
					tt.wantGsShift,
				)
			}
		})
	}
}

// Mocking SearchableData for tests
type mockSearchableData struct {
	data []byte
}

func (m *mockSearchableData) IsSearchableData() {}
func (m *mockSearchableData) IsEmpty() bool      { return len(m.data) == 0 }
func (m *mockSearchableData) Length() int {
	if m.IsEmpty() {
		return 0
	}
	return len(m.data)
}
func (m *mockSearchableData) ByteAt(i int) int {
	if m.IsEmpty() || i < 0 || i >= len(m.data) {
		return 0
	}
	return int(m.data[i] & 0xFF)
}

func TestBoyerMooreSearcher_A(t *testing.T) {
	tests := []struct {
		name          string
		haystack      []byte
		pattern       []byte
		caseSensitive bool
		fromIndex     int
		toIndex       int
		want          int
	}{
		{
			name:          "nil pattern",
			haystack:      []byte("abc"),
			pattern:       nil,
			caseSensitive: true,
			fromIndex:     0,
			toIndex:       3,
			want:          -1,
		},
		{
			name:          "empty pattern",
			haystack:      []byte("abc"),
			pattern:       []byte(""),
			caseSensitive: true,
			fromIndex:     0,
			toIndex:       3,
			want:          0,
		},
		{
			name:          "empty pattern, fromIndex 1",
			haystack:      []byte("abc"),
			pattern:       []byte(""),
			caseSensitive: true,
			fromIndex:     1,
			toIndex:       3,
			want:          1,
		},
		{
			name:          "empty pattern, fromIndex past end",
			haystack:      []byte("abc"),
			pattern:       []byte(""),
			caseSensitive: true,
			fromIndex:     5,
			toIndex:       5,
			want:          3,
		},
		{
			name:          "nil haystack",
			haystack:      nil,
			pattern:       []byte("a"),
			caseSensitive: true,
			fromIndex:     0,
			toIndex:       0,
			want:          -1,
		},
		{
			name:          "empty haystack",
			haystack:      []byte(""),
			pattern:       []byte("a"),
			caseSensitive: true,
			fromIndex:     0,
			toIndex:       0,
			want:          -1,
		},
		{
			name:          "simple match",
			haystack:      []byte("abracadabra"),
			pattern:       []byte("cad"),
			caseSensitive: true,
			fromIndex:     0,
			toIndex:       11,
			want:          4,
		},
		{
			name:          "no match",
			haystack:      []byte("abracadabra"),
			pattern:       []byte("xyz"),
			caseSensitive: true,
			fromIndex:     0,
			toIndex:       11,
			want:          -1,
		},
		{
			name:          "match at start",
			haystack:      []byte("abracadabra"),
			pattern:       []byte("abr"),
			caseSensitive: true,
			fromIndex:     0,
			toIndex:       11,
			want:          0,
		},
		{
			name:          "match at end",
			haystack:      []byte("abracadabra"),
			pattern:       []byte("bra"),
			caseSensitive: true,
			fromIndex:     0,
			toIndex:       11,
			want:          1,
		},
		{
			name:          "multiple matches, find first",
			haystack:      []byte("abababa"),
			pattern:       []byte("aba"),
			caseSensitive: true,
			fromIndex:     0,
			toIndex:       7,
			want:          0,
		},
		{
			name:          "match with fromIndex",
			haystack:      []byte("abababa"),
			pattern:       []byte("aba"),
			caseSensitive: true,
			fromIndex:     1,
			toIndex:       7,
			want:          2,
		},
		{
			name:          "case insensitive match",
			haystack:      []byte("AbrAcadAbrA"),
			pattern:       []byte("cad"),
			caseSensitive: false,
			fromIndex:     0,
			toIndex:       11,
			want:          4,
		},
		{
			name:          "case insensitive no match",
			haystack:      []byte("AbrAcadAbrA"),
			pattern:       []byte("xyz"),
			caseSensitive: false,
			fromIndex:     0,
			toIndex:       11,
			want:          -1,
		},
		{
			name:          "case insensitive pattern mixed",
			haystack:      []byte("abracadabra"),
			pattern:       []byte("CaD"),
			caseSensitive: false,
			fromIndex:     0,
			toIndex:       11,
			want:          4,
		},
		{
			name:          "match within range",
			haystack:      []byte("abracadabra"),
			pattern:       []byte("cad"),
			caseSensitive: true,
			fromIndex:     3,
			toIndex:       8,
			want:          4,
		},
		{
			name:          "match starts before range, ends in range",
			haystack:      []byte("abracadabra"),
			pattern:       []byte("acad"),
			caseSensitive: true,
			fromIndex:     3,
			toIndex:       8,
			want:          3,
		},
		{
			name:          "match starts in range, ends after range",
			haystack:      []byte("abracadabra"),
			pattern:       []byte("dab"),
			caseSensitive: true,
			fromIndex:     6,
			toIndex:       10,
			want:          6,
		},
		{
			name:          "pattern longer than range",
			haystack:      []byte("abracadabra"),
			pattern:       []byte("cadabra"),
			caseSensitive: true,
			fromIndex:     4,
			toIndex:       8,
			want:          -1,
		},
		{
			name:          "exact range match",
			haystack:      []byte("abcde"),
			pattern:       []byte("bcd"),
			caseSensitive: true,
			fromIndex:     1,
			toIndex:       4,
			want:          1,
		},
		{
			name:          "pattern equals haystack",
			haystack:      []byte("abc"),
			pattern:       []byte("abc"),
			caseSensitive: true,
			fromIndex:     0,
			toIndex:       3,
			want:          0,
		},
		{
			name:          "pattern longer than haystack",
			haystack:      []byte("abc"),
			pattern:       []byte("abcd"),
			caseSensitive: true,
			fromIndex:     0,
			toIndex:       3,
			want:          -1,
		},
		{
			name:          "fromIndex equals toIndex (empty search)",
			haystack:      []byte("abc"),
			pattern:       []byte("b"),
			caseSensitive: true,
			fromIndex:     1,
			toIndex:       1,
			want:          -1,
		},
		{
			name:          "toIndex beyond haystack length",
			haystack:      []byte("abc"),
			pattern:       []byte("c"),
			caseSensitive: true,
			fromIndex:     0,
			toIndex:       10,
			want:          2,
		},
		{
			name:          "Boyer-Moore example 1",
			haystack:      []byte("HERE IS A SIMPLE EXAMPLE"),
			pattern:       []byte("EXAMPLE"),
			caseSensitive: true,
			fromIndex:     0,
			toIndex:       24,
			want:          17,
		},
		{
			name:          "Boyer-Moore example 2",
			haystack:      []byte("ANPANMAN"),
			pattern:       []byte("PAN"),
			caseSensitive: true,
			fromIndex:     0,
			toIndex:       8,
			want:          2,
		},
		{
			name:          "special_ls_b_null_case_match",
			haystack:      []byte("abcde"),
			pattern:       []byte("b"),
			caseSensitive: true,
			fromIndex:     0,
			toIndex:       5,
			want:          1, // 'b' is at index 1 in "abcde"
		},
		{
			name:          "special_ls_b_null_case_no_match_anyway",
			haystack:      []byte("abcde"),
			pattern:       []byte("x"),
			caseSensitive: true,
			fromIndex:     0,
			toIndex:       5,
			want:          -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			searcher := NewBoyerMooreSearcher(tt.pattern, tt.caseSensitive)
			haystackWrapper := &mockSearchableData{data: tt.haystack}

			if tt.name == "special_ls_b_null_case_match" ||
				tt.name == "special_ls_b_null_case_no_match_anyway" {

				got := searcher.Search(haystackWrapper, tt.fromIndex, tt.toIndex)
				if got != tt.want {
					t.Errorf(
						"BoyerMooreSearcher.Search() with LsStaticC=nil for '%s' in '%s' got = %v, want %v",
						string(tt.pattern),
						string(tt.haystack),
						got,
						tt.want,
					)
				}
			} else {
				got := searcher.Search(haystackWrapper, tt.fromIndex, tt.toIndex)
				if got != tt.want {
					t.Errorf("BoyerMooreSearcher.Search() for '%s' in '%s' (cs:%t, from:%d, to:%d) = %v, want %v", string(tt.pattern), string(tt.haystack), tt.caseSensitive, tt.fromIndex, tt.toIndex, got, tt.want)
				}
			}
		})
	}
}
