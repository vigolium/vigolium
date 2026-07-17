package database

import "testing"

// TestQueryFilters_UsesRawCorpus pins every filter that reaches the
// raw_request/raw_response columns. Callers skip copying or selecting those
// blobs when this returns false, and the cost of a wrong answer is silent: a
// missed field makes --search match nothing and --exclude-* match everything.
func TestQueryFilters_UsesRawCorpus(t *testing.T) {
	t.Run("no filters", func(t *testing.T) {
		if (QueryFilters{}).UsesRawCorpus() {
			t.Fatal("empty filters reported a raw-corpus read")
		}
	})

	t.Run("metadata-only filters", func(t *testing.T) {
		// The case that matters for --glob-db: these all resolve against indexed
		// metadata columns, so the bodies are genuinely unnecessary.
		f := QueryFilters{
			HostPattern: "acme.com",
			Methods:     []string{"GET"},
			StatusCodes: []int{200},
			PathPattern: "/api",
			ContentType: "application/json",
		}
		if f.UsesRawCorpus() {
			t.Fatal("metadata-only filters reported a raw-corpus read")
		}
	})

	for _, tc := range []struct {
		name   string
		filter QueryFilters
	}{
		{"fuzzy term", QueryFilters{FuzzyTerm: "admin"}},
		{"search terms", QueryFilters{SearchTerms: []string{"admin"}}},
		{"single search term", QueryFilters{SearchTerm: "admin"}},
		{"header search", QueryFilters{HeaderSearch: "Authorization"}},
		{"body search", QueryFilters{BodySearch: "password"}},
		{"exclude terms", QueryFilters{ExcludeTerms: []string{"noise"}}},
		{"exclude header", QueryFilters{ExcludeHeaderSearch: "Set-Cookie"}},
		{"exclude body", QueryFilters{ExcludeBodySearch: "noise"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.filter.UsesRawCorpus() {
				t.Fatalf("%s must report a raw-corpus read: it LIKEs over raw_request/raw_response", tc.name)
			}
		})
	}

	t.Run("blank terms do not count", func(t *testing.T) {
		// EffectiveSearchTerms drops blanks, so a blank must not pin the bodies.
		f := QueryFilters{SearchTerms: []string{""}, ExcludeTerms: []string{""}}
		if f.UsesRawCorpus() {
			t.Fatal("blank-only terms reported a raw-corpus read")
		}
	})
}
