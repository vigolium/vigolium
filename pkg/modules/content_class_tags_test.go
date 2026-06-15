package modules

import "testing"

func TestDerivedContentClasses(t *testing.T) {
	cases := []struct {
		name string
		tags []string
		want []string
	}{
		{"clickjacking implies html", []string{"clickjacking", "ui-redress", "light"}, []string{"html"}},
		{"ui-redress alone", []string{"ui-redress"}, []string{"html"}},
		{"no content tag is agnostic", []string{"ssrf", "injection", "heavy"}, nil},
		{"nil tags", nil, nil},
		{"dedups repeated class", []string{"clickjacking", "ui-redress"}, []string{"html"}},
		{"case insensitive", []string{"ClickJacking"}, []string{"html"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DerivedContentClasses(tc.tags)
			if len(got) != len(tc.want) {
				t.Fatalf("DerivedContentClasses(%v) = %v, want %v", tc.tags, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("DerivedContentClasses(%v) = %v, want %v", tc.tags, got, tc.want)
				}
			}
		})
	}
}

// TestContentClassAware_Implementations pins that the modules we deliberately
// gated to HTML implement the interface (or are covered by tag derivation),
// guarding against an accidental removal that would silently re-broaden them.
func TestContentClassAware_Implementations(t *testing.T) {
	wantHTML := map[string]bool{
		"password-autocomplete-detect": false, // via interface
		"mixed-content-detect":         false, // via interface
		"clickjacking-detect":          false, // via tag derivation
	}
	for _, m := range DefaultRegistry.GetPassiveModules() {
		id := m.ID()
		if _, tracked := wantHTML[id]; !tracked {
			continue
		}
		var classes []string
		if aware, ok := m.(ContentClassAware); ok {
			classes = aware.RequiredContentClasses()
		} else {
			classes = DerivedContentClasses(m.Tags())
		}
		found := false
		for _, c := range classes {
			if c == "html" {
				found = true
			}
		}
		if !found {
			t.Errorf("module %q expected to require html content class, got %v", id, classes)
		}
		wantHTML[id] = true
	}
	for id, seen := range wantHTML {
		if !seen {
			t.Errorf("expected module %q in registry but it was not found", id)
		}
	}
}
