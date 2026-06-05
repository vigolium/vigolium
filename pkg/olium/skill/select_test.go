package skill

import (
	"sort"
	"strings"
	"testing"
)

// regFixture builds a small registry: xss[xss,dom], idor[idor,bola],
// triage[], jsext[].
func regFixture() *Registry {
	r := &Registry{skills: map[string]*Skill{}}
	add := func(name string, tags ...string) {
		r.skills[name] = &Skill{Name: name, Description: name, Tags: tags}
		r.order = append(r.order, name)
	}
	add("xss-browser-confirm", "xss", "dom")
	add("idor-blast-radius", "idor", "bola")
	add("triage-finding")
	add("write-jsext")
	return r
}

func selectedNames(r *Registry) []string {
	out := []string{}
	for _, s := range r.List() {
		out = append(out, s.Name)
	}
	sort.Strings(out)
	return out
}

func TestSelect(t *testing.T) {
	cases := []struct {
		name    string
		opts    SelectOptions
		want    []string
		warnSub string // substring expected in a warning, "" = none
	}{
		{
			name: "picks plus always-on union",
			opts: SelectOptions{Picks: []string{"xss-browser-confirm"}, AlwaysOn: []string{"triage-finding", "write-jsext"}},
			want: []string{"triage-finding", "write-jsext", "xss-browser-confirm"},
		},
		{
			name:    "unknown pick dropped and warned",
			opts:    SelectOptions{Picks: []string{"xss-browser-confirm", "does-not-exist"}},
			want:    []string{"xss-browser-confirm"},
			warnSub: "does-not-exist",
		},
		{
			name: "forced tag expands to all tagged",
			opts: SelectOptions{ForcedTags: []string{"DOM"}}, // case-insensitive
			want: []string{"xss-browser-confirm"},
		},
		{
			name:    "tag matching nothing warns",
			opts:    SelectOptions{Picks: []string{"triage-finding"}, ForcedTags: []string{"nope"}},
			want:    []string{"triage-finding"},
			warnSub: "matched no skills",
		},
		{
			name: "forced override included",
			opts: SelectOptions{Forced: []string{"idor-blast-radius"}},
			want: []string{"idor-blast-radius"},
		},
		{
			name: "disable filter returns full set",
			opts: SelectOptions{DisableFilter: true, Picks: []string{"xss-browser-confirm"}},
			want: []string{"idor-blast-radius", "triage-finding", "write-jsext", "xss-browser-confirm"},
		},
		{
			name: "empty selection yields empty registry",
			opts: SelectOptions{},
			want: []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, warnings := regFixture().Select(tc.opts)
			names := selectedNames(got)
			if strings.Join(names, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("selected = %v, want %v", names, tc.want)
			}
			if tc.warnSub == "" {
				return
			}
			found := false
			for _, w := range warnings {
				if strings.Contains(w, tc.warnSub) {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected a warning containing %q, got %v", tc.warnSub, warnings)
			}
		})
	}
}

func TestSelectNilRegistry(t *testing.T) {
	var r *Registry
	got, warnings := r.Select(SelectOptions{Picks: []string{"x"}})
	if got != nil || warnings != nil {
		t.Fatalf("nil registry should passthrough, got %v / %v", got, warnings)
	}
}

func TestEffectiveAlwaysOnDefaultMatchesBuiltins(t *testing.T) {
	// Guards against the default always-on list naming a skill that doesn't
	// ship embedded — which would silently warn on every run.
	reg := regFixture()
	for _, n := range []string{"triage-finding", "write-jsext"} {
		if reg.Get(n) == nil {
			t.Fatalf("fixture missing %q", n)
		}
	}
}
