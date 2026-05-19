package modules

import (
	"testing"
)

func TestDerivedRequiredTechs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "spring module tags",
			in:   []string{"spring", "java", "misconfiguration", "rce", "light"},
			want: []string{"spring", "java"},
		},
		{
			name: "generic XSS module",
			in:   []string{"injection", "xss", "light"},
			want: nil,
		},
		{
			name: "empty",
			in:   nil,
			want: nil,
		},
		{
			name: "mixed casing and whitespace",
			in:   []string{" NextJS ", "JAVASCRIPT", "session"},
			want: []string{"nextjs", "javascript"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DerivedRequiredTechs(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("len = %d, want %d (got=%v)", len(got), len(c.want), got)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("[%d] got %q want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}
