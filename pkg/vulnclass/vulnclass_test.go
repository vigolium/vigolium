package vulnclass

import (
	"regexp"
	"testing"

	"github.com/vigolium/vigolium/pkg/oast/oastclass"
)

var snakeCase = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)

func TestVocabularyIsStableSnakeCaseAndUnique(t *testing.T) {
	seen := map[Class]bool{}
	for _, e := range Vocabulary() {
		if !snakeCase.MatchString(string(e.Class)) {
			t.Errorf("class %q is not snake_case", e.Class)
		}
		if seen[e.Class] {
			t.Errorf("class %q listed twice", e.Class)
		}
		seen[e.Class] = true
		if e.Description == "" {
			t.Errorf("class %q has no description", e.Class)
		}
	}
	for id, c := range byModule {
		if !c.Valid() {
			t.Errorf("module %q declares %q, not in the vocabulary", id, c)
		}
	}
}

func TestForFinding(t *testing.T) {
	cases := []struct {
		explicit Class
		module   string
		want     Class
	}{
		{"", "sqli-error-based", SQLi},
		{XSSBlind, "oast-probe", XSSBlind},    // the result's own class wins
		{"", "oast-probe", ""},                // a multi-class module never stamps "multiple"
		{Multiple, "sqli-error-based", SQLi},  // "multiple" is not a finding class
		{"made-up", "sqli-error-based", SQLi}, // an unknown explicit value is ignored
		{"", "nuclei-template-x", ""},         // undeclared ids have no class
	}
	for _, c := range cases {
		if got := ForFinding(c.explicit, c.module); got != c.want {
			t.Errorf("ForFinding(%q, %q) = %q, want %q", c.explicit, c.module, got, c.want)
		}
	}
}

func TestFromOASTCoversEveryPayloadClass(t *testing.T) {
	for _, c := range oastclass.All() {
		got := FromOAST(c)
		switch c {
		case oastclass.Generic, oastclass.MCPArg:
			if got != "" {
				t.Errorf("FromOAST(%s) = %q, want empty (the module decides)", c, got)
			}
		default:
			if !got.Valid() {
				t.Errorf("FromOAST(%s) = %q, want a vocabulary class", c, got)
			}
		}
	}
	if FromOAST(oastclass.BlindXSS) != XSSBlind {
		t.Error("a blind-XSS callback must report xss_blind")
	}
}
