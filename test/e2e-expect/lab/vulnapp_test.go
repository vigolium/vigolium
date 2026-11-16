package lab

import (
	"strings"
	"testing"
)

func TestFakeShell(t *testing.T) {
	for in, want := range map[string]string{
		"ping -c 1 example;echo ab$((2+3))cd": "ab5cd",
		"ping -c 1 example& echo X$((4*5))Y":  "X20Y",
		"ping -c 1 example|id":                "uid=33(www-data)",
		"ping -c 1 example$(whoami)":          "www-data",
		"ping -c 1 example`expr 6 \\* 7`":     "42",
		"ping -c 1 example&&cat /etc/passwd":  "root:x:0:0",
	} {
		if got := fakeShell(in); !strings.Contains(got, want) {
			t.Errorf("fakeShell(%q) = %q, want it to contain %q", in, got, want)
		}
	}
	if got := fakeShell("ping -c 1 example.com"); strings.Contains(got, "uid=") || strings.Contains(got, "not found") {
		t.Errorf("a plain host must only ping: %q", got)
	}
}

func TestRenderTemplate(t *testing.T) {
	for in, want := range map[string]string{"{{7*7}}": "49", "${3*4}": "12", "<%= 2*5 %>": "10", "#{1+1}": "2", "guest": "guest"} {
		if got := renderTemplate(in); got != want {
			t.Errorf("renderTemplate(%q) = %q, want %q", in, got, want)
		}
	}
}
