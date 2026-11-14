package main

import (
	"bytes"
	"strings"
	"testing"
)

const baseJSONL = `{"commit":"a","case_id":"c1","module":"m1","assertion":"strict","findings":2,"requests":100,"passed":true}
{"commit":"a","case_id":"c2","module":"m2","assertion":"strict","findings":1,"requests":10,"passed":true}
{"commit":"a","case_id":"c3","module":"m3","assertion":"negative","findings":0,"requests":5,"passed":true}
{"commit":"a","case_id":"c4","module":"m4","assertion":"soft","findings":0,"requests":5,"passed":true}
`

func mustParse(t *testing.T, s string) map[string]record {
	t.Helper()
	m, err := parse(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDiff_NoChangeNoRegression(t *testing.T) {
	b := mustParse(t, baseJSONL)
	var out bytes.Buffer
	if n := diff(&out, b, b, 0.25, false); n != 0 {
		t.Fatalf("regressions = %d, want 0\n%s", n, out.String())
	}
}

func TestDiff_Regressions(t *testing.T) {
	b := mustParse(t, baseJSONL)
	h := mustParse(t, `{"case_id":"c1","module":"m1","assertion":"strict","findings":1,"requests":100,"passed":true}
{"case_id":"c2","module":"m2","assertion":"strict","findings":0,"requests":10,"passed":false}
{"case_id":"c4","module":"m4","assertion":"soft","findings":0,"requests":50,"passed":true}
`)
	var out bytes.Buffer
	n := diff(&out, b, h, 0.25, false)
	// c1 findings dropped; c2 passed->failed and findings dropped; c3 missing.
	if n != 4 {
		t.Fatalf("regressions = %d, want 4\n%s", n, out.String())
	}
	if !strings.Contains(out.String(), "requests   c4 / m4: requests 5 -> 50") {
		t.Fatalf("request drift not reported:\n%s", out.String())
	}

	out.Reset()
	if n := diff(&out, b, h, 0.25, true); n != 5 {
		t.Fatalf("with -strict-requests regressions = %d, want 5\n%s", n, out.String())
	}
}

func TestParse_LastLineWins(t *testing.T) {
	m := mustParse(t, `{"case_id":"c","module":"m","findings":1}
{"case_id":"c","module":"m","findings":3}
`)
	if got := m["c / m"].Findings; got != 3 {
		t.Fatalf("findings = %d, want 3", got)
	}
}
