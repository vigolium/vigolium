package graphql_scan

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/graphqlx"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestConfirmRounds(t *testing.T) {
	// All-true across rounds → confirmed.
	calls := 0
	if !confirmRounds(3, func() (bool, error) { calls++; return true, nil }) {
		t.Error("expected confirmed when all rounds true")
	}
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}

	// One false short-circuits.
	calls = 0
	if confirmRounds(3, func() (bool, error) { calls++; return calls < 2, nil }) {
		t.Error("expected not confirmed when a round is false")
	}
	if calls != 2 {
		t.Errorf("expected short-circuit at 2 calls, got %d", calls)
	}

	// Error short-circuits to false.
	if confirmRounds(3, func() (bool, error) { return true, errTest }) {
		t.Error("expected not confirmed on error")
	}

	// rounds < 1 behaves as 1.
	calls = 0
	confirmRounds(0, func() (bool, error) { calls++; return true, nil })
	if calls != 1 {
		t.Errorf("rounds<1 should run once, ran %d", calls)
	}
}

var errTest = &testErr{}

type testErr struct{}

func (*testErr) Error() string { return "test" }

func TestGqlRespIsHTML(t *testing.T) {
	if (&gqlResp{ctype: "application/json; charset=utf-8"}).isHTML() {
		t.Error("json content-type should not be HTML")
	}
	if !(&gqlResp{ctype: "text/html; charset=utf-8"}).isHTML() {
		t.Error("html content-type should be HTML")
	}
}

func TestMatchConsole(t *testing.T) {
	cases := []struct {
		name string
		resp *gqlResp
		want string
	}{
		{"graphiql", &gqlResp{status: 200, ctype: "text/html", body: `<html><title>GraphiQL</title></html>`}, "GraphiQL"},
		{"playground", &gqlResp{status: 200, ctype: "text/html", body: `<div>GraphQL Playground</div>`}, "GraphQL Playground"},
		{"altair", &gqlResp{status: 200, ctype: "text/html", body: `<app-altair></app-altair>`}, "Altair GraphQL"},
		{"json mentioning graphiql not matched", &gqlResp{status: 200, ctype: "application/json", body: `{"errors":[{"message":"see GraphiQL"}]}`}, ""},
		{"404 html not matched", &gqlResp{status: 404, ctype: "text/html", body: `<title>GraphiQL</title>`}, ""},
		{"no marker", &gqlResp{status: 200, ctype: "text/html", body: `<html>hi</html>`}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchConsole(tc.resp); got != tc.want {
				t.Errorf("matchConsole = %q want %q", got, tc.want)
			}
		})
	}
}

func TestBatchBuildersAndCounters(t *testing.T) {
	arr := buildArrayBatch(3)
	if strings.Count(arr, "__typename") != 3 || !strings.HasPrefix(arr, "[") {
		t.Errorf("buildArrayBatch malformed: %s", arr)
	}
	alias := buildAliasBatch(3)
	for _, a := range []string{"a0:", "a1:", "a2:"} {
		if !strings.Contains(alias, a) {
			t.Errorf("alias batch missing %s: %s", a, alias)
		}
	}

	arrResp := `[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`
	if n := countArrayResults(arrResp); n != 3 {
		t.Errorf("countArrayResults = %d want 3", n)
	}
	if n := countArrayResults(`{"data":{"__typename":"Query"}}`); n != 0 {
		t.Errorf("non-array should count 0, got %d", n)
	}
	if n := countArrayResults(`[{"errors":[{"message":"x"}]},{"data":{"__typename":"Q"}}]`); n != 1 {
		t.Errorf("partial batch count = %d want 1", n)
	}

	aliasResp := `{"data":{"a0":"Query","a1":"Query","a2":"Query"}}`
	if n := countAliasResults(aliasResp, 3); n != 3 {
		t.Errorf("countAliasResults = %d want 3", n)
	}
	if n := countAliasResults(`{"data":{"a0":"Query"}}`, 3); n != 1 {
		t.Errorf("partial alias count = %d want 1", n)
	}
}

func TestFieldObject(t *testing.T) {
	present, norm := fieldObject(`{"data":{"user":{"id":"1","name":"a"}}}`, "user")
	if !present || !strings.Contains(norm, `"name":"a"`) {
		t.Errorf("expected present object, got present=%v norm=%q", present, norm)
	}
	if p, _ := fieldObject(`{"data":{"user":null}}`, "user"); p {
		t.Error("null must be absent")
	}
	if p, _ := fieldObject(`{"data":{"user":"scalar"}}`, "user"); p {
		t.Error("scalar echo must not count as an object")
	}
	if p, _ := fieldObject(`{"errors":[{"message":"nope"}]}`, "user"); p {
		t.Error("error response must be absent")
	}
}

func TestIDLiteralAndControl(t *testing.T) {
	if idLiteral("Int", "1") != "1" {
		t.Error("int literal should be bare")
	}
	if idLiteral("ID", "1") != `"1"` {
		t.Error("ID literal should be quoted")
	}
	if idLiteral("String", "1") != `"1"` {
		t.Error("string literal should be quoted")
	}
	if controlValue("Int") != "999999999" {
		t.Error("int control")
	}
	if controlValue("String") == "" || controlValue("ID") == "" {
		t.Error("control values must be non-empty")
	}
}

func TestHasDepthLimitMarker(t *testing.T) {
	if !hasDepthLimitMarker(`{"errors":[{"message":"Query exceeds maximum operation depth of 5"}]}`) {
		t.Error("should detect depth-limit error")
	}
	if !hasDepthLimitMarker(`{"errors":[{"message":"query is too complex"}]}`) {
		t.Error("should detect complexity error")
	}
	if hasDepthLimitMarker(`{"data":{"user":{"manager":null}}}`) {
		t.Error("normal data must not be a depth-limit marker")
	}
}

func TestCollectXSSCandidates_PrefersNonString(t *testing.T) {
	body := `{"data":{"__schema":{
		"queryType":{"name":"Query"},
		"types":[{"kind":"OBJECT","name":"Query","fields":[
			{"name":"byName","args":[{"name":"name","type":{"kind":"SCALAR","name":"String","ofType":null}}],"type":{"kind":"SCALAR","name":"String","ofType":null}},
			{"name":"byId","args":[{"name":"id","type":{"kind":"SCALAR","name":"Int","ofType":null}}],"type":{"kind":"SCALAR","name":"String","ofType":null}}
		]}]
	}}}`
	schema, ok := graphqlx.ParseSchema([]byte(body))
	if !ok {
		t.Fatal("schema parse failed")
	}
	cands := collectXSSCandidates(schema)
	if len(cands) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(cands))
	}
	// Non-string (Int) arg must be probed first.
	if cands[0].field.Name != "byId" || cands[0].arg != "id" {
		t.Errorf("expected Int-arg candidate first, got %s(%s)", cands[0].field.Name, cands[0].arg)
	}
}

func TestBatchExecutionRemainsCandidate(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(strings.TrimSpace(string(body)), "[") {
			parts := make([]string, batchProbeSize)
			for i := range parts {
				parts[i] = `{"data":{"__typename":"Query"}}`
			}
			_, _ = w.Write([]byte("[" + strings.Join(parts, ",") + "]"))
			return
		}
		aliases := make([]string, batchProbeSize)
		for i := range aliases {
			aliases[i] = fmt.Sprintf(`"a%d":"Query"`, i)
		}
		_, _ = w.Write([]byte(`{"data":{` + strings.Join(aliases, ",") + `}}`))
	}))
	defer srv.Close()

	ctx := modtest.Request(t, srv.URL+"/")
	result := New().phaseBatching(ctx, modtest.Requester(t), "/graphql", srv.URL)
	if result == nil {
		t.Fatal("expected batch capability result")
	}
	if result.RecordKind != output.RecordKindCandidate || result.EvidenceGrade != output.EvidenceGradeCandidate {
		t.Fatalf("batch capability must not default to finding: kind=%q grade=%q", result.RecordKind, result.EvidenceGrade)
	}
	if result.Metadata["rate_limit_bypassed"] != false {
		t.Fatal("executing harmless aliases must not claim a rate-limit bypass")
	}
}
