package graphql_scan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestParseIntrospectionResponse(t *testing.T) {
	body := `{
		"data": {
			"__schema": {
				"types": [
					{
						"name": "Query",
						"fields": [
							{
								"name": "user",
								"args": [
									{
										"name": "id",
										"type": {"name": "ID", "kind": "SCALAR", "ofType": null}
									},
									{
										"name": "name",
										"type": {"name": "String", "kind": "SCALAR", "ofType": null}
									}
								]
							},
							{
								"name": "search",
								"args": [
									{
										"name": "query",
										"type": {"name": null, "kind": "NON_NULL", "ofType": {"name": "String"}}
									}
								]
							}
						]
					},
					{
						"name": "__Type",
						"fields": [
							{
								"name": "name",
								"args": []
							}
						]
					}
				]
			}
		}
	}`

	fields := parseIntrospectionResponse(body)
	if len(fields) != 3 {
		t.Fatalf("expected 3 fields, got %d", len(fields))
	}

	// Check first field
	if fields[0].fieldName != "user" || fields[0].argName != "id" {
		t.Errorf("field[0] = %v, want user(id)", fields[0])
	}
	if fields[1].fieldName != "user" || fields[1].argName != "name" {
		t.Errorf("field[1] = %v, want user(name)", fields[1])
	}
	if fields[2].fieldName != "search" || fields[2].argName != "query" {
		t.Errorf("field[2] = %v, want search(query)", fields[2])
	}
}

func TestParseIntrospectionResponse_Invalid(t *testing.T) {
	fields := parseIntrospectionResponse("not json")
	if fields != nil {
		t.Error("expected nil for invalid JSON")
	}
}

func TestParseIntrospectionResponse_SkipsInternalTypes(t *testing.T) {
	body := `{
		"data": {
			"__schema": {
				"types": [
					{
						"name": "__Type",
						"fields": [
							{
								"name": "name",
								"args": [
									{"name": "test", "type": {"name": "String", "kind": "SCALAR", "ofType": null}}
								]
							}
						]
					}
				]
			}
		}
	}`

	fields := parseIntrospectionResponse(body)
	if len(fields) != 0 {
		t.Errorf("expected 0 fields (internal types skipped), got %d", len(fields))
	}
}

func TestContainsSQLError(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "MySQL error",
			body: `{"errors":[{"message":"You have an error in your SQL syntax near '1'='1'"}]}`,
			want: true,
		},
		{
			name: "PostgreSQL error",
			body: `{"errors":[{"message":"ERROR:  syntax error at or near \"'\""}]}`,
			want: true,
		},
		{
			name: "Oracle error",
			body: `{"errors":[{"message":"ORA-01756: quoted string not properly terminated"}]}`,
			want: true,
		},
		{
			name: "SQLite error",
			body: `near "x": syntax error`,
			want: false,
		},
		{
			name: "MSSQL unclosed quotation",
			body: `{"errors":[{"message":"Unclosed quotation mark after the character string"}]}`,
			want: true,
		},
		{
			name: "no error",
			body: `{"data":{"user":null}}`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsSQLError(tt.body)
			if got != tt.want {
				t.Errorf("containsSQLError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsGraphQLEndpoint(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"typename response", `{"data":{"__typename":"Query"}}`, true},
		{"data null", `{"data":null}`, false},
		{"generic data object", `{"data":{"status":"ok"}}`, false},
		{"typename outside data", `{"message":"__typename"}`, false},
		{"html not found", `<html>Not Found</html>`, false},
		{"error not found", `{"error":"not found"}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isGraphQLEndpoint(tt.body)
			if got != tt.want {
				t.Errorf("isGraphQLEndpoint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasIntrospection(t *testing.T) {
	good := `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"kind":"OBJECT","name":"Query","fields":[]}]}}}`
	if !hasIntrospection(good) {
		t.Error("expected true for valid introspection response")
	}

	bad := `{"data":{"user":null}}`
	if hasIntrospection(bad) {
		t.Error("expected false for non-introspection response")
	}
}

func TestContainsSQLErrorRequiresGraphQLErrorEnvelope(t *testing.T) {
	if containsSQLError(`{"message":"You have an error in your SQL syntax"}`) {
		t.Fatal("a generic JSON message must not be treated as a GraphQL resolver error")
	}
	if containsSQLError(`<html>You have an error in your SQL syntax</html>`) {
		t.Fatal("an HTML/proxy error must not be treated as GraphQL SQL injection")
	}
	if !containsSQLError(`{"errors":[{"message":"You have an error in your SQL syntax near quote"}]}`) {
		t.Fatal("a structured GraphQL database error should remain visible")
	}
}

func TestIntrospectionIsObservationNotFinding(t *testing.T) {
	t.Parallel()
	const schema = `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,"subscriptionType":null,"types":[{"kind":"OBJECT","name":"Query","fields":[{"name":"health","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}}]},{"kind":"SCALAR","name":"String","fields":[]}]}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case string(body) == typenameQuery:
			_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
		case strings.Contains(string(body), "IntrospectionQuery"):
			_, _ = w.Write([]byte(schema))
		default:
			_, _ = w.Write([]byte(`{"errors":[{"message":"unknown field"}]}`))
		}
	}))
	defer srv.Close()

	ctx := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")
	results, err := New().ScanPerRequest(ctx, modtest.Requester(t), &modkit.ScanContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected only the introspection observation, got %d results", len(results))
	}
	if results[0].RecordKind != output.RecordKindObservation || results[0].EvidenceGrade != output.EvidenceGradeObservation {
		t.Fatalf("introspection must be an observation, got kind=%q grade=%q", results[0].RecordKind, results[0].EvidenceGrade)
	}
}

func TestEscapeJSON(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`hello`, `hello`},
		{`say "hi"`, `say \"hi\"`},
		{"line\nnewline", `line\nnewline`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := escapeJSON(tt.input)
			if got != tt.want {
				t.Errorf("escapeJSON(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
