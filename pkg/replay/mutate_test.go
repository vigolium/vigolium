package replay

import (
	"testing"
)

func TestParseMutationFlag(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		want  Mutation
		isErr bool
	}{
		{name: "key=value form", in: "name=id,payload=1 OR 1=1", want: Mutation{Name: "id", Payload: "1 OR 1=1"}},
		{name: "key=value with type", in: "name=q,type=URL_PARAM,payload=<svg>", want: Mutation{Name: "q", Type: "URL_PARAM", Payload: "<svg>"}},
		{name: "shorthand 2-part", in: "id:1 OR 1=1", want: Mutation{Name: "id", Payload: "1 OR 1=1"}},
		{name: "shorthand 3-part", in: "q:URL_PARAM:<svg>", want: Mutation{Name: "q", Type: "URL_PARAM", Payload: "<svg>"}},
		{name: "missing payload", in: "name=id", isErr: true},
		{name: "missing name", in: "payload=foo", isErr: true},
		{name: "escaped comma in payload", in: `name=p,payload=a\,b`, want: Mutation{Name: "p", Payload: "a,b"}},
		{name: "unknown key", in: "nope=1,payload=2", isErr: true},
		{name: "empty", in: "", isErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMutationFlag(tt.in)
			if tt.isErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseHeaderFlag(t *testing.T) {
	tests := []struct {
		in        string
		wantName  string
		wantValue string
		isErr     bool
	}{
		{in: "X-Foo: bar", wantName: "X-Foo", wantValue: "bar"},
		{in: "X-Foo=bar", wantName: "X-Foo", wantValue: "bar"},
		{in: "Authorization: Bearer eyJ...", wantName: "Authorization", wantValue: "Bearer eyJ..."},
		{in: "bare-no-separator", isErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			n, v, err := ParseHeaderFlag(tt.in)
			if tt.isErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if n != tt.wantName || v != tt.wantValue {
				t.Errorf("got (%q, %q), want (%q, %q)", n, v, tt.wantName, tt.wantValue)
			}
		})
	}
}

func TestApplyMutationsBasic(t *testing.T) {
	raw := []byte("GET /?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	mutations := []Mutation{{Name: "id", Payload: "999"}}
	mutated, payloads, unmatched, _, err := applyMutations(raw, mutations)
	if err != nil {
		t.Fatalf("applyMutations: %v", err)
	}
	if len(unmatched) != 0 {
		t.Fatalf("unexpected unmatched: %v", unmatched)
	}
	if string(payloads[0]) != "999" {
		t.Errorf("payloads[0] = %q, want 999", payloads[0])
	}
	if !contains(string(mutated), "id=999") {
		t.Errorf("mutated request should contain id=999, got: %s", mutated)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
