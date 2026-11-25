package requesttransform

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type vectorRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    *string           `json:"body"`
}

type vector struct {
	Name      string            `json:"name"`
	Transform json.RawMessage   `json:"transform"`
	Keys      map[string]string `json:"keys"`
	Now       int64             `json:"now"`
	Fixed     map[string]string `json:"fixed"`
	Vars      map[string]string `json:"vars"`
	Request   vectorRequest     `json:"request"`
	Expect    *vectorRequest    `json:"expect"`
	Refusal   string            `json:"refusal"`
}

const vectorsFile = "testdata/request-transform.json"

func loadVectors(t *testing.T) []vector {
	t.Helper()
	data, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return doc.Vectors
}

func run(v vector) (Request, *Refusal) {
	tr, r := Decode(v.Transform)
	if r != nil {
		return Request{}, r
	}
	env := Env{
		Now:    func() int64 { return v.Now },
		Key:    func(name string) (string, bool) { k, ok := v.Keys[name]; return k, ok },
		Random: func(int) []byte { panic("a vector needs randomness") },
		Fixed:  v.Fixed,
		Vars:   v.Vars,
	}
	out, _, r := Evaluate(tr, Request{Method: v.Request.Method, URL: v.Request.URL, Headers: v.Request.Headers, Body: v.Request.Body}, env)
	return out, r
}

// TestConformanceVectors answers every vector exactly as gimorra's evaluator
// does: the transformed request byte for byte, or the same refusal code.
func TestConformanceVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			out, r := run(v)
			if v.Refusal != "" {
				if r == nil {
					t.Fatalf("admitted, want refusal %q", v.Refusal)
				}
				if r.Code != v.Refusal {
					t.Fatalf("refusal %q (%s), want %q", r.Code, r.Detail, v.Refusal)
				}
				return
			}
			if r != nil {
				t.Fatalf("refused %s: %s", r.Code, r.Detail)
			}
			e := v.Expect
			if out.Method != e.Method || out.URL != e.URL {
				t.Fatalf("got %s %s, want %s %s", out.Method, out.URL, e.Method, e.URL)
			}
			if len(out.Headers) != len(e.Headers) {
				t.Fatalf("headers %v, want %v", out.Headers, e.Headers)
			}
			for k, want := range e.Headers {
				if out.Headers[k] != want {
					t.Fatalf("header %s = %q, want %q", k, out.Headers[k], want)
				}
			}
			if (out.Body == nil) != (e.Body == nil) || (out.Body != nil && *out.Body != *e.Body) {
				t.Fatalf("body %v, want %v", deref(out.Body), deref(e.Body))
			}
		})
	}
}

func deref(s *string) string {
	if s == nil {
		return "(absent)"
	}
	return *s
}

// TestVectorsMatchGimorra pins this copy of the vectors to gimorra's, so the
// two evaluators are held to one file.
func TestVectorsMatchGimorra(t *testing.T) {
	path := os.Getenv("GIMORRA_TRANSFORM_VECTORS")
	if path == "" {
		path = filepath.Join("..", "..", "..", "gimorra", "packages", "validators", "conformance", "request-transform.json")
	}
	theirs, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("gimorra's vectors are not beside this checkout (%v)", err)
	}
	ours, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ours, theirs) {
		t.Fatalf("%s differs from %s - copy gimorra's file byte for byte", vectorsFile, path)
	}
}

// TestDestinationIsNotAddressable holds the invariant the scope guard rests
// on: a transformed request goes to the origin it was given.
func TestDestinationIsNotAddressable(t *testing.T) {
	for _, v := range loadVectors(t) {
		out, r := run(v)
		if r != nil {
			continue
		}
		if SplitURL(out.URL).Origin != SplitURL(v.Request.URL).Origin {
			t.Fatalf("%s: origin moved %s -> %s", v.Name, v.Request.URL, out.URL)
		}
		if _, ok := out.Headers["host"]; ok {
			t.Fatalf("%s: wrote a Host header", v.Name)
		}
	}
	for _, h := range []string{"Host", ":authority", "X-Forwarded-Host", "Forwarded", "X-HTTP-Method-Override", "Content-Length"} {
		doc := `{"id":"x","applies":{"host":"a.test"},"ops":[{"op":"set-header","header":"` + h + `","value":"evil.test"}]}`
		if _, r := Decode([]byte(doc)); r == nil || r.Code != "destination-header" {
			t.Fatalf("%s: %v, want destination-header", h, r)
		}
	}
	for _, doc := range []string{
		`{"id":"x","applies":{"host":"a.test"},"scheme":"http","ops":[{"op":"set-header","header":"X","value":"1"}]}`,
		`{"id":"x","applies":{"host":"a.test","port":8080},"ops":[{"op":"set-header","header":"X","value":"1"}]}`,
		`{"id":"x","applies":{"host":"a.test"},"ops":[{"op":"set-header","header":"X","value":"1","host":"evil.test"}]}`,
	} {
		if _, r := Decode([]byte(doc)); r == nil || r.Code != "bad-shape" {
			t.Fatalf("%s: %v, want bad-shape", doc, r)
		}
	}
}

func TestForPicksLongestPrefix(t *testing.T) {
	mk := func(doc string) *Transform {
		tr, r := Decode([]byte(doc))
		if r != nil {
			t.Fatal(r)
		}
		return tr
	}
	host := mk(`{"id":"h","applies":{"host":"api.test"},"ops":[{"op":"set-header","header":"X","value":"1"}]}`)
	route := mk(`{"id":"r","applies":{"host":"api.test","pathPrefix":"/v2/"},"ops":[{"op":"set-header","header":"X","value":"2"}]}`)
	list := []*Transform{host, route}
	if got := For(list, "https://api.test:8443/v2/x"); got != route {
		t.Fatalf("got %v", got)
	}
	if got := For(list, "https://API.test/v1"); got != host {
		t.Fatalf("got %v", got)
	}
	if got := For(list, "https://other.test/v2/x"); got != nil {
		t.Fatalf("got %v", got)
	}
	if !strings.HasPrefix(SplitURL("https://u:p@Api.Test:1/a?b#c").Host, "api.test") {
		t.Fatal("host")
	}
}
