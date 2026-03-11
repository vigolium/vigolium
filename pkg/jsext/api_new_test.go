package jsext

import (
	"strings"
	"testing"

	"github.com/grafana/sobek"
)

// newTestVM creates a Sobek VM with vigolium.utils, vigolium.parse, vigolium.payloads, and vigolium.http.buildRequest set up.
func newTestVM(t *testing.T) *sobek.Runtime {
	t.Helper()
	vm := sobek.New()
	vigolium := vm.NewObject()
	_ = vm.Set("vigolium", vigolium)
	setupUtilsAPI(vm, APIOptions{})
	setupParseAPI(vm)
	setupPayloadsAPI(vm)
	// Set up http namespace with buildRequest only (no actual HTTP client)
	httpObj := vm.NewObject()
	_ = httpObj.Set("buildRequest", func(call sobek.FunctionCall) sobek.Value {
		rawReq := call.Argument(0).String()
		overridesVal := call.Argument(1)
		if sobek.IsUndefined(overridesVal) || sobek.IsNull(overridesVal) {
			return vm.ToValue(rawReq)
		}
		return vm.ToValue(applyRequestOverrides(vm, rawReq, overridesVal.ToObject(vm)))
	})
	_ = vigolium.Set("http", httpObj)
	return vm
}

// --- diff tests ---

func TestUtilsDiff(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`
		var result = vigolium.utils.diff("line1\nline2\nline3", "line1\nline4\nline3");
		JSON.stringify(result);
	`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s := val.String()
	if !strings.Contains(s, `"line4"`) {
		t.Error("expected 'line4' in added")
	}
	if !strings.Contains(s, `"line2"`) {
		t.Error("expected 'line2' in removed")
	}
	if !strings.Contains(s, `"similarity"`) {
		t.Error("expected similarity field")
	}
}

func TestUtilsDiffIdentical(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`vigolium.utils.diff("hello", "hello").similarity`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.ToFloat() != 1.0 {
		t.Errorf("expected similarity 1.0 for identical strings, got %v", val.ToFloat())
	}
}

func TestUtilsDiffCompleteDifference(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`vigolium.utils.diff("aaa", "bbb").similarity`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.ToFloat() != 0.0 {
		t.Errorf("expected similarity 0.0 for completely different strings, got %v", val.ToFloat())
	}
}

// --- similarity tests ---

func TestUtilsSimilarityIdentical(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`vigolium.utils.similarity("hello world", "hello world")`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.ToFloat() != 1.0 {
		t.Errorf("expected 1.0, got %v", val.ToFloat())
	}
}

func TestUtilsSimilarityDifferent(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`vigolium.utils.similarity("foo bar baz", "qux quux corge")`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.ToFloat() != 0.0 {
		t.Errorf("expected 0.0, got %v", val.ToFloat())
	}
}

func TestUtilsSimilarityPartial(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`vigolium.utils.similarity("foo bar baz", "foo bar qux")`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sim := val.ToFloat()
	if sim <= 0.0 || sim >= 1.0 {
		t.Errorf("expected partial similarity, got %v", sim)
	}
}

func TestUtilsSimilarityEmpty(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`vigolium.utils.similarity("", "")`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.ToFloat() != 1.0 {
		t.Errorf("expected 1.0 for two empty strings, got %v", val.ToFloat())
	}
}

// --- payloads tests ---

func TestPayloadsXSS(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`vigolium.payloads("xss").length`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.ToInteger() == 0 {
		t.Error("expected non-empty xss payloads")
	}
}

func TestPayloadsSQLi(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`vigolium.payloads("sqli").length`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.ToInteger() == 0 {
		t.Error("expected non-empty sqli payloads")
	}
}

func TestPayloadsAllTypes(t *testing.T) {
	vm := newTestVM(t)
	types := []string{"xss", "sqli", "ssti", "ssrf", "lfi", "path_traversal", "xxe", "cmdi", "open_redirect", "crlf"}
	for _, typ := range types {
		val, err := vm.RunString(`vigolium.payloads("` + typ + `").length`)
		if err != nil {
			t.Fatalf("unexpected error for type %s: %v", typ, err)
		}
		if val.ToInteger() == 0 {
			t.Errorf("expected non-empty payloads for type %s", typ)
		}
	}
}

func TestPayloadsUnknownType(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`vigolium.payloads("nonexistent").length`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val.ToInteger() != 0 {
		t.Error("expected empty array for unknown type")
	}
}

// --- buildRequest tests ---

func TestBuildRequestMethodOverride(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`
		var raw = "GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n";
		vigolium.http.buildRequest(raw, {method: "POST"});
	`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := val.String()
	if !strings.HasPrefix(result, "POST /api/test HTTP/1.1\r\n") {
		t.Errorf("expected POST method, got: %s", result[:50])
	}
}

func TestBuildRequestPathOverride(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`
		var raw = "GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n";
		vigolium.http.buildRequest(raw, {path: "/admin"});
	`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := val.String()
	if !strings.Contains(result, "GET /admin HTTP/1.1") {
		t.Errorf("expected /admin path, got: %s", result)
	}
}

func TestBuildRequestHeadersMerge(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`
		var raw = "GET /api HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n";
		vigolium.http.buildRequest(raw, {headers: {"X-Custom": "test", "Accept": "application/json"}});
	`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := val.String()
	if !strings.Contains(result, "X-Custom: test") {
		t.Error("expected new header X-Custom")
	}
	if !strings.Contains(result, "Accept: application/json") {
		t.Error("expected Accept header to be overridden")
	}
	// Original Accept: text/html should be gone
	if strings.Contains(result, "Accept: text/html") {
		t.Error("expected original Accept header to be replaced")
	}
}

func TestBuildRequestBodyOverride(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`
		var raw = "POST /api HTTP/1.1\r\nHost: example.com\r\n\r\noriginal=body";
		vigolium.http.buildRequest(raw, {body: "new=body"});
	`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := val.String()
	if !strings.HasSuffix(result, "new=body") {
		t.Errorf("expected body override, got: %s", result)
	}
}

func TestBuildRequestQueryMerge(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`
		var raw = "GET /api?a=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
		vigolium.http.buildRequest(raw, {query: {"b": "2"}});
	`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result := val.String()
	if !strings.Contains(result, "a=1") {
		t.Error("expected original query param a=1")
	}
	if !strings.Contains(result, "b=2") {
		t.Error("expected new query param b=2")
	}
}

// --- parse.html tests ---

func TestParseHTMLForms(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`
		var html = '<html><body><form action="/login" method="POST"><input name="user" type="text"><input name="pass" type="password"></form></body></html>';
		var result = vigolium.parse.html(html);
		JSON.stringify({
			formCount: result.forms.length,
			action: result.forms[0].action,
			method: result.forms[0].method,
			inputCount: result.forms[0].inputs.length,
			firstName: result.forms[0].inputs[0].name
		});
	`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := val.String()
	if !strings.Contains(s, `"formCount":1`) {
		t.Error("expected 1 form")
	}
	if !strings.Contains(s, `"action":"/login"`) {
		t.Error("expected action /login")
	}
	if !strings.Contains(s, `"method":"POST"`) {
		t.Error("expected method POST")
	}
	if !strings.Contains(s, `"inputCount":2`) {
		t.Error("expected 2 inputs")
	}
	if !strings.Contains(s, `"firstName":"user"`) {
		t.Error("expected first input name 'user'")
	}
}

func TestParseHTMLLinks(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`
		var html = '<html><body><a href="/about">About Us</a><a href="https://ext.com">External</a></body></html>';
		var result = vigolium.parse.html(html);
		JSON.stringify({count: result.links.length, first: result.links[0].href, text: result.links[0].text});
	`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := val.String()
	if !strings.Contains(s, `"count":2`) {
		t.Error("expected 2 links")
	}
	if !strings.Contains(s, `"first":"/about"`) {
		t.Error("expected first link /about")
	}
	if !strings.Contains(s, `"text":"About Us"`) {
		t.Error("expected link text 'About Us'")
	}
}

func TestParseHTMLScripts(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`
		var html = '<html><head><script src="/app.js"></script><script>var x = 1;</script></head></html>';
		var result = vigolium.parse.html(html);
		JSON.stringify({count: result.scripts.length, src: result.scripts[0].src, inline: result.scripts[1].content});
	`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := val.String()
	if !strings.Contains(s, `"count":2`) {
		t.Error("expected 2 scripts")
	}
	if !strings.Contains(s, `"src":"/app.js"`) {
		t.Error("expected script src /app.js")
	}
	if !strings.Contains(s, `var x = 1;`) {
		t.Error("expected inline script content")
	}
}

func TestParseHTMLMeta(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`
		var html = '<html><head><meta name="description" content="test page"><meta property="og:title" content="Test"></head></html>';
		var result = vigolium.parse.html(html);
		JSON.stringify({count: result.meta.length, name0: result.meta[0].name, content0: result.meta[0].content});
	`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := val.String()
	if !strings.Contains(s, `"count":2`) {
		t.Error("expected 2 meta tags")
	}
	if !strings.Contains(s, `"name0":"description"`) {
		t.Error("expected meta name 'description'")
	}
	if !strings.Contains(s, `"content0":"test page"`) {
		t.Error("expected meta content 'test page'")
	}
}

func TestParseHTMLEmpty(t *testing.T) {
	vm := newTestVM(t)

	val, err := vm.RunString(`
		var result = vigolium.parse.html('<html></html>');
		JSON.stringify({f: result.forms.length, l: result.links.length, s: result.scripts.length, m: result.meta.length});
	`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := val.String()
	if s != `{"f":0,"l":0,"s":0,"m":0}` {
		t.Errorf("expected all empty arrays, got: %s", s)
	}
}
