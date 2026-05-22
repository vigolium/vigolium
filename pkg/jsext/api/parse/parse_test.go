package parse

import (
	"strings"
	"testing"

	"github.com/grafana/sobek"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/jsext/api"
	"golang.org/x/net/html"
)

// handlerFor builds a bare sobek runtime and returns the invocable handler for
// the named parse function. This drives the handler factory bodies directly
// without standing up the full jsext engine.
func handlerFor(t *testing.T, name string) (*sobek.Runtime, func(sobek.FunctionCall) sobek.Value) {
	t.Helper()
	vm := sobek.New()
	for _, d := range FuncDefs() {
		if d.Name == name {
			require.NotNil(t, d.MakeHandler)
			return vm, d.MakeHandler(vm, api.APIOptions{ScriptID: "test"})
		}
	}
	t.Fatalf("parse function %q not found", name)
	return nil, nil
}

// call invokes a handler with the given string argument.
func call(vm *sobek.Runtime, h func(sobek.FunctionCall) sobek.Value, arg string) sobek.Value {
	return h(sobek.FunctionCall{Arguments: []sobek.Value{vm.ToValue(arg)}})
}

func TestSplitHTTPMessage(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		wantHeader string
		wantBody   string
	}{
		{
			name:       "crlf separator",
			raw:        "GET / HTTP/1.1\r\nHost: x\r\n\r\nbody",
			wantHeader: "GET / HTTP/1.1\r\nHost: x",
			wantBody:   "body",
		},
		{
			name:       "lf separator",
			raw:        "GET / HTTP/1.1\nHost: x\n\nbody",
			wantHeader: "GET / HTTP/1.1\nHost: x",
			wantBody:   "body",
		},
		{
			name:       "no separator returns all as header",
			raw:        "GET / HTTP/1.1\r\nHost: x",
			wantHeader: "GET / HTTP/1.1\r\nHost: x",
			wantBody:   "",
		},
		{
			name:       "crlf preferred over lf",
			raw:        "h\r\n\r\nb\n\nc",
			wantHeader: "h",
			wantBody:   "b\n\nc",
		},
		{
			name:       "empty body after separator",
			raw:        "h\r\n\r\n",
			wantHeader: "h",
			wantBody:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, b := SplitHTTPMessage(tc.raw)
			assert.Equal(t, tc.wantHeader, h)
			assert.Equal(t, tc.wantBody, b)
		})
	}
}

func TestSplitHeaderLines(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"crlf", "GET / HTTP/1.1\r\nHost: x\r\nAccept: */*", []string{"GET / HTTP/1.1", "Host: x", "Accept: */*"}},
		{"lf only", "GET / HTTP/1.1\nHost: x", []string{"GET / HTTP/1.1", "Host: x"}},
		{"trailing cr stripped", "a\r\nb\r", []string{"a", "b"}},
		{"empty lines dropped", "a\n\n\nb", []string{"a", "b"}},
		{"empty input", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, SplitHeaderLines(tc.in))
		})
	}
}

func TestSplitPathQuery(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		wantPath  string
		wantQuery string
	}{
		{"path with query", "/search?q=test&p=1", "/search", "q=test&p=1"},
		{"path no query", "/users", "/users", ""},
		{"empty query after question mark", "/users?", "/users", ""},
		{"root", "/", "/", ""},
		{"empty", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, q := SplitPathQuery(tc.in)
			assert.Equal(t, tc.wantPath, p)
			assert.Equal(t, tc.wantQuery, q)
		})
	}
}

func TestGetAttr(t *testing.T) {
	doc, err := html.Parse(strings.NewReader(`<a href="https://example.com" class="link" data-id="42">x</a>`))
	require.NoError(t, err)

	// Locate the <a> node.
	var anchor *html.Node
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			anchor = n
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	require.NotNil(t, anchor)

	assert.Equal(t, "https://example.com", GetAttr(anchor, "href"))
	assert.Equal(t, "link", GetAttr(anchor, "class"))
	assert.Equal(t, "42", GetAttr(anchor, "data-id"))
	// Missing attribute returns empty string.
	assert.Equal(t, "", GetAttr(anchor, "id"))
}

// TestFuncDefs verifies the declarative parse function definitions are
// internally consistent: non-empty, correctly namespaced, with handlers and
// unique names.
func TestFuncDefs(t *testing.T) {
	defs := FuncDefs()
	require.NotEmpty(t, defs)

	seen := make(map[string]bool, len(defs))
	for _, d := range defs {
		assert.Equal(t, api.NsParse, d.Namespace, "def %q must use the parse namespace", d.Name)
		assert.NotEmpty(t, d.Name)
		assert.NotEmpty(t, d.Signature)
		assert.NotEmpty(t, d.Returns)
		assert.NotEmpty(t, d.Description)
		assert.NotNil(t, d.MakeHandler, "parse def %q should have a handler factory", d.Name)
		assert.False(t, seen[d.FullName()], "duplicate def %q", d.FullName())
		seen[d.FullName()] = true
	}

	// Spot-check the documented set is present.
	for _, want := range []string{"url", "request", "response", "headers", "cookies", "query", "json", "form", "html"} {
		assert.True(t, seen[api.NsParse+"."+want], "expected parse.%s to be defined", want)
	}
}

func TestHandlerURL(t *testing.T) {
	vm, h := handlerFor(t, "url")
	obj := call(vm, h, "https://example.com:8080/api/users?id=1#frag").ToObject(vm)
	assert.Equal(t, "https", obj.Get("scheme").String())
	assert.Equal(t, "example.com:8080", obj.Get("host").String())
	assert.Equal(t, "8080", obj.Get("port").String())
	assert.Equal(t, "/api/users", obj.Get("path").String())
	assert.Equal(t, "frag", obj.Get("fragment").String())
	assert.Equal(t, "1", obj.Get("params").ToObject(vm).Get("id").String())

	// Hard parse error returns null.
	assert.True(t, sobek.IsNull(call(vm, h, "://bad url with spaces")))
}

func TestHandlerRequest(t *testing.T) {
	vm, h := handlerFor(t, "request")
	raw := "POST /login?next=/home HTTP/1.1\r\nHost: example.com\r\nCookie: a=1; b=2\r\n\r\nuser=admin"
	obj := call(vm, h, raw).ToObject(vm)
	assert.Equal(t, "POST", obj.Get("method").String())
	assert.Equal(t, "/login", obj.Get("path").String())
	assert.Equal(t, "next=/home", obj.Get("query").String())
	assert.Equal(t, "1.1", obj.Get("version").String())
	assert.Equal(t, "example.com", obj.Get("host").String())
	assert.Equal(t, "user=admin", obj.Get("body").String())
	assert.Equal(t, "/home", obj.Get("params").ToObject(vm).Get("next").String())
	cookies := obj.Get("cookies").ToObject(vm)
	assert.Equal(t, "1", cookies.Get("a").String())
	assert.Equal(t, "2", cookies.Get("b").String())

	// Empty input returns null.
	assert.True(t, sobek.IsNull(call(vm, h, "")))
}

func TestHandlerResponse(t *testing.T) {
	vm, h := handlerFor(t, "response")
	raw := "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nSet-Cookie: session=abc; Path=/; HttpOnly\r\n\r\n<html>x</html>"
	obj := call(vm, h, raw).ToObject(vm)
	assert.Equal(t, int64(404), obj.Get("status").ToInteger())
	assert.Equal(t, "Not Found", obj.Get("statusText").String())
	assert.Equal(t, "1.1", obj.Get("version").String())
	assert.Equal(t, "text/html", obj.Get("contentType").String())
	assert.Equal(t, "<html>x</html>", obj.Get("body").String())
	assert.Equal(t, "abc", obj.Get("cookies").ToObject(vm).Get("session").String())

	assert.True(t, sobek.IsNull(call(vm, h, "")))
}

func TestHandlerHeaders(t *testing.T) {
	vm, h := handlerFor(t, "headers")
	obj := call(vm, h, "Content-Type: application/json\r\nX-Custom: v\r\nbad-line-no-colon").ToObject(vm)
	assert.Equal(t, "application/json", obj.Get("Content-Type").String())
	assert.Equal(t, "v", obj.Get("X-Custom").String())

	// Null argument yields an empty object (no panic).
	empty := h(sobek.FunctionCall{Arguments: []sobek.Value{sobek.Null()}}).ToObject(vm)
	assert.Empty(t, empty.Keys())
}

func TestHandlerCookies(t *testing.T) {
	vm, h := handlerFor(t, "cookies")
	obj := call(vm, h, "a=1; b=2; novalue").ToObject(vm)
	assert.Equal(t, "1", obj.Get("a").String())
	assert.Equal(t, "2", obj.Get("b").String())
}

func TestHandlerQuery(t *testing.T) {
	vm, h := handlerFor(t, "query")
	obj := call(vm, h, "?id=1&name=foo").ToObject(vm)
	assert.Equal(t, "1", obj.Get("id").String())
	assert.Equal(t, "foo", obj.Get("name").String())

	// Empty string yields empty object.
	assert.Empty(t, call(vm, h, "").ToObject(vm).Keys())
}

func TestHandlerJSON(t *testing.T) {
	vm, h := handlerFor(t, "json")
	obj := call(vm, h, `{"a":1,"b":"x"}`).ToObject(vm)
	assert.Equal(t, int64(1), obj.Get("a").ToInteger())
	assert.Equal(t, "x", obj.Get("b").String())

	// Invalid JSON returns null.
	assert.True(t, sobek.IsNull(call(vm, h, "{not json")))
}

func TestHandlerForm(t *testing.T) {
	vm, h := handlerFor(t, "form")
	obj := call(vm, h, "user=admin&pass=secret").ToObject(vm)
	assert.Equal(t, "admin", obj.Get("user").String())
	assert.Equal(t, "secret", obj.Get("pass").String())

	assert.Empty(t, call(vm, h, "").ToObject(vm).Keys())
}

func TestHandlerHTML(t *testing.T) {
	vm, h := handlerFor(t, "html")
	doc := `<html><head><meta name="generator" content="x"></head><body>
		<a href="/about">About</a>
		<form action="/submit" method="post"><input name="q" type="text" value="v"></form>
		<script src="/app.js"></script>
	</body></html>`
	obj := call(vm, h, doc).ToObject(vm)

	links := obj.Get("links").ToObject(vm)
	assert.Equal(t, int64(1), links.Get("length").ToInteger())
	assert.Equal(t, "/about", links.Get("0").ToObject(vm).Get("href").String())

	forms := obj.Get("forms").ToObject(vm)
	assert.Equal(t, int64(1), forms.Get("length").ToInteger())
	form := forms.Get("0").ToObject(vm)
	assert.Equal(t, "/submit", form.Get("action").String())
	assert.Equal(t, "POST", form.Get("method").String())
	inputs := form.Get("inputs").ToObject(vm)
	assert.Equal(t, "q", inputs.Get("0").ToObject(vm).Get("name").String())

	scripts := obj.Get("scripts").ToObject(vm)
	assert.Equal(t, "/app.js", scripts.Get("0").ToObject(vm).Get("src").String())

	metas := obj.Get("meta").ToObject(vm)
	assert.Equal(t, "generator", metas.Get("0").ToObject(vm).Get("name").String())
}
