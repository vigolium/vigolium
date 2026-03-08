package jsext

import (
	"testing"

	"github.com/grafana/sobek"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupParseTestVM creates a VM with the full API (including parse) installed.
func setupParseTestVM(t *testing.T) *sobek.Runtime {
	t.Helper()
	vm := sobek.New()
	SetupAPI(vm, APIOptions{ScriptID: "test"})
	return vm
}

// ── parse.url ────────────────────────────────────────────────────────────────

func TestParseURLFull(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.url("https://example.com:8080/api/users/123?id=1&name=foo#section")`)
	require.NoError(t, err)
	require.False(t, sobek.IsNull(val))

	obj := val.ToObject(vm)
	assert.Equal(t, "https", obj.Get("scheme").String())
	assert.Equal(t, "example.com:8080", obj.Get("host").String())
	assert.Equal(t, "example.com", obj.Get("hostname").String())
	assert.Equal(t, "8080", obj.Get("port").String())
	assert.Equal(t, "/api/users/123", obj.Get("path").String())
	assert.Equal(t, "id=1&name=foo", obj.Get("query").String())
	assert.Equal(t, "section", obj.Get("fragment").String())
	assert.Equal(t, "/api/users/*", obj.Get("template").String())

	params := obj.Get("params").ToObject(vm)
	assert.Equal(t, "1", params.Get("id").String())
	assert.Equal(t, "foo", params.Get("name").String())

	segments := obj.Get("segments").ToObject(vm)
	assert.Equal(t, int64(3), segments.Get("length").ToInteger())
	assert.Equal(t, "api", segments.Get("0").String())
	assert.Equal(t, "users", segments.Get("1").String())
	assert.Equal(t, "123", segments.Get("2").String())
}

func TestParseURLSimple(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.url("https://example.com/path")`)
	require.NoError(t, err)
	require.False(t, sobek.IsNull(val))

	obj := val.ToObject(vm)
	assert.Equal(t, "https", obj.Get("scheme").String())
	assert.Equal(t, "example.com", obj.Get("hostname").String())
	assert.Equal(t, "", obj.Get("port").String())
	assert.Equal(t, "", obj.Get("query").String())
	assert.Equal(t, "", obj.Get("fragment").String())
}

func TestParseURLRelative(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.url("/api/users/456")`)
	require.NoError(t, err)
	// Relative URLs parse successfully with empty scheme
	obj := val.ToObject(vm)
	assert.Equal(t, "/api/users/456", obj.Get("path").String())
	assert.Equal(t, "/api/users/*", obj.Get("template").String())
}

func TestParseURLInvalid(t *testing.T) {
	vm := setupParseTestVM(t)
	// Go's url.Parse is very permissive; test with an empty string
	val, err := vm.RunString(`vigolium.parse.url("")`)
	require.NoError(t, err)
	obj := val.ToObject(vm)
	assert.Equal(t, "", obj.Get("path").String())
}

// ── parse.request ────────────────────────────────────────────────────────────

func TestParseRequestGET(t *testing.T) {
	vm := setupParseTestVM(t)
	raw := "GET /api/users/123?role=admin HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc; token=xyz\r\nAccept: application/json\r\n\r\n"
	val, err := vm.RunString(`vigolium.parse.request(` + "`" + raw + "`" + `)`)
	require.NoError(t, err)
	require.False(t, sobek.IsNull(val))

	obj := val.ToObject(vm)
	assert.Equal(t, "GET", obj.Get("method").String())
	assert.Equal(t, "/api/users/123", obj.Get("path").String())
	assert.Equal(t, "role=admin", obj.Get("query").String())
	assert.Equal(t, "1.1", obj.Get("version").String())
	assert.Equal(t, "example.com", obj.Get("host").String())
	assert.Equal(t, "", obj.Get("body").String())

	headers := obj.Get("headers").ToObject(vm)
	assert.Equal(t, "example.com", headers.Get("Host").String())
	assert.Equal(t, "application/json", headers.Get("Accept").String())

	params := obj.Get("params").ToObject(vm)
	assert.Equal(t, "admin", params.Get("role").String())

	cookies := obj.Get("cookies").ToObject(vm)
	assert.Equal(t, "abc", cookies.Get("session").String())
	assert.Equal(t, "xyz", cookies.Get("token").String())
}

func TestParseRequestPOST(t *testing.T) {
	vm := setupParseTestVM(t)
	raw := "POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\nusername=admin&password=pass"
	val, err := vm.RunString(`vigolium.parse.request(` + "`" + raw + "`" + `)`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, "POST", obj.Get("method").String())
	assert.Equal(t, "/api/login", obj.Get("path").String())
	assert.Equal(t, "", obj.Get("query").String())
	assert.Equal(t, "username=admin&password=pass", obj.Get("body").String())
}

func TestParseRequestEmpty(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.request("")`)
	require.NoError(t, err)
	assert.True(t, sobek.IsNull(val))
}

// ── parse.response ───────────────────────────────────────────────────────────

func TestParseResponseOK(t *testing.T) {
	vm := setupParseTestVM(t)
	raw := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: session=abc123; HttpOnly\r\nSet-Cookie: tracker=xyz\r\n\r\n{\"id\":1}"
	val, err := vm.RunString(`vigolium.parse.response(` + "`" + raw + "`" + `)`)
	require.NoError(t, err)
	require.False(t, sobek.IsNull(val))

	obj := val.ToObject(vm)
	assert.Equal(t, int64(200), obj.Get("status").ToInteger())
	assert.Equal(t, "OK", obj.Get("statusText").String())
	assert.Equal(t, "1.1", obj.Get("version").String())
	assert.Equal(t, `{"id":1}`, obj.Get("body").String())
	assert.Equal(t, "application/json", obj.Get("contentType").String())

	headers := obj.Get("headers").ToObject(vm)
	assert.Equal(t, "application/json", headers.Get("Content-Type").String())

	cookies := obj.Get("cookies").ToObject(vm)
	assert.Equal(t, "abc123", cookies.Get("session").String())
	assert.Equal(t, "xyz", cookies.Get("tracker").String())
}

func TestParseResponse403(t *testing.T) {
	vm := setupParseTestVM(t)
	raw := "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nAccess denied"
	val, err := vm.RunString(`vigolium.parse.response(` + "`" + raw + "`" + `)`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(403), obj.Get("status").ToInteger())
	assert.Equal(t, "Forbidden", obj.Get("statusText").String())
}

func TestParseResponseEmpty(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.response("")`)
	require.NoError(t, err)
	assert.True(t, sobek.IsNull(val))
}

// ── parse.headers ────────────────────────────────────────────────────────────

func TestParseHeaders(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.headers("Content-Type: application/json\r\nX-Custom: value\r\nAuthorization: Bearer token123")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, "application/json", obj.Get("Content-Type").String())
	assert.Equal(t, "value", obj.Get("X-Custom").String())
	assert.Equal(t, "Bearer token123", obj.Get("Authorization").String())
}

func TestParseHeadersSkipsNonHeaderLines(t *testing.T) {
	vm := setupParseTestVM(t)
	// Request line should be skipped (no colon after non-empty name part, or malformed)
	val, err := vm.RunString(`vigolium.parse.headers("GET / HTTP/1.1\r\nHost: example.com")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, "example.com", obj.Get("Host").String())
}

func TestParseHeadersNull(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.headers(null)`)
	require.NoError(t, err)
	// Should return empty object, not throw
	obj := val.ToObject(vm)
	assert.Equal(t, int64(0), int64(len(obj.Keys())))
}

// ── parse.cookies ────────────────────────────────────────────────────────────

func TestParseCookies(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.cookies("session=abc123; token=xyz; csrf=def456")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, "abc123", obj.Get("session").String())
	assert.Equal(t, "xyz", obj.Get("token").String())
	assert.Equal(t, "def456", obj.Get("csrf").String())
}

func TestParseCookiesEmpty(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.cookies("")`)
	require.NoError(t, err)
	obj := val.ToObject(vm)
	assert.Equal(t, int64(0), int64(len(obj.Keys())))
}

// ── parse.query ──────────────────────────────────────────────────────────────

func TestParseQuery(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.query("id=1&name=foo&active=true")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, "1", obj.Get("id").String())
	assert.Equal(t, "foo", obj.Get("name").String())
	assert.Equal(t, "true", obj.Get("active").String())
}

func TestParseQueryWithLeadingQuestionMark(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.query("?id=42&x=y")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, "42", obj.Get("id").String())
}

func TestParseQueryEmpty(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.query("")`)
	require.NoError(t, err)
	obj := val.ToObject(vm)
	assert.Equal(t, int64(0), int64(len(obj.Keys())))
}

// ── parse.json ───────────────────────────────────────────────────────────────

func TestParseJSONObject(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.json('{"name":"Alice","age":30}')`)
	require.NoError(t, err)
	require.False(t, sobek.IsNull(val))

	obj := val.ToObject(vm)
	assert.Equal(t, "Alice", obj.Get("name").String())
	assert.Equal(t, int64(30), obj.Get("age").ToInteger())
}

func TestParseJSONArray(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.json('[1,2,3]')`)
	require.NoError(t, err)
	require.False(t, sobek.IsNull(val))

	arr := val.ToObject(vm)
	assert.Equal(t, int64(3), arr.Get("length").ToInteger())
}

func TestParseJSONInvalid(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.json("not json")`)
	require.NoError(t, err)
	assert.True(t, sobek.IsNull(val))
}

// ── parse.form ───────────────────────────────────────────────────────────────

func TestParseForm(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.form("username=admin&password=secret&remember=1")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, "admin", obj.Get("username").String())
	assert.Equal(t, "secret", obj.Get("password").String())
	assert.Equal(t, "1", obj.Get("remember").String())
}

func TestParseFormURLEncoded(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.form("q=hello+world&lang=en%20US")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, "hello world", obj.Get("q").String())
	assert.Equal(t, "en US", obj.Get("lang").String())
}

func TestParseFormEmpty(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.parse.form("")`)
	require.NoError(t, err)
	obj := val.ToObject(vm)
	assert.Equal(t, int64(0), int64(len(obj.Keys())))
}

// ── vigolium.utils.pathToTemplate and hasDynamicSegment ─────────────────────

func TestUtilsPathToTemplate(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.utils.pathToTemplate("/api/users/123")`)
	require.NoError(t, err)
	assert.Equal(t, "/api/users/*", val.String())
}

func TestUtilsPathToTemplateStatic(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.utils.pathToTemplate("/api/users")`)
	require.NoError(t, err)
	assert.Equal(t, "/api/users", val.String())
}

func TestUtilsHasDynamicSegmentTrue(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.utils.hasDynamicSegment("/api/users/123")`)
	require.NoError(t, err)
	assert.True(t, val.ToBoolean())
}

func TestUtilsHasDynamicSegmentFalse(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.utils.hasDynamicSegment("/api/users")`)
	require.NoError(t, err)
	assert.False(t, val.ToBoolean())
}

func TestUtilsHasDynamicSegmentUUID(t *testing.T) {
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`vigolium.utils.hasDynamicSegment("/api/orders/550e8400-e29b-41d4-a716-446655440000")`)
	require.NoError(t, err)
	assert.True(t, val.ToBoolean())
}

// ── parse API availability ───────────────────────────────────────────────────

func TestParseAPIAlwaysAvailable(t *testing.T) {
	// parse API requires no optional deps — should always be set up
	vm := setupParseTestVM(t)
	val, err := vm.RunString(`typeof vigolium.parse`)
	require.NoError(t, err)
	assert.Equal(t, "object", val.String())
}
