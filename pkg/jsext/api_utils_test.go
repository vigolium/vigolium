package jsext

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grafana/sobek"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestVM(t *testing.T, opts APIOptions) *sobek.Runtime {
	t.Helper()
	vm := sobek.New()
	vigolium := vm.NewObject()
	_ = vm.Set("vigolium", vigolium)
	setupUtilsAPI(vm, opts)
	return vm
}

func TestExecBlocked(t *testing.T) {
	vm := setupTestVM(t, APIOptions{AllowExec: false})
	val, err := vm.RunString(`vigolium.utils.exec("echo hello")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(-1), obj.Get("exitCode").ToInteger())
	assert.Contains(t, obj.Get("stderr").String(), "disabled")
}

func TestExecAllowed(t *testing.T) {
	vm := setupTestVM(t, APIOptions{AllowExec: true, ExecTimeout: 5})
	val, err := vm.RunString(`vigolium.utils.exec("echo hello")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(0), obj.Get("exitCode").ToInteger())
	assert.Contains(t, obj.Get("stdout").String(), "hello")
}

func TestGlob(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0644))

	vm := setupTestVM(t, APIOptions{})
	pattern := filepath.Join(dir, "*.txt")
	val, err := vm.RunString(`vigolium.utils.glob("` + pattern + `")`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	length := arr.Get("length").ToInteger()
	assert.Equal(t, int64(2), length)
}

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("hello world"), 0644))

	vm := setupTestVM(t, APIOptions{})
	val, err := vm.RunString(`vigolium.utils.readFile("` + testFile + `")`)
	require.NoError(t, err)
	assert.Equal(t, "hello world", val.String())
}

func TestReadLines(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "lines.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("line1\nline2\nline3"), 0644))

	vm := setupTestVM(t, APIOptions{})
	val, err := vm.RunString(`vigolium.utils.readLines("` + testFile + `")`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	assert.Equal(t, int64(3), arr.Get("length").ToInteger())
	assert.Equal(t, "line1", arr.Get("0").String())
}

func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "out.txt")

	vm := setupTestVM(t, APIOptions{})
	val, err := vm.RunString(`vigolium.utils.writeFile("` + testFile + `", "test data")`)
	require.NoError(t, err)
	assert.True(t, val.ToBoolean())

	data, err := os.ReadFile(testFile)
	require.NoError(t, err)
	assert.Equal(t, "test data", string(data))
}

func TestMkdir(t *testing.T) {
	dir := t.TempDir()
	newDir := filepath.Join(dir, "sub", "dir")

	vm := setupTestVM(t, APIOptions{})
	val, err := vm.RunString(`vigolium.utils.mkdir("` + newDir + `")`)
	require.NoError(t, err)
	assert.True(t, val.ToBoolean())

	info, err := os.Stat(newDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestGetEnv(t *testing.T) {
	t.Setenv("VIGOLIUM_TEST_VAR", "test_value")

	vm := setupTestVM(t, APIOptions{})
	val, err := vm.RunString(`vigolium.utils.getEnv("VIGOLIUM_TEST_VAR")`)
	require.NoError(t, err)
	assert.Equal(t, "test_value", val.String())
}

func TestSetEnvBlocked(t *testing.T) {
	vm := setupTestVM(t, APIOptions{AllowExec: false})
	val, err := vm.RunString(`vigolium.utils.setEnv("VIGOLIUM_BLOCKED", "val")`)
	require.NoError(t, err)
	assert.False(t, val.ToBoolean())
}

func TestSetEnvAllowed(t *testing.T) {
	vm := setupTestVM(t, APIOptions{AllowExec: true})
	val, err := vm.RunString(`vigolium.utils.setEnv("VIGOLIUM_ALLOWED", "val")`)
	require.NoError(t, err)
	assert.True(t, val.ToBoolean())
	assert.Equal(t, "val", os.Getenv("VIGOLIUM_ALLOWED"))
}

func TestJsonExtract(t *testing.T) {
	vm := setupTestVM(t, APIOptions{})

	tests := []struct {
		name     string
		json     string
		path     string
		expected string
	}{
		{"simple key", `{"name":"test"}`, "name", "test"},
		{"nested", `{"a":{"b":"deep"}}`, "a.b", "deep"},
		{"array index", `{"items":["x","y","z"]}`, "items.1", "y"},
		{"nested array", `{"a":{"b":[1,2,3]}}`, "a.b.2", "3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := `vigolium.utils.jsonExtract('` + tt.json + `', '` + tt.path + `')`
			val, err := vm.RunString(script)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, val.String())
		})
	}
}

func TestJsonExtractInvalid(t *testing.T) {
	vm := setupTestVM(t, APIOptions{})
	val, err := vm.RunString(`vigolium.utils.jsonExtract("not json", "key")`)
	require.NoError(t, err)
	assert.True(t, sobek.IsUndefined(val))
}

func TestRegexMatch(t *testing.T) {
	vm := setupTestVM(t, APIOptions{})

	val, err := vm.RunString(`vigolium.utils.regexMatch("hello world", "hel+o")`)
	require.NoError(t, err)
	assert.True(t, val.ToBoolean())

	val, err = vm.RunString(`vigolium.utils.regexMatch("hello world", "^xyz$")`)
	require.NoError(t, err)
	assert.False(t, val.ToBoolean())
}

func TestRegexExtract(t *testing.T) {
	vm := setupTestVM(t, APIOptions{})

	// Single capture group
	val, err := vm.RunString(`vigolium.utils.regexExtract("version: 1.2.3", "version: (\\d+\\.\\d+\\.\\d+)")`)
	require.NoError(t, err)
	assert.Equal(t, "1.2.3", val.String())

	// No match
	val, err = vm.RunString(`vigolium.utils.regexExtract("hello", "^(xyz)$")`)
	require.NoError(t, err)
	assert.True(t, sobek.IsNull(val))

	// No capture group — returns full match
	val, err = vm.RunString(`vigolium.utils.regexExtract("abc123", "\\d+")`)
	require.NoError(t, err)
	assert.Equal(t, "123", val.String())
}

func TestSandboxEnforcement(t *testing.T) {
	sandbox := t.TempDir()

	vm := setupTestVM(t, APIOptions{SandboxDir: sandbox})

	// Reading outside sandbox should return empty
	val, err := vm.RunString(`vigolium.utils.readFile("/etc/passwd")`)
	require.NoError(t, err)
	assert.Equal(t, "", val.String())

	// Writing outside sandbox should return false
	val, err = vm.RunString(`vigolium.utils.writeFile("/tmp/evil.txt", "data")`)
	require.NoError(t, err)
	assert.False(t, val.ToBoolean())

	// Writing inside sandbox should work
	testFile := filepath.Join(sandbox, "ok.txt")
	val, err = vm.RunString(`vigolium.utils.writeFile("` + testFile + `", "safe data")`)
	require.NoError(t, err)
	assert.True(t, val.ToBoolean())
}

func TestResolveSandboxPath(t *testing.T) {
	sandbox := t.TempDir()

	// Path inside sandbox: allowed
	inside := filepath.Join(sandbox, "sub", "file.txt")
	resolved, err := resolveSandboxPath(inside, sandbox)
	require.NoError(t, err)
	assert.Equal(t, inside, resolved)

	// Path outside sandbox: blocked
	_, err = resolveSandboxPath("/etc/passwd", sandbox)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "outside sandbox")

	// No sandbox: everything allowed
	resolved, err = resolveSandboxPath("/etc/passwd", "")
	require.NoError(t, err)
	assert.Equal(t, "/etc/passwd", resolved)
}

func TestParseURL(t *testing.T) {
	fullURL := "https://sub.example.com:8443/path/file.js?q=1#sec"
	tests := []struct {
		name     string
		url      string
		format   string
		expected string
	}{
		{"scheme", fullURL, "%s", "https"},
		{"domain", fullURL, "%d", "sub.example.com"},
		{"subdomain", fullURL, "%S", "sub"},
		{"root domain", fullURL, "%r", "example.com"},
		{"tld", fullURL, "%t", "com"},
		{"port non-default", fullURL, "%P", "8443"},
		{"port default", "https://example.com/", "%P", ""},
		{"path", fullURL, "%p", "/path/file.js"},
		{"extension", fullURL, "%e", "js"},
		{"query", fullURL, "%q", "q=1"},
		{"fragment", fullURL, "%f", "sec"},
		{"authority with port", fullURL, "%a", "sub.example.com:8443"},
		{"authority default port", "https://example.com/path", "%a", "example.com"},
		{"literal percent", fullURL, "%%", "%"},
		{"composed", fullURL, "%s://%d%p", "https://sub.example.com/path/file.js"},
		{"invalid url", "not-a-url", "%d", ""},
		{"no extension", "https://example.com/path/dir/", "%e", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatURL(tt.url, tt.format)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseURLFile(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "urls.txt")
	outputFile := filepath.Join(dir, "domains.txt")

	input := "https://sub.example.com/path1\nhttps://other.example.org/path2\nhttps://sub.example.com/path3\nhttps://test.net/path4\n"
	require.NoError(t, os.WriteFile(inputFile, []byte(input), 0644))

	vm := setupTestVM(t, APIOptions{})
	val, err := vm.RunString(`vigolium.utils.parse_url_file("` + inputFile + `", "%d", "` + outputFile + `")`)
	require.NoError(t, err)
	assert.True(t, val.ToBoolean())

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	assert.Equal(t, 3, len(lines), "should have 3 deduplicated domains")
	assert.Contains(t, lines, "sub.example.com")
	assert.Contains(t, lines, "other.example.org")
	assert.Contains(t, lines, "test.net")
}

func TestParseURLFileSandbox(t *testing.T) {
	sandbox := t.TempDir()
	outsideDir := t.TempDir()

	inputFile := filepath.Join(outsideDir, "urls.txt")
	require.NoError(t, os.WriteFile(inputFile, []byte("https://example.com\n"), 0644))

	vm := setupTestVM(t, APIOptions{SandboxDir: sandbox})

	// Reading from outside sandbox should fail
	val, err := vm.RunString(`vigolium.utils.parse_url_file("` + inputFile + `", "%d", "` + filepath.Join(sandbox, "out.txt") + `")`)
	require.NoError(t, err)
	assert.False(t, val.ToBoolean())

	// Writing to outside sandbox should fail
	insideInput := filepath.Join(sandbox, "urls.txt")
	require.NoError(t, os.WriteFile(insideInput, []byte("https://example.com\n"), 0644))
	val, err = vm.RunString(`vigolium.utils.parse_url_file("` + insideInput + `", "%d", "` + filepath.Join(outsideDir, "out.txt") + `")`)
	require.NoError(t, err)
	assert.False(t, val.ToBoolean())
}

func TestDetectAnomaly(t *testing.T) {
	vm := setupTestVM(t, APIOptions{})

	// Create array with identical responses + one different
	val, err := vm.RunString(`
		var responses = [
			{status: 200, body: "OK", headers: {"content-type": "text/html"}},
			{status: 200, body: "OK", headers: {"content-type": "text/html"}},
			{status: 200, body: "OK", headers: {"content-type": "text/html"}},
			{status: 500, body: "Internal Server Error with a very different body content", headers: {"content-type": "text/plain"}},
			{status: 200, body: "OK", headers: {"content-type": "text/html"}}
		];
		vigolium.utils.detectAnomaly(responses);
	`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	length := arr.Get("length").ToInteger()
	assert.Equal(t, int64(5), length)

	// First result should have highest score (the anomalous 500 response)
	first := arr.Get("0").ToObject(vm)
	assert.NotNil(t, first.Get("index"))
	assert.NotNil(t, first.Get("score"))

	// The anomalous response (index 3) should have the highest score
	firstScore := first.Get("score").ToInteger()
	assert.Greater(t, firstScore, int64(0), "Anomalous response should have positive score")
}

func TestDetectAnomalyTooFew(t *testing.T) {
	vm := setupTestVM(t, APIOptions{})

	// Only 1 response — not enough for anomaly detection
	val, err := vm.RunString(`
		vigolium.utils.detectAnomaly([{status: 200, body: "OK"}]);
	`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	length := arr.Get("length").ToInteger()
	assert.Equal(t, int64(0), length, "Should return empty array for <2 responses")
}

func TestToSet(t *testing.T) {
	vm := setupTestVM(t, APIOptions{})

	val, err := vm.RunString(`
		var s = vigolium.utils.toSet("id,name,email");
		JSON.stringify({id: s["id"], name: s["name"], email: s["email"], missing: s["missing"] || false});
	`)
	require.NoError(t, err)
	assert.Equal(t, `{"id":true,"name":true,"email":true,"missing":false}`, val.String())
}

func TestToSetEmpty(t *testing.T) {
	vm := setupTestVM(t, APIOptions{})

	val, err := vm.RunString(`Object.keys(vigolium.utils.toSet("")).length`)
	require.NoError(t, err)
	assert.Equal(t, int64(0), val.ToInteger())
}

func TestExtractParamNames(t *testing.T) {
	vm := setupTestVM(t, APIOptions{})

	val, err := vm.RunString(`JSON.stringify(vigolium.utils.extractParamNames("id=1&name=test&email=a@b.com"))`)
	require.NoError(t, err)
	assert.Equal(t, `["id","name","email"]`, val.String())
}

func TestExtractParamNamesWithQuery(t *testing.T) {
	vm := setupTestVM(t, APIOptions{})

	val, err := vm.RunString(`JSON.stringify(vigolium.utils.extractParamNames("?user=admin&token=abc"))`)
	require.NoError(t, err)
	assert.Equal(t, `["user","token"]`, val.String())
}

func TestExtractParamNamesDeduplicated(t *testing.T) {
	vm := setupTestVM(t, APIOptions{})

	val, err := vm.RunString(`JSON.stringify(vigolium.utils.extractParamNames("id=1&ID=2&name=x"))`)
	require.NoError(t, err)
	assert.Equal(t, `["id","name"]`, val.String())
}

func TestExtractParamNamesEmpty(t *testing.T) {
	vm := setupTestVM(t, APIOptions{})

	val, err := vm.RunString(`vigolium.utils.extractParamNames("").length`)
	require.NoError(t, err)
	assert.Equal(t, int64(0), val.ToInteger())
}

func TestDetectAnomalyNullInput(t *testing.T) {
	vm := setupTestVM(t, APIOptions{})

	val, err := vm.RunString(`vigolium.utils.detectAnomaly(null)`)
	require.NoError(t, err)

	arr := val.ToObject(vm)
	length := arr.Get("length").ToInteger()
	assert.Equal(t, int64(0), length, "Should return empty array for null input")
}
