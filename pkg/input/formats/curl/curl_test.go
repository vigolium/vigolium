package curl

import (
	"os"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenizeCurlCommand(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect []string
	}{
		{
			name:   "simple command",
			input:  `curl http://example.com`,
			expect: []string{"curl", "http://example.com"},
		},
		{
			name:   "single quoted args",
			input:  `curl -H 'Content-Type: application/json' http://example.com`,
			expect: []string{"curl", "-H", "Content-Type: application/json", "http://example.com"},
		},
		{
			name:   "double quoted args",
			input:  `curl -H "Authorization: Bearer token123" http://example.com`,
			expect: []string{"curl", "-H", "Authorization: Bearer token123", "http://example.com"},
		},
		{
			name:   "escaped quotes in double quotes",
			input:  `curl -d "{\"key\":\"value\"}" http://example.com`,
			expect: []string{"curl", "-d", `{"key":"value"}`, "http://example.com"},
		},
		{
			name:   "mixed quotes",
			input:  `curl -H 'Content-Type: application/json' -d '{"key":"value"}' http://example.com`,
			expect: []string{"curl", "-H", "Content-Type: application/json", "-d", `{"key":"value"}`, "http://example.com"},
		},
		{
			name:   "line continuation",
			input:  "curl -X POST \\\n  http://example.com",
			expect: []string{"curl", "-X", "POST", "http://example.com"},
		},
		{
			name:   "empty string",
			input:  "",
			expect: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tokenizeCurlCommand(tt.input)
			assert.Equal(t, tt.expect, got)
		})
	}
}

func TestParseSingleCommand_SimpleGET(t *testing.T) {
	rr, err := ParseSingleCommand(`curl http://localhost:8888/api/users`)
	require.NoError(t, err)
	require.NotNil(t, rr)

	req := rr.Request()
	assert.Equal(t, "GET", req.Method())
	assert.Equal(t, "localhost", req.Service().Host())
	assert.Equal(t, 8888, req.Service().Port())
	assert.Contains(t, string(req.Raw()), "/api/users")
}

func TestParseSingleCommand_POSTWithJSON(t *testing.T) {
	cmd := `curl -X POST http://localhost:8888/api/auth/login -H 'Content-Type: application/json' -d '{"email":"test@example.com","password":"Test!123"}'`
	rr, err := ParseSingleCommand(cmd)
	require.NoError(t, err)
	require.NotNil(t, rr)

	req := rr.Request()
	assert.Equal(t, "POST", req.Method())
	assert.Contains(t, string(req.Raw()), "/api/auth/login")
	assert.Contains(t, string(req.Raw()), `{"email":"test@example.com","password":"Test!123"}`)
	assert.Contains(t, string(req.Raw()), "Content-Type: application/json")
}

func TestParseSingleCommand_POSTWithFormData(t *testing.T) {
	cmd := `curl -X POST http://localhost:8888/api/upload -H 'Authorization: Bearer token123' -F 'file=@/path/to/file.jpg'`
	rr, err := ParseSingleCommand(cmd)
	require.NoError(t, err)
	require.NotNil(t, rr)

	req := rr.Request()
	assert.Equal(t, "POST", req.Method())
	assert.Contains(t, string(req.Raw()), "Content-Type: multipart/form-data")
}

func TestParseSingleCommand_PUTWithHeaders(t *testing.T) {
	cmd := `curl -X PUT http://localhost:8888/api/orders/1 -H 'Content-Type: application/json' -H 'Authorization: Bearer token123' -d '{"quantity":2}'`
	rr, err := ParseSingleCommand(cmd)
	require.NoError(t, err)
	require.NotNil(t, rr)

	req := rr.Request()
	assert.Equal(t, "PUT", req.Method())
	raw := string(req.Raw())
	assert.Contains(t, raw, "Authorization: Bearer token123")
	assert.Contains(t, raw, `{"quantity":2}`)
}

func TestParseSingleCommand_DELETE(t *testing.T) {
	cmd := `curl -X DELETE http://localhost:8888/api/videos/1 -H 'Authorization: Bearer token123'`
	rr, err := ParseSingleCommand(cmd)
	require.NoError(t, err)
	require.NotNil(t, rr)

	req := rr.Request()
	assert.Equal(t, "DELETE", req.Method())
	assert.Contains(t, string(req.Raw()), "/api/videos/1")
}

func TestParseSingleCommand_GETWithQueryParams(t *testing.T) {
	cmd := `curl -X GET 'http://localhost:8888/api/posts/recent?limit=30&offset=0' -H 'Authorization: Bearer token123'`
	rr, err := ParseSingleCommand(cmd)
	require.NoError(t, err)
	require.NotNil(t, rr)

	req := rr.Request()
	assert.Equal(t, "GET", req.Method())
	raw := string(req.Raw())
	assert.Contains(t, raw, "limit=30")
	assert.Contains(t, raw, "offset=0")
}

func TestParseSingleCommand_ImplicitPOST(t *testing.T) {
	cmd := `curl http://localhost:8888/api/login -d '{"email":"test@example.com"}'`
	rr, err := ParseSingleCommand(cmd)
	require.NoError(t, err)
	require.NotNil(t, rr)

	req := rr.Request()
	assert.Equal(t, "POST", req.Method())
}

func TestParseSingleCommand_MultipleHeaders(t *testing.T) {
	cmd := `curl -X GET http://localhost:8888/api/data -H 'Accept: application/json' -H 'Authorization: Bearer token' -H 'X-Custom: value'`
	rr, err := ParseSingleCommand(cmd)
	require.NoError(t, err)
	require.NotNil(t, rr)

	raw := string(rr.Request().Raw())
	assert.Contains(t, raw, "Accept: application/json")
	assert.Contains(t, raw, "Authorization: Bearer token")
	assert.Contains(t, raw, "X-Custom: value")
}

func TestParseSingleCommand_IgnoredFlags(t *testing.T) {
	cmd := `curl -s -k --compressed -o /dev/null http://localhost:8888/api/test`
	rr, err := ParseSingleCommand(cmd)
	require.NoError(t, err)
	require.NotNil(t, rr)

	req := rr.Request()
	assert.Equal(t, "GET", req.Method())
	assert.Contains(t, string(req.Raw()), "/api/test")
}

func TestParseSingleCommand_BasicAuth(t *testing.T) {
	cmd := `curl -u admin:password http://localhost:8888/api/admin`
	rr, err := ParseSingleCommand(cmd)
	require.NoError(t, err)
	require.NotNil(t, rr)

	raw := string(rr.Request().Raw())
	assert.Contains(t, raw, "Authorization: Basic")
}

func TestParseSingleCommand_CookieFlag(t *testing.T) {
	cmd := `curl -b 'session=abc123' http://localhost:8888/api/profile`
	rr, err := ParseSingleCommand(cmd)
	require.NoError(t, err)
	require.NotNil(t, rr)

	raw := string(rr.Request().Raw())
	assert.Contains(t, raw, "Cookie: session=abc123")
}

func TestParseSingleCommand_NoURL(t *testing.T) {
	_, err := ParseSingleCommand(`curl -X GET`)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no URL")
}

func TestParseSingleCommand_MultipleDataFlags(t *testing.T) {
	cmd := `curl -X POST http://localhost:8888/api/form -d 'name=John' -d 'email=john@example.com'`
	rr, err := ParseSingleCommand(cmd)
	require.NoError(t, err)
	require.NotNil(t, rr)

	raw := string(rr.Request().Raw())
	assert.Contains(t, raw, "name=John&email=john@example.com")
}

func TestParseSingleCommand_ImplicitPOSTWithForm(t *testing.T) {
	cmd := `curl http://localhost:8888/upload -F 'file=@photo.jpg'`
	rr, err := ParseSingleCommand(cmd)
	require.NoError(t, err)
	require.NotNil(t, rr)

	assert.Equal(t, "POST", rr.Request().Method())
}

func TestExtractFromShellScript(t *testing.T) {
	script := `#!/bin/bash
# This is a comment
BASE_URL="http://localhost:8888"

# 1. Sign Up
signup() {
  curl -s -X POST "${BASE_URL}/identity/api/auth/signup" \
    -H 'Content-Type: application/json' \
    -d '{"email": "test@example.com"}'
}

# 2. Login
login() {
  curl -s -X POST "${BASE_URL}/identity/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d '{"email": "test@example.com", "password": "Test!123"}'
}

echo "not a curl command"
`
	commands := extractFromShellScript(script)
	assert.Len(t, commands, 2)
	assert.Contains(t, commands[0], "curl")
	assert.Contains(t, commands[0], "signup")
	assert.Contains(t, commands[1], "curl")
	assert.Contains(t, commands[1], "login")
}

func TestExtractFromMarkdown(t *testing.T) {
	md := "# API Examples\n\n" +
		"## Login\n\n" +
		"```bash\n" +
		"curl -X POST http://localhost:8888/api/login \\\n" +
		"  -H 'Content-Type: application/json' \\\n" +
		"  -d '{\"email\":\"test@example.com\"}'\n" +
		"```\n\n" +
		"## Get Users\n\n" +
		"```\n" +
		"curl -X GET http://localhost:8888/api/users\n" +
		"```\n"

	commands := extractFromMarkdown(md)
	assert.Len(t, commands, 2)
	assert.Contains(t, commands[0], "curl")
	assert.Contains(t, commands[0], "login")
	assert.Contains(t, commands[1], "curl")
	assert.Contains(t, commands[1], "users")
}

func TestJoinContinuationLines(t *testing.T) {
	lines := []string{
		"curl -X POST \\",
		"  http://example.com \\",
		"  -H 'Content-Type: application/json'",
		"",
		"echo done",
	}
	joined := joinContinuationLines(lines)
	assert.Len(t, joined, 3)
	assert.Contains(t, joined[0], "curl")
	assert.Contains(t, joined[0], "http://example.com")
	assert.Contains(t, joined[0], "Content-Type: application/json")
}

func TestFormat_Parse_RawCommands(t *testing.T) {
	// Create a temp file with raw curl commands
	tmpFile := t.TempDir() + "/commands.txt"
	content := "curl -X GET http://localhost:8888/api/test\ncurl -X POST http://localhost:8888/api/create -d '{\"name\":\"test\"}'\n"
	require.NoError(t, writeFile(tmpFile, content))

	f := New()
	var count int
	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		count++
		return true
	})
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestFormat_Count(t *testing.T) {
	tmpFile := t.TempDir() + "/commands.txt"
	content := "curl http://example.com/1\ncurl http://example.com/2\ncurl http://example.com/3\n"
	require.NoError(t, writeFile(tmpFile, content))

	f := New()
	count, err := f.Count(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestFormat_VariableSubstitution(t *testing.T) {
	tmpFile := t.TempDir() + "/commands.txt"
	content := "curl -X GET http://${HOST}/api/test -H 'Authorization: Bearer {{TOKEN}}'\n"
	require.NoError(t, writeFile(tmpFile, content))

	f := New()
	f.SetCurlOptions(Options{
		Variables: map[string]string{
			"HOST":  "myhost:9090",
			"TOKEN": "my-jwt-token",
		},
	})

	var parsed bool
	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		raw := string(rr.Request().Raw())
		assert.Contains(t, raw, "myhost:9090")
		assert.Contains(t, raw, "Authorization: Bearer my-jwt-token")
		parsed = true
		return true
	})
	require.NoError(t, err)
	assert.True(t, parsed)
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
