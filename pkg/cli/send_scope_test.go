package cli

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

func TestSendHostname(t *testing.T) {
	for in, want := range map[string]string{
		"http://App.Example:8080/x": "app.example",
		"app.example:443":           "app.example",
		"[::1]:80":                  "::1",
		"10.0.0.1":                  "10.0.0.1",
		"":                          "",
	} {
		assert.Equal(t, want, sendHostname(in), in)
	}
}

// Every sender refuses an out-of-scope host the same way: exit 2,
// out_of_scope, nothing sent; --ignore-scope sends.
func TestSendScopeGateAcrossSenders(t *testing.T) {
	srv, hits := countingServer(t)
	home := a3Home(t, "in-scope.example")
	reqFile := t.TempDir() + "/req.txt"
	require.NoError(t, writeFile(reqFile, "GET /x?id=1 HTTP/1.1\r\nHost: "+srv.Listener.Addr().String()+"\r\n\r\n"))

	cases := map[string][]string{
		"replay -i":      {"replay", "-i", "curl " + srv.URL + "/x", "-j"},
		"kit param-mine": {"kit", "param-mine", srv.URL + "/x", "-j", "--max-requests", "5"},
		"fuzz":           {"fuzz", "-i", reqFile, "-t", srv.URL, "--fuzz", "params", "-p", "a", "-j"},
		"dns":            {"dns", "127.0.0.1.nip.io", "-j"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			before := hits.Load()
			code, stdout, stderr := runA3(t, home, args...)
			assert.Equal(t, ExitUsageError, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
			assert.Equal(t, string(apicontract.CodeOutOfScope), errorCode(t, stdout))
			assert.Equal(t, before, hits.Load(), "nothing sent")
		})
	}

	before := hits.Load()
	code, stdout, stderr := runA3(t, home, "replay", "-i", "curl "+srv.URL+"/x", "-j", "--ignore-scope")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Greater(t, hits.Load(), before, "--ignore-scope sends")
}

func TestOutOfScopeErrorShape(t *testing.T) {
	err := outOfScopeError([]string{"a.example"})
	var ce clicommon.CLIError
	require.True(t, errors.As(err, &ce))
	assert.Equal(t, apicontract.CodeOutOfScope, ce.ErrorCode())
	assert.Contains(t, ce.Hint, "--ignore-scope")
	assert.Equal(t, ExitUsageError, classifyExitCode(err))
	assert.Equal(t, apicontract.CodeOutOfScope, classifyErrorCode(err, classifyExitCode(err)))
}
