package cli

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
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

func scopeGateFor(cfg config.ScopeConfig, require bool) sendScopeGate {
	return sendScopeGate{matcher: config.NewScopeMatcher(cfg), require: require}
}

// The gate enforces scope.path as well as scope.host whenever the request's
// path is known; a bare host is judged on the host rule alone.
func TestSendScopeGateEnforcesPathRules(t *testing.T) {
	cfg := *config.DefaultScopeConfig()
	cfg.Host = config.ScopeRule{Include: []string{"in.example"}}
	cfg.Path = config.ScopeRule{Exclude: []string{"/admin/*"}}
	gate := scopeGateFor(cfg, false)

	require.NoError(t, gate.check("https://in.example/api/users?id=1"))
	require.NoError(t, gate.check("in.example"), "a bare host has no path to judge")
	require.NoError(t, gate.check("https://in.example"), "the origin is /")

	err := gate.check("https://in.example/admin/delete")
	require.True(t, isOutOfScope(err), "a path the exclude names is refused: %v", err)
	assert.Contains(t, err.Error(), "in.example/admin/delete")
	assert.Contains(t, err.Error(), "scope.path.exclude")
	require.True(t, isOutOfScope(gate.check("https://out.example/api")), "the host rule still applies")

	// An include list admits only what it names.
	cfg.Path = config.ScopeRule{Include: []string{"/api/*"}}
	gate = scopeGateFor(cfg, false)
	require.NoError(t, gate.check("https://in.example/api/x"))
	err = gate.check("https://in.example/static/x")
	require.True(t, isOutOfScope(err))
	assert.Contains(t, err.Error(), "scope.path.include")

	// A parsed request is judged by the path on its request line.
	src := &replaySource{Hostname: "in.example", BaselineRequest: []byte("GET /static/app.js HTTP/1.1\r\nHost: in.example\r\n\r\n")}
	require.True(t, isOutOfScope(gate.checkSource(src)))
	src.BaselineRequest = []byte("POST https://in.example/api/login HTTP/1.1\r\nHost: in.example\r\n\r\n")
	require.NoError(t, gate.checkSource(src))
}

// --require-scope turns an empty scope from admit-all into out_of_scope;
// --ignore-scope still overrides; a named host or a CLI origin is a scope.
func TestSendScopeGateRequireScope(t *testing.T) {
	empty := *config.DefaultScopeConfig()
	require.NoError(t, scopeGateFor(empty, false).check("anything.example"), "no scope admits every host")

	err := scopeGateFor(empty, true).check("anything.example")
	require.True(t, isOutOfScope(err), "an empty scope fails closed under --require-scope: %v", err)
	assert.Contains(t, err.Error(), "--require-scope")

	wildcard := empty
	wildcard.Host = config.ScopeRule{Include: []string{"*", "in.example"}}
	require.True(t, isOutOfScope(scopeGateFor(wildcard, true).check("in.example")), `"*" names no hosts`)

	excludeOnly := empty
	excludeOnly.Host = config.ScopeRule{Exclude: []string{"evil.example"}}
	require.True(t, isOutOfScope(scopeGateFor(excludeOnly, true).check("in.example")), "an exclude-only rule names no hosts")

	named := empty
	named.Host = config.ScopeRule{Include: []string{"in.example"}}
	require.NoError(t, scopeGateFor(named, true).check("in.example"))

	require.NoError(t, sendScopeGate{ignore: true, require: true}.check("anything.example"))
}

func TestRequireScopeRequested(t *testing.T) {
	swapGlobal(t, &sendRequireScope, false)
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == requireScopeEnvVar {
				return v
			}
			return ""
		}
	}
	for raw, want := range map[string]bool{"": false, "0": false, "false": false, "1": true, "true": true} {
		got, err := requireScopeRequested(env(raw))
		require.NoError(t, err, raw)
		assert.Equal(t, want, got, raw)
	}
	_, err := requireScopeRequested(env("sure"))
	var ue usageError
	require.ErrorAs(t, err, &ue, "a misspelt value is refused, not read as off")

	sendRequireScope = true
	got, err := requireScopeRequested(env("0"))
	require.NoError(t, err)
	assert.True(t, got, "the flag wins")
}

func TestReplaySourcePath(t *testing.T) {
	for _, c := range []struct {
		src  replaySource
		want string
		ok   bool
	}{
		{replaySource{BaselineRequest: []byte("GET /a/b?x=1 HTTP/1.1\r\n\r\n")}, "/a/b?x=1", true},
		{replaySource{BaselineRequest: []byte("GET http://h.example/c HTTP/1.1\r\n\r\n")}, "/c", true},
		{replaySource{BaselineRequest: []byte("GET http://h.example HTTP/1.1\r\n\r\n")}, "/", true},
		{replaySource{URL: "https://h.example/d"}, "/d", true},
		{replaySource{}, "", false},
	} {
		got, ok := replaySourcePath(&c.src)
		assert.Equal(t, c.ok, ok, "%+v", c.src)
		assert.Equal(t, c.want, got, "%+v", c.src)
	}
}

// End to end: a path the scope excludes is refused before anything is sent;
// --require-scope refuses an empty scope; and a root --config file's scope is
// the one the gate applies, over the discovered global config.
func TestSendScopeGatePathRequireAndConfigEndToEnd(t *testing.T) {
	srv, hits := countingServer(t)
	host := srv.Listener.Addr().(*net.TCPAddr).IP.String()

	pathHome := t.TempDir()
	dir := filepath.Join(pathHome, ".vigolium")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, initMarkerFileName), []byte("ok"), 0o600))
	cfg := noOASTConfig + "scope:\n  host:\n    include: [\"" + host + "\"]\n  path:\n    exclude: [\"/admin/*\"]\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "vigolium-configs.yaml"), []byte(cfg), 0o600))

	before := hits.Load()
	code, stdout, stderr := runA3(t, pathHome, "replay", "-i", "curl "+srv.URL+"/admin/x", "-j")
	assert.Equal(t, ExitUsageError, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, string(apicontract.CodeOutOfScope), errorCode(t, stdout))
	assert.Equal(t, before, hits.Load(), "an excluded path is not sent")

	code, stdout, stderr = runA3(t, pathHome, "replay", "-i", "curl "+srv.URL+"/ok", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Greater(t, hits.Load(), before, "an in-scope path is sent")

	// No scope at all: admitted, unless --require-scope.
	emptyHome := t.TempDir()
	writeNoOASTHomeConfig(t, emptyHome)
	before = hits.Load()
	code, stdout, stderr = runA3(t, emptyHome, "replay", "-i", "curl "+srv.URL+"/x", "-j", "--require-scope")
	assert.Equal(t, ExitUsageError, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, string(apicontract.CodeOutOfScope), errorCode(t, stdout))
	assert.Equal(t, before, hits.Load(), "nothing sent under --require-scope with no scope")

	// --config wins over the discovered global config, in both directions.
	otherHome := a3Home(t, "elsewhere.example") // the global config refuses the server
	cfgFile := filepath.Join(t.TempDir(), "engagement.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte(noOASTConfig+"scope:\n  host:\n    include: [\""+host+"\"]\n"), 0o600))
	before = hits.Load()
	code, stdout, stderr = runA3(t, otherHome, "replay", "-i", "curl "+srv.URL+"/x", "-j", "--config", cfgFile, "--require-scope")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Greater(t, hits.Load(), before, "the --config scope admits the server")

	permissive := a3Home(t, host) // the global config admits the server
	narrow := filepath.Join(t.TempDir(), "narrow.yaml")
	require.NoError(t, os.WriteFile(narrow, []byte(noOASTConfig+"scope:\n  host:\n    include: [\"elsewhere.example\"]\n"), 0o600))
	before = hits.Load()
	code, stdout, _ = runA3(t, permissive, "replay", "-i", "curl "+srv.URL+"/x", "-j", "--config", narrow)
	assert.Equal(t, ExitUsageError, code)
	assert.Equal(t, string(apicontract.CodeOutOfScope), errorCode(t, stdout))
	assert.Equal(t, before, hits.Load(), "the --config scope refuses the server")
}
