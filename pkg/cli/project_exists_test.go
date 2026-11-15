package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A project that does not exist is project_not_found (exit 1) instead of an
// empty scope, and nothing is created for it; a UUID prefix or a name
// resolves to the existing project.
func TestUnknownProjectIsNotFound(t *testing.T) {
	e := newB5Env(t)
	const ghost = "99999999-9999-9999-9999-999999999999"

	code, stdout, stderr := e.run(t, nil, "project", "create", "acme", "-j")
	require.Equal(t, 0, code, stderr)
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(stdout)), &doc))
	full := doc["items"].([]any)[0].(map[string]any)["uuid"].(string)

	code, stdout, stderr = e.run(t, nil, "finding", "-j", "--project-uuid", ghost)
	require.Equal(t, 1, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(stdout)), &doc), stdout)
	require.Equal(t, "project_not_found", doc["error"].(map[string]any)["code"])

	code, _, _ = e.run(t, nil, "scope", "set", "host.exclude", "x.example", "--project", ghost)
	require.Equal(t, 1, code)
	_, statErr := os.Stat(filepath.Join(e.home, ".vigolium", "projects", ghost))
	require.True(t, os.IsNotExist(statErr), "scope set created a directory for an unknown project")

	code, _, _ = e.run(t, nil, "project", "config", ghost, "-j")
	require.Equal(t, 1, code)

	for _, ref := range []string{full[:8], "acme"} {
		code, stdout, stderr = e.run(t, nil, "finding", "-j", "--project-uuid", ref)
		require.Equal(t, 0, code, "ref %q: %s", ref, stderr)
		require.Contains(t, stdout, full, "ref %q did not resolve to the project", ref)
	}

	code, _, stderr = e.run(t, nil, "scope", "set", "host.exclude", "x.example", "--project", "acme")
	require.Equal(t, 0, code, stderr)
	_, statErr = os.Stat(filepath.Join(e.home, ".vigolium", "projects", full, "config.yaml"))
	require.NoError(t, statErr)
}

// A standalone JSONL source has no project registry, so naming a project
// there is a filter, not an existence check.
func TestStatelessSourceSkipsProjectCheck(t *testing.T) {
	e := newB5Env(t)
	src := filepath.Join(e.home, "x.jsonl")
	line := `{"type":"http_record","data":{"uuid":"r1","project_uuid":"11111111-1111-1111-1111-111111111111","scheme":"http","hostname":"a.example","port":80,"method":"GET","path":"/","url":"http://a.example/","status_code":200}}`
	require.NoError(t, os.WriteFile(src, []byte(line+"\n"), 0o600))
	code, _, stderr := e.run(t, nil, "finding", "-j", "-S", "--db", src, "--project-uuid", "99999999-9999-9999-9999-999999999999")
	require.Equal(t, 0, code, stderr)
}
