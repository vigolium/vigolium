package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A project's scope overlay reads back through scope view and config ls, with
// the layer that set it, and scope set takes the global --project-uuid.
func TestProjectOverlayReadsBack(t *testing.T) {
	e := newB5Env(t)
	code, stdout, stderr := e.run(t, nil, "project", "create", "beta-proj", "-j")
	require.Equal(t, 0, code, stderr)
	proj := oneDoc(t, stdout, stderr)["items"].([]any)[0].(map[string]any)["uuid"].(string)

	code, _, stderr = e.run(t, nil, "scope", "set", "host.exclude", "only-beta.example", "--project-uuid", proj, "-j")
	require.Equal(t, 0, code, stderr)

	code, stdout, stderr = e.run(t, nil, "scope", "view", "host", "-j", "--project-uuid", proj)
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, "only-beta.example")
	require.Contains(t, stdout, `"source":"project"`)

	code, stdout, stderr = e.run(t, nil, "config", "ls", "scope.host.exclude", "-j", "--project-uuid", proj)
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, "only-beta.example")

	// Without the project, the global value is unchanged.
	code, stdout, stderr = e.run(t, nil, "scope", "view", "host", "-j")
	require.Equal(t, 0, code, stderr)
	require.False(t, strings.Contains(stdout, "only-beta.example"), stdout)
}

// config ls -j values are typed, false keys are listed, credentials are
// redacted by key class only, and --effective names the env var behind a
// placeholder.
func TestConfigLsTypedAndSourced(t *testing.T) {
	e := newB5Env(t)
	code, _, stderr := e.run(t, nil, "config", "set", "notify.enabled", "false", "-j")
	require.Equal(t, 0, code, stderr)
	code, _, stderr = e.run(t, nil, "config", "set", "external_harvester.api_keys.urlscan", "sekrit", "-j")
	require.Equal(t, 0, code, stderr)

	code, stdout, stderr := e.run(t, nil, "config", "ls", "notify.enabled", "-j")
	require.Equal(t, 0, code, stderr)
	doc := oneDoc(t, stdout, stderr)
	require.EqualValues(t, 1, doc["total"])
	item := doc["items"].([]any)[0].(map[string]any)
	require.Equal(t, false, item["value"])
	require.Equal(t, "file", item["source"])

	code, stdout, stderr = e.run(t, nil, "config", "ls", "api_keys.urlscan", "-j")
	require.Equal(t, 0, code, stderr)
	require.NotContains(t, stdout, "sekrit")
	require.Contains(t, stdout, `"redacted":true`)

	code, stdout, stderr = e.run(t, nil, "config", "ls", "disable_secret_scan", "-j")
	require.Equal(t, 0, code, stderr)
	require.NotContains(t, stdout, `"sensitive":true`, "a boolean is never redacted")

	code, stdout, stderr = e.run(t, []string{"VIGOLIUM_STORAGE_ENABLED=true"}, "config", "ls", "storage.enabled", "--effective", "-j")
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, `"source":"env:VIGOLIUM_STORAGE_ENABLED"`)

	code, stdout, stderr = e.run(t, nil, "config", "env", "-j")
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, `"name":"VIGOLIUM_DB_PATH"`)
}

// project use --print-env pins a shell only: it writes no active-project
// file, and it takes a name or a UUID prefix.
func TestProjectUsePrintEnv(t *testing.T) {
	e := newB5Env(t)
	code, stdout, stderr := e.run(t, nil, "project", "create", "pinned-proj", "-j")
	require.Equal(t, 0, code, stderr)
	proj := oneDoc(t, stdout, stderr)["items"].([]any)[0].(map[string]any)["uuid"].(string)

	for _, ref := range []string{"pinned-proj", proj[:8]} {
		code, stdout, stderr = e.run(t, nil, "project", "use", ref, "--print-env")
		require.Equal(t, 0, code, stderr)
		require.Equal(t, "export VIGOLIUM_PROJECT_UUID="+proj+"\n", stdout)
	}
	_, err := os.Stat(filepath.Join(e.home, ".vigolium", "active-project"))
	require.True(t, os.IsNotExist(err), "--print-env must write no active-project file")

	code, stdout, stderr = e.run(t, nil, "project", "use", "no-such-proj", "-j")
	require.Equal(t, 1, code, stderr)
	require.Contains(t, stdout, "project_not_found")
	require.Contains(t, stdout, "project create <name>")
}
