package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/modules"
)

// The mutating commands moved onto the mutation spine (plan B5). Each test runs
// the real Execute() in a re-exec'd child with a throwaway HOME and --db, so
// cobra parsing, PersistentPreRunE, the envelope and the exit-code mapping are
// all exercised, and asserts what a -j consumer relies on: exactly one document
// on stdout, kind "mutation", and `changed` present.

const b5ChildEnv = "VIGOLIUM_B5_ARGS"

func TestMachineMutationsChild(t *testing.T) {
	raw := os.Getenv(b5ChildEnv)
	if raw == "" {
		t.Skip("child process helper")
	}
	os.Args = append([]string{"vigolium"}, strings.Split(raw, "\x1f")...)
	Execute()
	os.Exit(0)
}

// b5Env is one isolated install: a HOME whose first-run marker is present (so
// no dependency install runs) and a database file inside it.
type b5Env struct {
	home, db string
}

func newB5Env(t *testing.T) *b5Env {
	t.Helper()
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".vigolium"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".vigolium", initMarkerFileName), []byte("ok"), 0o600))
	return &b5Env{home: home, db: filepath.Join(home, "b5.sqlite")}
}

// run executes `vigolium --db <db> <args...>` with stdout and stderr on pipes.
func (e *b5Env) run(t *testing.T, extraEnv []string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	argv := append([]string{"--db", e.db}, args...)
	cmd := exec.Command(os.Args[0], "-test.run=^TestMachineMutationsChild$", "-test.v=false")
	env := []string{b5ChildEnv + "=" + strings.Join(argv, "\x1f"), "HOME=" + e.home,
		"VIGOLIUM_DISABLE_UPDATE_CHECK=1"}
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case name == "HOME", strings.HasPrefix(name, "VIGOLIUM_"),
			strings.EqualFold(name, "http_proxy"), strings.EqualFold(name, "https_proxy"),
			strings.EqualFold(name, "all_proxy"):
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = append(env, extraEnv...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String(), errb.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), out.String(), errb.String()
	default:
		t.Fatalf("run child: %v", err)
		return -1, "", ""
	}
}

// oneDoc asserts stdout is exactly one JSON document and returns it.
func oneDoc(t *testing.T, stdout, stderr string) map[string]any {
	t.Helper()
	docs := decodeStdoutDocuments(t, stdout)
	require.Len(t, docs, 1, "exactly one document on stdout\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	return docs[0]
}

// requireMutation asserts the mutation spine and returns items.
func requireMutation(t *testing.T, doc map[string]any, command string, changed bool) []any {
	t.Helper()
	require.EqualValues(t, AgentSchemaVersion, doc["schema_version"])
	require.Equal(t, command, doc["command"])
	require.Equal(t, true, doc["ok"])
	require.Equal(t, string(kindMutation), doc["kind"])
	require.Contains(t, doc, "changed", "a mutation always says whether it changed state")
	require.Equal(t, changed, doc["changed"], "changed")
	require.NotEmpty(t, doc["action"])
	require.Contains(t, doc, "project_source", "every envelope says where its project came from")
	items, ok := doc["items"].([]any)
	require.True(t, ok, "items must be an array: %v", doc["items"])
	validateRegisteredMap(t, doc)
	return items
}

func TestProjectUseUnknownUUIDIsNotFound(t *testing.T) {
	e := newB5Env(t)
	id := uuid.NewString()

	code, stdout, stderr := e.run(t, nil, "project", "use", id, "-j")
	require.Equal(t, 1, code, "an unknown UUID is an error without --create\nstderr:\n%s", stderr)
	doc := oneDoc(t, stdout, stderr)
	require.Equal(t, false, doc["ok"])
	errObj, _ := doc["error"].(map[string]any)
	require.Equal(t, "not_found", errObj["code"], "error: %v", doc["error"])
	assert.NotContains(t, stdout, "export ", "no export line under -j")

	// Nothing was created, and nothing was activated.
	code, stdout, stderr = e.run(t, nil, "project", "list", "-j")
	require.Equal(t, 0, code, stderr)
	assert.NotContains(t, stdout, id, "project use must not create the project")
	_, err := os.Stat(filepath.Join(e.home, ".vigolium", "active-project"))
	assert.True(t, os.IsNotExist(err), "a refused activation writes no active-project file")
}

func TestProjectUseCreateThenNoop(t *testing.T) {
	e := newB5Env(t)
	id := uuid.NewString()

	code, stdout, stderr := e.run(t, nil, "project", "use", id, "--create", "--name", "acme", "-j")
	require.Equal(t, 0, code, stderr)
	assert.NotContains(t, stdout, "export ", "no export line under -j")
	doc := oneDoc(t, stdout, stderr)
	items := requireMutation(t, doc, "project use", true)
	require.Equal(t, "create", doc["action"])
	require.Len(t, items, 1)
	require.Equal(t, id, items[0].(map[string]any)["uuid"])
	require.Equal(t, "acme", items[0].(map[string]any)["name"])
	require.Equal(t, id, doc["project_uuid"])
	env, _ := doc["env"].(map[string]any)
	require.Equal(t, id, env["VIGOLIUM_PROJECT_UUID"])

	data, err := os.ReadFile(filepath.Join(e.home, ".vigolium", "active-project"))
	require.NoError(t, err)
	require.Equal(t, id, strings.TrimSpace(string(data)))

	// Activating the already-active project changes nothing.
	code, stdout, stderr = e.run(t, nil, "project", "use", id, "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	requireMutation(t, doc, "project use", false)
	require.Equal(t, "noop", doc["action"])

	// A later unpinned read resolves through the active file: provenance plus
	// the warning. A pin (flag or env) clears both.
	code, stdout, stderr = e.run(t, nil, "db", "stats", "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	require.Equal(t, "active_file", doc["project_source"])
	require.NotEmpty(t, doc["warnings"], "a -j read scoped by the global active file says so")

	code, stdout, stderr = e.run(t, nil, "--project-uuid", id, "db", "stats", "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	require.Equal(t, "flag", doc["project_source"])
	require.NotContains(t, doc, "warnings")

	code, stdout, stderr = e.run(t, []string{"VIGOLIUM_PROJECT_UUID=" + id}, "db", "stats", "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	require.Equal(t, "env", doc["project_source"])
}

func TestProjectUseHumanPrintsExportOnPipe(t *testing.T) {
	e := newB5Env(t)
	id := uuid.NewString()
	code, stdout, stderr := e.run(t, nil, "project", "use", id, "--create")
	require.Equal(t, 0, code, stderr)
	// stdout is a pipe here, which is exactly the eval "$(vigolium project use X)" case.
	require.Equal(t, "export VIGOLIUM_PROJECT_UUID="+id+"\n", stdout)
}

func TestProjectUseReadonlyRefusesActivation(t *testing.T) {
	e := newB5Env(t)
	code, stdout, stderr := e.run(t, nil, "project", "create", "acme", "-j")
	require.Equal(t, 0, code, stderr)
	id := requireMutation(t, oneDoc(t, stdout, stderr), "project create", true)[0].(map[string]any)["uuid"].(string)

	code, _, _ = e.run(t, []string{"VIGOLIUM_PROJECT_READONLY=true"}, "project", "use", id, "-j")
	require.NotEqual(t, 0, code, "activating an EXISTING project is refused under VIGOLIUM_PROJECT_READONLY too")
	_, err := os.Stat(filepath.Join(e.home, ".vigolium", "active-project"))
	assert.True(t, os.IsNotExist(err))
}

func TestProjectCreateConfigDeleteJSON(t *testing.T) {
	e := newB5Env(t)

	code, stdout, stderr := e.run(t, nil, "project", "create", "acme", "--description", "d", "-j")
	require.Equal(t, 0, code, stderr)
	doc := oneDoc(t, stdout, stderr)
	items := requireMutation(t, doc, "project create", true)
	require.Len(t, items, 1)
	id, _ := items[0].(map[string]any)["uuid"].(string)
	_, err := uuid.Parse(id)
	require.NoError(t, err, "items[0].uuid is the new project's UUID")
	require.Contains(t, doc["query"], id, "the follow-up is pinned to the new project")

	code, stdout, stderr = e.run(t, nil, "project", "config", id, "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	require.Equal(t, "read", doc["kind"])
	cfg := doc["items"].([]any)[0].(map[string]any)
	require.Equal(t, id, cfg["project_uuid"])
	require.Equal(t, false, cfg["exists"])
	require.Contains(t, cfg["path"], id)

	code, stdout, stderr = e.run(t, nil, "--force", "project", "delete", id, "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	items = requireMutation(t, doc, "project delete", true)
	require.Equal(t, "delete", doc["action"])
	require.Equal(t, id, items[0].(map[string]any)["uuid"])

	// Deleting it again is a no-op, not a failure.
	code, stdout, stderr = e.run(t, nil, "--force", "project", "delete", id, "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	requireMutation(t, doc, "project delete", false)
	require.Equal(t, false, doc["found"])
}

func TestModuleEnableDisableJSON(t *testing.T) {
	e := newB5Env(t)
	active := modules.GetActiveModules()
	require.NotEmpty(t, active)
	id := active[0].ID()

	code, stdout, stderr := e.run(t, nil, "module", "disable", id, "--id", "-j")
	require.Equal(t, 0, code, stderr)
	doc := oneDoc(t, stdout, stderr)
	items := requireMutation(t, doc, "module disable", true)
	require.Len(t, items, 1)
	require.Equal(t, id, items[0].(map[string]any)["id"])

	code, stdout, stderr = e.run(t, nil, "module", "disable", id, "--id", "-j")
	require.Equal(t, 0, code, stderr)
	requireMutation(t, oneDoc(t, stdout, stderr), "module disable", false)

	code, stdout, stderr = e.run(t, nil, "module", "enable", id, "--id", "-j")
	require.Equal(t, 0, code, stderr)
	requireMutation(t, oneDoc(t, stdout, stderr), "module enable", true)
}

func TestConfigAndScopeSetJSON(t *testing.T) {
	e := newB5Env(t)

	code, stdout, stderr := e.run(t, nil, "config", "set", "notify.enabled", "true", "-j")
	require.Equal(t, 0, code, stderr)
	doc := oneDoc(t, stdout, stderr)
	requireMutation(t, doc, "config set", true)

	code, stdout, stderr = e.run(t, nil, "config", "set", "notify.enabled", "true", "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	requireMutation(t, doc, "config set", false)
	require.Equal(t, "noop", doc["action"])

	code, stdout, stderr = e.run(t, nil, "scope", "set", "host.exclude", "admin.example.com", "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	items := requireMutation(t, doc, "scope set", true)
	row := items[0].(map[string]any)
	require.Equal(t, "scope.host.exclude", row["key"])
	require.Equal(t, "global", row["layer"])
	require.Contains(t, row["new"], "admin.example.com")
}

// `scope set` edits the config in place: `<rule>.clear` needs no value, and
// the file keeps its comments and placeholders.
func TestScopeSetEditsInPlace(t *testing.T) {
	e := newB5Env(t)
	cfg := filepath.Join(e.home, ".vigolium", "vigolium-configs.yaml")
	src := "# keep me\nstorage:\n  secret_key: ${VIGOLIUM_STORAGE_SECRET_KEY}\nscope:\n  host:\n    exclude: [a.example] # rule\n"
	require.NoError(t, os.WriteFile(cfg, []byte(src), 0o600))

	code, _, stderr := e.run(t, []string{"VIGOLIUM_STORAGE_SECRET_KEY=topsecret-value"}, "scope", "set", "host.exclude.add", "b.example", "-j")
	require.Equal(t, 0, code, stderr)
	got, _ := os.ReadFile(cfg)
	require.Equal(t, strings.Replace(src, "[a.example]", "[a.example, b.example]", 1), string(got))

	code, _, stderr = e.run(t, nil, "scope", "set", "host.exclude.clear", "-j")
	require.Equal(t, 0, code, stderr)
	got, _ = os.ReadFile(cfg)
	require.Equal(t, strings.Replace(src, "[a.example]", "[]", 1), string(got))

	code, _, _ = e.run(t, nil, "scope", "set", "host.exclude", "-j")
	require.Equal(t, 2, code)
}

func TestDBCleanResetJSON(t *testing.T) {
	e := newB5Env(t)
	code, _, stderr := e.run(t, nil, "project", "create", "seed", "-j")
	require.Equal(t, 0, code, stderr)

	code, stdout, stderr := e.run(t, nil, "--force", "db", "clean", "--all", "--dry-run", "-j")
	require.Equal(t, 0, code, stderr)
	doc := oneDoc(t, stdout, stderr)
	requireMutation(t, doc, "db clean", false)
	require.Equal(t, true, doc["dry_run"])

	code, stdout, stderr = e.run(t, nil, "db", "clean", "--host", "nothing.example", "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	requireMutation(t, doc, "db clean", false)
	require.Equal(t, "noop", doc["action"])

	code, stdout, stderr = e.run(t, nil, "--force", "db", "reset", "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	items := requireMutation(t, doc, "db reset", true)
	require.Equal(t, e.db, items[0].(map[string]any)["path"])
}

func TestSkillsInstallAndInitJSON(t *testing.T) {
	e := newB5Env(t)
	dir := filepath.Join(e.home, "skills-dest")

	code, stdout, stderr := e.run(t, nil, "skills", "install", "--dir", dir, "-j")
	require.Equal(t, 0, code, stderr)
	doc := oneDoc(t, stdout, stderr)
	items := requireMutation(t, doc, "skills install", true)
	require.Len(t, items, 1)
	require.Equal(t, true, items[0].(map[string]any)["installed"])

	code, stdout, stderr = e.run(t, nil, "skills", "install", "--dir", dir, "-j")
	require.Equal(t, 0, code, stderr)
	requireMutation(t, oneDoc(t, stdout, stderr), "skills install", false)

	// The first command above already initialized this HOME, so init is a no-op.
	code, stdout, stderr = e.run(t, nil, "init", "-j")
	require.Equal(t, 0, code, stderr)
	requireMutation(t, oneDoc(t, stdout, stderr), "init", false)
}

func TestStorageDownloadJSONNeedsOutputFile(t *testing.T) {
	e := newB5Env(t)
	code, stdout, stderr := e.run(t, nil, "storage", "download", "ugc/x", "-j")
	require.Equal(t, 2, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc := oneDoc(t, stdout, stderr)
	require.Equal(t, false, doc["ok"])
}

// TestProjectSourceInEnvelope covers the in-process mapping: the resolution
// branch decides, and a selection is split into flag vs env.
func TestProjectSourceInEnvelope(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	clicommon.ResetProjectResolutionForTest()
	t.Cleanup(clicommon.ResetProjectResolutionForTest)
	swapGlobal(t, &globalProjectUUID, "")
	swapGlobal(t, &globalProjectName, "")
	swapGlobal(t, &projectFromEnv, false)

	env := newAgentEnvelope("db stats", "", nil, 0, 0, 0)
	require.Equal(t, projectSourceDefault, env.extra["project_source"])
	require.NotContains(t, env.extra, "warnings")

	clicommon.PinProjectUUID("p-1")
	env = newAgentEnvelope("db stats", "", nil, 0, 0, 0)
	require.Equal(t, projectSourceFlag, env.extra["project_source"])

	projectFromEnv = true
	env = newAgentEnvelope("db stats", "", nil, 0, 0, 0)
	require.Equal(t, projectSourceEnv, env.extra["project_source"])
}
