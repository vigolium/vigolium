package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dbimport"
)

// resetProjectScopeGlobals restores every global the project-scope resolution
// reads, and clears the once-per-process memo so each case resolves its own
// selection rather than silently asserting the first one's answer.
func resetProjectScopeGlobals(t *testing.T) {
	t.Helper()
	orig := struct {
		db, glob, projUUID, projName string
		stateless, auto, env, silent bool
	}{
		db: globalDB, glob: globalGlobDB,
		projUUID: globalProjectUUID, projName: globalProjectName,
		stateless: globalStateless, auto: dbPathEnvAutoStateless,
		env: projectFromEnv, silent: globalSilent,
	}
	globalDB, globalGlobDB = "", ""
	globalProjectUUID, globalProjectName = "", ""
	globalStateless, dbPathEnvAutoStateless, projectFromEnv = false, false, false
	globalSilent = true // keep the env-project notice out of the test log
	clicommon.ResetProjectResolutionForTest()
	t.Cleanup(func() {
		globalDB, globalGlobDB = orig.db, orig.glob
		globalProjectUUID, globalProjectName = orig.projUUID, orig.projName
		globalStateless, dbPathEnvAutoStateless = orig.stateless, orig.auto
		projectFromEnv, globalSilent = orig.env, orig.silent
		clicommon.ResetProjectResolutionForTest()
	})
}

// An explicit project selection is a filter even on a standalone source. It used
// to be dropped, so `finding -S --db merged.sqlite --project-uuid X` listed every
// project in the file while looking like it had narrowed to one.
func TestEffectiveProjectUUIDStatelessExplicit(t *testing.T) {
	t.Run("explicit --project-uuid filters", func(t *testing.T) {
		resetProjectScopeGlobals(t)
		globalStateless = true
		globalProjectUUID = "P"

		got, err := effectiveProjectUUID()
		require.NoError(t, err)
		assert.Equal(t, "P", got)
	})

	t.Run("no selection stays unscoped", func(t *testing.T) {
		resetProjectScopeGlobals(t)
		globalStateless = true

		got, err := effectiveProjectUUID()
		require.NoError(t, err)
		assert.Empty(t, got, "a standalone source carries its own project_uuid; default scoping is off")
	})

	t.Run("env var counts as explicit", func(t *testing.T) {
		resetProjectScopeGlobals(t)
		globalStateless = true
		// root.go folds VIGOLIUM_PROJECT_UUID into the global and records that it
		// came from the environment.
		globalProjectUUID, projectFromEnv = "P-env", true

		got, err := effectiveProjectUUID()
		require.NoError(t, err)
		assert.Equal(t, "P-env", got)
	})

	t.Run("--project-name over a JSONL source is a usage error", func(t *testing.T) {
		resetProjectScopeGlobals(t)
		globalStateless = true
		globalDB = filepath.Join(t.TempDir(), "export.jsonl")
		globalProjectName = "acme"

		_, err := effectiveProjectUUID()
		require.Error(t, err, "a JSONL export has no project registry to resolve a name in")
		assert.Equal(t, ExitUsageError, classifyExitCode(err))
		assert.Contains(t, err.Error(), "--project-uuid")
	})

	t.Run("--project-name over a glob merge is a usage error", func(t *testing.T) {
		resetProjectScopeGlobals(t)
		globalGlobDB = "scans/*.jsonl"
		globalProjectName = "acme"

		_, err := effectiveProjectUUID()
		require.Error(t, err)
		assert.Equal(t, ExitUsageError, classifyExitCode(err))
	})
}

// A record in another project must read as absent, not as forbidden: saying
// "that belongs to another project" confirms the UUID exists, which is what a
// scoped reader must not learn.
func TestTrafficBodyCrossProjectNotFound(t *testing.T) {
	resetProjectScopeGlobals(t)
	origUUID := extractUUID
	t.Cleanup(func() {
		extractUUID = origUUID
		clicommon.CloseDatabaseOnExit()
	})

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "two-projects.sqlite")
	db := newDBAtPath(t, dbPath)
	seedFindingAndRecord(t, db, "projA", "a")
	seedFindingAndRecord(t, db, "projB", "b")
	seedRawBytes(t, db, "rec-a")
	seedRawBytes(t, db, "rec-b")
	require.NoError(t, db.Close())

	globalDB = dbPath
	globalStateless = true
	globalProjectUUID = "projA"

	t.Run("in-scope record resolves", func(t *testing.T) {
		extractUUID = "rec-a"
		msg, err := loadExtractTarget(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "rec-a", msg.Record.UUID)
		assert.Equal(t, "projA", msg.ProjectScope, "the receipt reports the scope the lookup applied")
	})

	t.Run("out-of-scope record reads as missing", func(t *testing.T) {
		extractUUID = "rec-b"
		_, err := loadExtractTarget(context.Background())
		require.Error(t, err)
		assert.Equal(t, apicontract.CodeRecordNotFound, classifyErrorCode(err, classifyExitCode(err)))
		assert.NotContains(t, err.Error(), "project",
			"the message must not reveal that the record exists elsewhere")
	})
}

// `export --project-uuid` filters. It used to pass "" at every call site, so the
// flag the root help documents as scoping all operations scoped nothing here.
func TestExportExplicitProjectFilters(t *testing.T) {
	resetProjectScopeGlobals(t)
	t.Cleanup(clicommon.CloseDatabaseOnExit)

	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "export.sqlite")
	db := newDBAtPath(t, dbPath)
	seedFindingAndRecord(t, db, "projA", "a")
	seedFindingAndRecord(t, db, "projB", "b")
	for _, p := range []string{"projA", "projB"} {
		_, err := db.NewInsert().Model(&database.Project{UUID: p, Name: p}).Exec(ctx)
		require.NoError(t, err)
	}

	t.Run("no selection exports every project", func(t *testing.T) {
		resetProjectScopeGlobals(t)
		r := &exportRun{db: db}
		var buf bytes.Buffer
		counts, err := streamJSONLExport(ctx, db, &buf, false, r.projectUUID)
		require.NoError(t, err)
		require.Positive(t, counts.total)
		assert.Equal(t, 2, countEnvelopeTypes(t, buf.Bytes())["finding"])
	})

	t.Run("an explicit project narrows", func(t *testing.T) {
		resetProjectScopeGlobals(t)
		globalDB = dbPath
		globalProjectUUID = "projA"
		// openDB resolves the filter; the handle is already open here, so the
		// resolution is driven directly the way openDB would.
		r := &exportRun{db: db}
		require.True(t, explicitProjectSelected())
		uuid, err := resolveProjectUUID()
		require.NoError(t, err)
		r.projectUUID = uuid

		var buf bytes.Buffer
		counts, err := streamJSONLExport(ctx, db, &buf, false, r.projectUUID)
		require.NoError(t, err)
		require.Positive(t, counts.total)

		out := buf.String()
		assert.Contains(t, out, "projA")
		assert.NotContains(t, out, "projB", "another project's rows must not be in a scoped export")
		assert.Equal(t, 1, countEnvelopeTypes(t, buf.Bytes())["finding"])
	})
}

// A JSONL load for a read-only scratch database keeps each row's own project, so
// `-S` output reports the data's project rather than the reader's.
func TestImportJSONLPreserveProject(t *testing.T) {
	ctx := context.Background()
	lines := strings.Join([]string{
		envelopeLine(t, "http_record", map[string]any{
			"uuid": "rec-a", "project_uuid": "projA", "scheme": "http",
			"hostname": "a.example", "port": 80, "method": "GET", "path": "/",
			"url": "http://a.example/", "http_version": "HTTP/1.1", "request_hash": "ra",
		}),
		envelopeLine(t, "http_record", map[string]any{
			"uuid": "rec-none", "scheme": "http",
			"hostname": "n.example", "port": 80, "method": "GET", "path": "/",
			"url": "http://n.example/", "http_version": "HTTP/1.1", "request_hash": "rn",
		}),
	}, "\n") + "\n"

	load := func(t *testing.T, preserve bool) map[string]string {
		t.Helper()
		db := newExportTestDB(t)
		repo := database.NewRepository(db)
		_, err := dbimport.ImportJSONL(ctx, repo, strings.NewReader(lines), "target-project",
			dbimport.Options{PreserveProjectUUID: preserve})
		require.NoError(t, err)

		var rows []struct {
			UUID        string `bun:"uuid"`
			ProjectUUID string `bun:"project_uuid"`
		}
		require.NoError(t, db.NewRaw("SELECT uuid, project_uuid FROM http_records").Scan(ctx, &rows))
		got := map[string]string{}
		for _, r := range rows {
			got[r.UUID] = r.ProjectUUID
		}
		return got
	}

	t.Run("preserve keeps the row's project", func(t *testing.T) {
		got := load(t, true)
		assert.Equal(t, "projA", got["rec-a"])
		assert.Equal(t, "target-project", got["rec-none"],
			"a row with no project of its own still gets the import target")
	})

	t.Run("the default re-homes every row", func(t *testing.T) {
		got := load(t, false)
		assert.Equal(t, "target-project", got["rec-a"],
			"persistent import must keep re-homing rows into the project they are imported into")
		assert.Equal(t, "target-project", got["rec-none"])
	})
}

// `db ls -S` used to call getDB, which opens the DEFAULT project database, and
// then dropped the project filter because the read was stateless — listing every
// project's rows in the operator's own store.
func TestDBListStatelessRequiresSource(t *testing.T) {
	resetProjectScopeGlobals(t)
	globalStateless = true

	_, err := openReadDB(globDBSkipSet{})
	require.Error(t, err, "-S without --db must not silently open the default database")
	assert.Contains(t, err.Error(), "--db")
}

// newDBAtPath opens a schema-initialized SQLite database at an exact path, so a
// test can hand that path to the CLI as --db.
func newDBAtPath(t *testing.T, path string) *database.DB {
	t.Helper()
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = path
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	// Closed on cleanup: this used to leak a handle per case, which on a table
	// test is one open SQLite connection per row for the rest of the package run.
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.CreateSchema(context.Background()))
	return db
}

// seedRawBytes gives an existing record a raw request and response, which
// traffic body/headers require.
func seedRawBytes(t *testing.T, db *database.DB, uuid string) {
	t.Helper()
	_, err := db.NewRaw(
		"UPDATE http_records SET raw_request = ?, raw_response = ?, has_response = ? WHERE uuid = ?",
		[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody-"+uuid),
		true, uuid,
	).Exec(context.Background())
	require.NoError(t, err)
}

// envelopeLine renders one {type,data} JSONL line.
func envelopeLine(t *testing.T, typ string, data map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"type": typ, "data": data})
	require.NoError(t, err)
	return string(b)
}

// `vigolium export` reads the active project by default, like every sibling
// read; --all-projects spans the store and cannot be combined with a project.
func TestExportProjectFilterDefaultsToActiveProject(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetProjectScopeGlobals(t)
	prev := topExportAllProjects
	t.Cleanup(func() { topExportAllProjects = prev })

	topExportAllProjects = false
	got, err := exportProjectFilter()
	require.NoError(t, err)
	assert.Equal(t, database.DefaultProjectUUID, got, "no flag must not mean every project")

	topExportAllProjects = true
	got, err = exportProjectFilter()
	require.NoError(t, err)
	assert.Empty(t, got)

	globalProjectUUID = database.DefaultProjectUUID
	_, err = exportProjectFilter()
	var usage clicommon.UsageError
	require.ErrorAs(t, err, &usage)

	// A standalone source is read whole unless a project is named.
	resetProjectScopeGlobals(t)
	topExportAllProjects = false
	globalStateless = true
	got, err = exportProjectFilter()
	require.NoError(t, err)
	assert.Empty(t, got)
}
