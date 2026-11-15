package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/types"
)

// newExportTestDB returns a fresh schema-initialized SQLite DB in a temp dir.
func newExportTestDB(t *testing.T) *database.DB {
	t.Helper()
	return newDBAtPath(t, filepath.Join(t.TempDir(), "export.sqlite"))
}

// seedFindingAndRecord inserts one finding + one http_record under project.
func seedFindingAndRecord(t *testing.T, db *database.DB, project, suffix string) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, database.NewRepository(db).SaveFindingDirect(ctx, &database.Finding{
		ProjectUUID:     project,
		HTTPRecordUUIDs: []string{"rec-" + suffix},
		ModuleID:        "mod-" + suffix,
		ModuleName:      "Module " + suffix,
		Severity:        "high",
		Confidence:      "firm",
		FindingHash:     "hash-" + suffix,
		URL:             "http://" + suffix + ".example/",
		Hostname:        suffix + ".example",
	}))
	_, err := db.NewInsert().Model(&database.HTTPRecord{
		UUID:        "rec-" + suffix,
		ProjectUUID: project,
		Scheme:      "http",
		Hostname:    suffix + ".example",
		Port:        80,
		Method:      "GET",
		Path:        "/",
		URL:         "http://" + suffix + ".example/",
		HTTPVersion: "HTTP/1.1",
		RequestHash: "rhash-" + suffix,
	}).Exec(ctx)
	require.NoError(t, err)
}

func countEnvelopeTypes(t *testing.T, data []byte) map[string]int {
	t.Helper()
	counts := map[string]int{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		var env struct {
			Type string `json:"type"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &env))
		counts[env.Type]++
	}
	require.NoError(t, sc.Err())
	return counts
}

// reconcileOutputFormats decides whether --format jsonl routes through the
// post-scan unified envelope export (DeferredJSONLExport) or the legacy live
// nuclei stream (CI output).
func TestReconcileOutputFormatsDeferredJSONL(t *testing.T) {
	origJSON, origCI := globalJSON, globalCIOutput
	defer func() { globalJSON, globalCIOutput = origJSON, origCI }()

	t.Run("jsonl enables deferred export", func(t *testing.T) {
		globalJSON, globalCIOutput = false, false
		opts := &types.Options{OutputFormats: []string{"jsonl"}}
		require.NoError(t, reconcileOutputFormats(opts))
		assert.True(t, opts.DeferredJSONLExport)
		assert.True(t, opts.JSONOutput)
	})

	t.Run("console does not defer", func(t *testing.T) {
		globalJSON, globalCIOutput = false, false
		opts := &types.Options{OutputFormats: []string{"console"}}
		require.NoError(t, reconcileOutputFormats(opts))
		assert.False(t, opts.DeferredJSONLExport)
	})

	t.Run("--silent prints finding lines when stdout is free", func(t *testing.T) {
		swapGlobal(t, &globalSilent, true)
		swapGlobal(t, &scanOpts, types.DefaultOptions())
		cases := []struct {
			name    string
			json    bool
			formats []string
			output  string
			events  string
			want    bool
		}{
			{name: "console", formats: []string{"console"}, want: true},
			{name: "-j owns stdout", json: true, formats: []string{"console"}},
			{name: "jsonl to stdout", formats: []string{"jsonl"}},
			{name: "jsonl to a file", formats: []string{"jsonl"}, output: "x.jsonl", want: true},
			{name: "github to stdout", formats: []string{"github"}},
			{name: "--events", formats: []string{"console"}, events: "ndjson"},
		}
		for _, c := range cases {
			globalJSON = c.json
			scanOpts.Output, scanOpts.Events = c.output, c.events
			opts := &types.Options{OutputFormats: c.formats, Output: c.output}
			require.NoError(t, reconcileOutputFormats(opts), c.name)
			assert.Equal(t, c.want, opts.FindingLinesToStdout, c.name)
		}
		globalSilent = false
		globalJSON = false
		opts := &types.Options{OutputFormats: []string{"console"}}
		require.NoError(t, reconcileOutputFormats(opts))
		assert.False(t, opts.FindingLinesToStdout, "only a typed --silent")
	})

	t.Run("--json is the scan document, not jsonl", func(t *testing.T) {
		globalJSON, globalCIOutput = true, false
		opts := &types.Options{OutputFormats: []string{"console"}}
		require.NoError(t, reconcileOutputFormats(opts))
		assert.Equal(t, []string{"console"}, opts.OutputFormats, "--format jsonl only when explicit")
		assert.False(t, opts.DeferredJSONLExport)
		assert.True(t, opts.StdoutDocument)
	})
}

// The sqlite format normalizes its aliases (sqlite3, db) and is gated to
// stateless mode (it dumps the per-run temp DB).
func TestReconcileOutputFormatsSQLite(t *testing.T) {
	origJSON, origCI, origStateless := globalJSON, globalCIOutput, globalStateless
	defer func() { globalJSON, globalCIOutput, globalStateless = origJSON, origCI, origStateless }()
	globalJSON, globalCIOutput = false, false

	t.Run("aliases normalize to sqlite under --stateless", func(t *testing.T) {
		globalStateless = true
		for _, alias := range []string{"sqlite", "sqlite3", "db"} {
			opts := &types.Options{OutputFormats: []string{alias, "html"}}
			require.NoError(t, reconcileOutputFormats(opts), "alias %q", alias)
			assert.Equal(t, []string{"sqlite", "html"}, opts.OutputFormats, "alias %q", alias)
		}
	})

	t.Run("sqlite without --stateless errors", func(t *testing.T) {
		globalStateless = false
		opts := &types.Options{OutputFormats: []string{"sqlite"}}
		err := reconcileOutputFormats(opts)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--stateless")
	})
}

// writeJSONLExport must emit the unified {"type":...,"data":...} envelope (never
// the nuclei ResultEvent schema) and, when given a project UUID, scope every
// DB-backed row to that project.
func TestWriteJSONLExportEnvelopeAndProjectScope(t *testing.T) {
	ctx := context.Background()

	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = filepath.Join(t.TempDir(), "export.sqlite")
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	require.NoError(t, db.CreateSchema(ctx))
	repo := database.NewRepository(db)

	const projA = "00000000-0000-0000-0000-0000000000aa"
	const projB = "00000000-0000-0000-0000-0000000000bb"

	require.NoError(t, repo.SaveFindingDirect(ctx, &database.Finding{
		ProjectUUID:     projA,
		HTTPRecordUUIDs: []string{"rec-a"},
		ModuleID:        "mod-a",
		ModuleName:      "Module A",
		Severity:        "high",
		Confidence:      "firm",
		FindingHash:     "hash-a",
		URL:             "http://a.example/",
		Hostname:        "a.example",
	}))
	require.NoError(t, repo.SaveFindingDirect(ctx, &database.Finding{
		ProjectUUID:     projB,
		HTTPRecordUUIDs: []string{"rec-b"},
		ModuleID:        "mod-b",
		ModuleName:      "Module B",
		Severity:        "low",
		Confidence:      "firm",
		FindingHash:     "hash-b",
		URL:             "http://b.example/",
		Hostname:        "b.example",
	}))

	insertRecord := func(uuid, project, host, url, reqHash string) {
		rec := &database.HTTPRecord{
			UUID:        uuid,
			ProjectUUID: project,
			Scheme:      "http",
			Hostname:    host,
			Port:        80,
			Method:      "GET",
			Path:        "/",
			URL:         url,
			HTTPVersion: "HTTP/1.1",
			RequestHash: reqHash,
		}
		_, insErr := db.NewInsert().Model(rec).Exec(ctx)
		require.NoError(t, insErr)
	}
	insertRecord("rec-a", projA, "a.example", "http://a.example/", "rhash-a")
	insertRecord("rec-b", projB, "b.example", "http://b.example/", "rhash-b")

	var buf bytes.Buffer
	n, err := writeJSONLExport(ctx, db, &buf, false, projA, "")
	require.NoError(t, err)
	require.Positive(t, n)

	type envelope struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}

	var findings, records int
	sc := bufio.NewScanner(&buf)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		assert.NotContains(t, line, `"template-id"`, "must not emit nuclei ResultEvent schema")
		assert.NotContains(t, line, `"matcher-status"`, "must not emit nuclei ResultEvent schema")

		var env envelope
		require.NoError(t, json.Unmarshal([]byte(line), &env), "every line must be a typed envelope")
		require.NotEmpty(t, env.Type)
		require.NotEmpty(t, env.Data)

		switch env.Type {
		case "finding":
			findings++
			var f database.Finding
			require.NoError(t, json.Unmarshal(env.Data, &f))
			assert.Equal(t, projA, f.ProjectUUID, "findings must be scoped to project A")
		case "http_record":
			records++
			var r database.HTTPRecord
			require.NoError(t, json.Unmarshal(env.Data, &r))
			assert.Equal(t, projA, r.ProjectUUID, "records must be scoped to project A")
		}
	}
	require.NoError(t, sc.Err())

	assert.Equal(t, 1, findings, "exactly project A's finding, never project B's")
	assert.Equal(t, 1, records, "exactly project A's record, never project B's")
}

// omitResponse must drop the bulky raw byte fields from http_records while
// keeping the rest of the envelope intact.
func TestWriteJSONLExportOmitResponse(t *testing.T) {
	ctx := context.Background()

	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = filepath.Join(t.TempDir(), "omit.sqlite")
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	require.NoError(t, db.CreateSchema(ctx))

	const proj = "00000000-0000-0000-0000-0000000000cc"
	rec := &database.HTTPRecord{
		UUID:        "rec-omit",
		ProjectUUID: proj,
		Scheme:      "http",
		Hostname:    "omit.example",
		Port:        80,
		Method:      "GET",
		Path:        "/",
		URL:         "http://omit.example/",
		HTTPVersion: "HTTP/1.1",
		RequestHash: "rhash-omit",
		RawRequest:  []byte("GET / HTTP/1.1\r\nHost: omit.example\r\n\r\n"),
		RawResponse: []byte("HTTP/1.1 200 OK\r\n\r\nhello"),
	}
	_, err = db.NewInsert().Model(rec).Exec(ctx)
	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = writeJSONLExport(ctx, db, &buf, true, proj, "")
	require.NoError(t, err)

	out := buf.String()
	require.Contains(t, out, `"type":"http_record"`)
	assert.False(t, strings.Contains(out, `"raw_request"`), "omitResponse should drop raw_request")
	assert.False(t, strings.Contains(out, `"raw_response"`), "omitResponse should drop raw_response")
}

// finishScanJSONLExport is the persisted-scan entrypoint: it owns the
// stateless/output guards, the single-vs-multi-format output path, the stdout
// fallback, and the project scope.
func TestFinishScanJSONLExport(t *testing.T) {
	const projA = "00000000-0000-0000-0000-0000000000aa"

	t.Run("single format honors the literal -o path", func(t *testing.T) {
		db := newExportTestDB(t)
		seedFindingAndRecord(t, db, projA, "a")
		outPath := filepath.Join(t.TempDir(), "myout") // no extension
		opts := &types.Options{
			DeferredJSONLExport: true,
			Output:              outPath,
			OutputFormats:       []string{"jsonl"},
			ProjectUUID:         projA,
		}
		require.NoError(t, finishScanJSONLExport(db, opts))

		data, err := os.ReadFile(outPath) // literal path, no .jsonl appended
		require.NoError(t, err, "single-format export must honor the exact -o path")
		counts := countEnvelopeTypes(t, data)
		assert.Equal(t, 1, counts["finding"])
		assert.Equal(t, 1, counts["http_record"])
		assert.NotContains(t, string(data), `"template-id"`)
	})

	t.Run("multi-format writes the jsonl-suffixed path (no collision)", func(t *testing.T) {
		db := newExportTestDB(t)
		seedFindingAndRecord(t, db, projA, "a")
		base := filepath.Join(t.TempDir(), "myout")
		opts := &types.Options{
			DeferredJSONLExport: true,
			Output:              base, // -o myout, formats jsonl+console
			OutputFormats:       []string{"jsonl", "console"},
			ProjectUUID:         projA,
		}
		require.NoError(t, finishScanJSONLExport(db, opts))

		// Multi-format must use the .jsonl-suffixed path so it never clobbers the
		// console live file (which uses the bare base path).
		_, err := os.Stat(base)
		assert.True(t, os.IsNotExist(err), "must NOT write to the bare console base path")
		data, err := os.ReadFile(base + ".jsonl")
		require.NoError(t, err, "multi-format export must use the .jsonl path")
		assert.Equal(t, 1, countEnvelopeTypes(t, data)["finding"])
	})

	t.Run("stateless with -o is a no-op (finishStatelessExport handles it)", func(t *testing.T) {
		db := newExportTestDB(t)
		seedFindingAndRecord(t, db, projA, "a")
		outPath := filepath.Join(t.TempDir(), "stateless.jsonl")
		opts := &types.Options{
			DeferredJSONLExport: true,
			Stateless:           true,
			Output:              outPath,
			OutputFormats:       []string{"jsonl"},
			ProjectUUID:         projA,
		}
		require.NoError(t, finishScanJSONLExport(db, opts))
		_, err := os.Stat(outPath)
		assert.True(t, os.IsNotExist(err), "stateless+output is handled by finishStatelessExport, not here")
	})

	t.Run("stateless without -o streams the envelope to stdout", func(t *testing.T) {
		db := newExportTestDB(t)
		seedFindingAndRecord(t, db, projA, "a")
		opts := &types.Options{
			DeferredJSONLExport: true,
			Stateless:           true,
			Output:              "", // discard-to-DB but still emit jsonl to stdout
			OutputFormats:       []string{"jsonl"},
			ProjectUUID:         projA,
		}
		out := captureStdout(t, func() { require.NoError(t, finishScanJSONLExport(db, opts)) })
		counts := countEnvelopeTypes(t, []byte(out))
		assert.Equal(t, 1, counts["finding"], "stateless no-o must stream to stdout, not silently drop")
		assert.Equal(t, 1, counts["http_record"])
	})

	t.Run("empty ProjectUUID falls back to the default project", func(t *testing.T) {
		db := newExportTestDB(t)
		seedFindingAndRecord(t, db, database.DefaultProjectUUID, "def")
		seedFindingAndRecord(t, db, projA, "other")
		outPath := filepath.Join(t.TempDir(), "default.jsonl")
		opts := &types.Options{
			DeferredJSONLExport: true,
			Output:              outPath,
			OutputFormats:       []string{"jsonl"},
			ProjectUUID:         "", // → DefaultProjectUUID
		}
		require.NoError(t, finishScanJSONLExport(db, opts))

		data, err := os.ReadFile(outPath)
		require.NoError(t, err)
		// Only the default-project finding, not projA's.
		assert.Equal(t, 1, countEnvelopeTypes(t, data)["finding"])
	})

	t.Run("persisted run streams only this scan, not the project", func(t *testing.T) {
		db := newExportTestDB(t)
		ctx := context.Background()
		repo := database.NewRepository(db)
		const scanOld, scanNew = "scan-old", "scan-new"
		for _, s := range []struct{ scan, suffix string }{{scanOld, "old"}, {scanNew, "new"}} {
			_, err := db.NewInsert().Model(&database.Scan{
				UUID: s.scan, ProjectUUID: projA, Status: "completed",
			}).Exec(ctx)
			require.NoError(t, err)
			require.NoError(t, repo.SaveFindingDirect(ctx, &database.Finding{
				ProjectUUID: projA,
				ScanUUID:    s.scan,
				ModuleID:    "mod-" + s.suffix,
				ModuleName:  "Module " + s.suffix,
				Severity:    "high",
				Confidence:  "firm",
				FindingHash: "hash-" + s.suffix,
				URL:         "http://" + s.suffix + ".example/",
				Hostname:    s.suffix + ".example",
			}))
			// Each scan stored one exchange (http_records.scan_uuid, A5b).
			_, err = db.NewInsert().Model(&database.HTTPRecord{
				UUID: "rec-" + s.suffix, ProjectUUID: projA, ScanUUID: s.scan,
				Scheme: "http", Hostname: s.suffix + ".example", Port: 80, Method: "GET",
				Path: "/", URL: "http://" + s.suffix + ".example/", HTTPVersion: "HTTP/1.1",
				RequestHash: "rhash-" + s.suffix,
			}).Exec(ctx)
			require.NoError(t, err)
		}
		opts := &types.Options{
			DeferredJSONLExport: true,
			OutputFormats:       []string{"jsonl"},
			ProjectUUID:         projA,
			ScanUUID:            scanNew,
		}
		out := captureStdout(t, func() { require.NoError(t, finishScanJSONLExport(db, opts)) })
		counts := countEnvelopeTypes(t, []byte(out))
		assert.Equal(t, 1, counts["finding"], "only this scan's finding")
		assert.Equal(t, 1, counts["scan"], "only this scan's row")
		assert.Equal(t, 1, counts["http_record"], "only the record this scan stored")
		assert.Contains(t, out, `"hash-new"`)
		assert.Contains(t, out, `"rec-new"`)
		assert.NotContains(t, out, `"hash-old"`, "an earlier scan's finding must not leak into this scan's stream")
		assert.NotContains(t, out, `"rec-old"`, "nor an earlier scan's records")
		assert.NotContains(t, out, `"scan-old"`)

		// `vigolium export` (streamJSONLExport, no scan UUID) stays project-wide.
		var buf bytes.Buffer
		all, err := streamJSONLExport(ctx, db, &buf, false, projA)
		require.NoError(t, err)
		assert.Equal(t, 2, all.byType["finding"])
		assert.Equal(t, 2, all.byType["http_record"])
	})

	t.Run("not deferred is a no-op", func(t *testing.T) {
		db := newExportTestDB(t)
		seedFindingAndRecord(t, db, projA, "a")
		outPath := filepath.Join(t.TempDir(), "noop.jsonl")
		opts := &types.Options{
			DeferredJSONLExport: false,
			Output:              outPath,
			OutputFormats:       []string{"jsonl"},
			ProjectUUID:         projA,
		}
		require.NoError(t, finishScanJSONLExport(db, opts))
		_, err := os.Stat(outPath)
		assert.True(t, os.IsNotExist(err))
	})
}
