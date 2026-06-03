package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
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
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = filepath.Join(t.TempDir(), "export.sqlite")
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.CreateSchema(context.Background()))
	return db
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

// captureStdout redirects os.Stdout for the duration of fn and returns what was
// written, so the stdout-streaming export branch can be asserted.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	require.NoError(t, w.Close())
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
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

	t.Run("CI output keeps the legacy emitter", func(t *testing.T) {
		globalJSON, globalCIOutput = false, true
		opts := &types.Options{OutputFormats: []string{"console"}}
		require.NoError(t, reconcileOutputFormats(opts))
		assert.True(t, opts.CIOutput)
		assert.False(t, opts.DeferredJSONLExport, "CI output must not route through the envelope export")
	})

	t.Run("--json maps to jsonl and defers", func(t *testing.T) {
		globalJSON, globalCIOutput = true, false
		opts := &types.Options{OutputFormats: []string{"console"}}
		require.NoError(t, reconcileOutputFormats(opts))
		assert.Equal(t, []string{"jsonl"}, opts.OutputFormats)
		assert.True(t, opts.DeferredJSONLExport)
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
	n, err := writeJSONLExport(ctx, db, &buf, false, projA)
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
	_, err = writeJSONLExport(ctx, db, &buf, true, proj)
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
		finishScanJSONLExport(db, opts)

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
		finishScanJSONLExport(db, opts)

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
		finishScanJSONLExport(db, opts)
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
		out := captureStdout(t, func() { finishScanJSONLExport(db, opts) })
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
		finishScanJSONLExport(db, opts)

		data, err := os.ReadFile(outPath)
		require.NoError(t, err)
		// Only the default-project finding, not projA's.
		assert.Equal(t, 1, countEnvelopeTypes(t, data)["finding"])
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
		finishScanJSONLExport(db, opts)
		_, err := os.Stat(outPath)
		assert.True(t, os.IsNotExist(err))
	})
}
