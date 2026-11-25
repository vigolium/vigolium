package cli

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
)

const tagRedactRawRequest = "GET /me HTTP/1.1\r\nHost: app.example.com\r\nAuthorization: Bearer cli-bearer-secret\r\nCookie: sid=cli-cookie-secret\r\n\r\n"

// seedCredentialedSQLite writes a vigolium SQLite source with two records on
// app.example.com, each carrying an Authorization and a Cookie.
func seedCredentialedSQLite(t *testing.T, dir string) string {
	t.Helper()
	return seedSQLiteRequest(t, dir, tagRedactRawRequest)
}

// seedSQLiteRequest writes a vigolium SQLite source with two records on
// app.example.com whose raw request is raw.
func seedSQLiteRequest(t *testing.T, dir, raw string) string {
	t.Helper()
	path := filepath.Join(dir, "board.sqlite")
	db := newDBAtPath(t, path)
	for _, id := range []string{"rec-1", "rec-2"} {
		_, err := db.ExecContext(context.Background(), `INSERT INTO http_records
			(uuid, project_uuid, scheme, hostname, port, method, path, url, http_version, request_hash, raw_request, request_authorization)
			VALUES (?, ?, 'https', 'app.example.com', 443, 'GET', '/me', 'https://app.example.com/me', 'HTTP/1.1', ?, ?, 'Bearer cli-bearer-secret')`,
			id, database.DefaultProjectUUID, "rh-"+id, []byte(raw))
		require.NoError(t, err)
	}
	require.NoError(t, db.Close())
	return path
}

// `import --tag --redact credentials` labels and masks the written records and
// says so in -j; a re-import is a delta; `traffic --tag` reads the labelled
// records back with their tags; `db clean --tag` previews and deletes them.
func TestImportTagRedactRoundTrip(t *testing.T) {
	e := newB5Env(t)
	src := seedCredentialedSQLite(t, t.TempDir())

	code, stdout, stderr := e.run(t, nil, "import", src, "--tag", "carried=1", "--tag", "engagement=e7", "--redact", "credentials", "-j")
	require.Equal(t, 0, code, stderr)
	doc := oneDoc(t, stdout, stderr)
	require.EqualValues(t, 2, doc["records_merged"])
	require.EqualValues(t, 0, doc["records_skipped_present"])
	require.EqualValues(t, 2, doc["records_tagged"])
	require.EqualValues(t, 2, doc["records_redacted"])
	require.Equal(t, "credentials", doc["redaction"])
	require.Equal(t, map[string]any{"carried": "1", "engagement": "e7"}, doc["tags"])

	db := newDBAtPath(t, e.db)
	var leaked int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM http_records WHERE CAST(raw_request AS TEXT) LIKE '%secret%' OR request_authorization LIKE '%secret%'`).Scan(&leaked))
	require.Zero(t, leaked, "a stored record still carries a credential")
	require.NoError(t, db.Close())

	code, stdout, stderr = e.run(t, nil, "import", src, "--tag", "carried=1", "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	require.EqualValues(t, 0, doc["records_merged"])
	require.EqualValues(t, 2, doc["records_skipped_present"], "a re-import skips the records already present")
	require.EqualValues(t, 0, doc["records_tagged"])

	code, stdout, stderr = e.run(t, nil, "traffic", "--tag", "engagement=e7", "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	require.EqualValues(t, 2, doc["total"])
	row := doc["items"].([]any)[0].(map[string]any)
	require.Equal(t, map[string]any{"carried": "1", "engagement": "e7"}, row["tags"])

	code, stdout, stderr = e.run(t, nil, "traffic", "--tag", "engagement=other", "-j")
	require.Equal(t, 0, code, stderr)
	require.EqualValues(t, 0, oneDoc(t, stdout, stderr)["total"])

	code, stdout, stderr = e.run(t, nil, "db", "clean", "--tag", "carried=1", "--dry-run", "-j")
	require.Equal(t, 0, code, stderr)
	doc = oneDoc(t, stdout, stderr)
	require.Equal(t, true, doc["dry_run"])
	counts := map[string]float64{}
	for _, it := range doc["items"].([]any) {
		m := it.(map[string]any)
		counts[m["table"].(string)] = m["rows"].(float64)
	}
	require.EqualValues(t, 2, counts["http_records"])
	require.EqualValues(t, 4, counts["record_tags"])

	code, _, stderr = e.run(t, nil, "--force", "db", "clean", "--tag", "carried=1", "-j")
	require.Equal(t, 0, code, stderr)
	code, stdout, stderr = e.run(t, nil, "traffic", "-j")
	require.Equal(t, 0, code, stderr)
	require.EqualValues(t, 0, oneDoc(t, stdout, stderr)["total"])
}

// `--redact-header` masks a header vigolium does not recognize as a credential
// itself; without it the same header is stored as sent.
func TestImportRedactHeader(t *testing.T) {
	raw := "GET /me HTTP/1.1\r\nHost: app.example.com\r\nX-Acme-Sess: acme-house-secret\r\n\r\n"
	stored := func(t *testing.T, extra ...string) int {
		t.Helper()
		e := newB5Env(t)
		src := seedSQLiteRequest(t, t.TempDir(), raw)
		args := append([]string{"import", src, "--redact", "credentials", "-j"}, extra...)
		code, stdout, stderr := e.run(t, nil, args...)
		require.Equal(t, 0, code, stderr)
		oneDoc(t, stdout, stderr)
		db := newDBAtPath(t, e.db)
		defer func() { _ = db.Close() }()
		var n int
		require.NoError(t, db.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM http_records WHERE CAST(raw_request AS TEXT) LIKE '%acme-house-secret%'`).Scan(&n))
		return n
	}
	require.Equal(t, 2, stored(t), "vigolium's own list does not name X-Acme-Sess")
	require.Zero(t, stored(t, "--redact-header", "x-acme-sess"))
}

// The flags refuse what they cannot honour, before anything is written.
func TestImportTagRedactRefusals(t *testing.T) {
	e := newB5Env(t)
	src := seedCredentialedSQLite(t, t.TempDir())
	for name, args := range map[string][]string{
		"unknown redaction":   {"import", src, "--redact", "everything"},
		"header w/o redact":   {"import", src, "--redact-header", "X-A"},
		"header not a name":   {"import", src, "--redact", "credentials", "--redact-header", "a: b"},
		"malformed tag":       {"import", src, "--tag", "novalue"},
		"one key two values":  {"import", src, "--tag", "k=1", "--tag", "k=2"},
		"bridge pull":         {"import", "--burp-bridge-url", "http://127.0.0.1:1", "--tag", "k=v"},
		"tag on findings":     {"db", "clean", "--tag", "k=v", "--findings-only"},
		"tag with --table":    {"db", "clean", "--tag", "k=v", "--table", "http_records"},
		"traffic bad tag key": {"traffic", "--tag", "bad key=v"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := e.run(t, nil, args...)
			require.Equal(t, 2, code, stderr)
		})
	}
}
