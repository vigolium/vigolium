package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/redact"
)

func TestParseRecordTags(t *testing.T) {
	got, err := ParseRecordTags([]string{"carried=1", "engagement=e-42", "carried=1", "note=a=b"})
	if err != nil {
		t.Fatalf("ParseRecordTags: %v", err)
	}
	want := []RecordTag{{"carried", "1"}, {"engagement", "e-42"}, {"note", "a=b"}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tag %d = %v, want %v", i, got[i], want[i])
		}
	}
	for _, bad := range [][]string{{"novalue"}, {"=v"}, {"k="}, {"bad key=v"}, {"k=1", "k=2"}} {
		if _, err := ParseRecordTags(bad); err == nil {
			t.Errorf("ParseRecordTags(%q) accepted", bad)
		}
	}
}

// closedSource builds a source store with fill and closes it, as a finished
// run's store is when it is imported.
func closedSource(t *testing.T, fill func(db *DB)) string {
	t.Helper()
	src, path := newFileDB(t, "src.sqlite")
	fill(src)
	if err := src.Close(); err != nil {
		t.Fatalf("close src: %v", err)
	}
	return path
}

// A re-import is a delta: records the destination holds are skipped by uuid
// (their stored bytes are not touched), counted, and not tagged again.
func TestMergeDeltaSkipsPresentRecordsAndTagsNewOnes(t *testing.T) {
	ctx := context.Background()
	srcPath := closedSource(t, func(db *DB) {
		insertHTTPRecord(t, db, "rec-a", DefaultProjectUUID)
		insertHTTPRecord(t, db, "rec-b", DefaultProjectUUID)
		mustExec(t, db, `UPDATE http_records SET raw_request = ? WHERE uuid = 'rec-a'`, []byte("SOURCE BYTES"))
		// The source's own label travels with its record.
		mustExec(t, db, `INSERT INTO record_tags (record_uuid, key, value) VALUES ('rec-b', 'origin', 'board')`)
	})

	dest, _ := newFileDB(t, "dest.sqlite")
	insertHTTPRecord(t, dest, "rec-a", DefaultProjectUUID)
	mustExec(t, dest, `UPDATE http_records SET raw_request = ? WHERE uuid = 'rec-a'`, []byte("DEST BYTES"))

	tags := []RecordTag{{Key: "carried", Value: "1"}}
	stats, err := MergeSQLiteFileWithOptions(ctx, dest, srcPath, MergeOptions{Tags: tags})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if stats.RecordsMerged != 1 || stats.RecordsSkippedPresent != 1 || stats.RecordsTagged != 1 {
		t.Fatalf("stats = %+v, want 1 merged, 1 skipped present, 1 tagged", stats)
	}
	var raw []byte
	if err := dest.QueryRowContext(ctx, `SELECT raw_request FROM http_records WHERE uuid = 'rec-a'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if string(raw) != "DEST BYTES" {
		t.Fatalf("present record rewritten: %q", raw)
	}
	if n := scalarInt(t, dest, `SELECT COUNT(*) FROM record_tags WHERE record_uuid = 'rec-a'`); n != 0 {
		t.Fatalf("a record the destination already held was tagged (%d rows)", n)
	}
	got, err := LoadRecordTags(ctx, dest, []string{"rec-a", "rec-b"})
	if err != nil {
		t.Fatal(err)
	}
	if got["rec-b"]["carried"] != "1" || got["rec-b"]["origin"] != "board" || len(got["rec-a"]) != 0 {
		t.Fatalf("tags = %v", got)
	}

	again, err := MergeSQLiteFileWithOptions(ctx, dest, srcPath, MergeOptions{Tags: []RecordTag{{Key: "carried", Value: "2"}}})
	if err != nil {
		t.Fatalf("re-merge: %v", err)
	}
	if again.RecordsMerged != 0 || again.RecordsSkippedPresent != 2 || again.RecordsTagged != 0 {
		t.Fatalf("re-merge stats = %+v, want 0 merged, 2 skipped present, 0 tagged", again)
	}
	if v := scalarInt(t, dest, `SELECT COUNT(*) FROM record_tags WHERE key = 'carried' AND value = '1'`); v != 1 {
		t.Fatalf("re-merge changed the existing label (carried=1 rows: %d)", v)
	}
}

// The host filter and the delta compose: a present record outside the filter
// is not counted as skipped.
func TestMergeDeltaCountsOnlyFilteredHosts(t *testing.T) {
	ctx := context.Background()
	srcPath := seedTwoHostSource(t)
	dest, _ := newFileDB(t, "dest.sqlite")
	first, err := MergeSQLiteFileWithOptions(ctx, dest, srcPath, MergeOptions{Hosts: []string{"a.example"}})
	if err != nil {
		t.Fatal(err)
	}
	again, err := MergeSQLiteFileWithOptions(ctx, dest, srcPath, MergeOptions{Hosts: []string{"a.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if again.RecordsMerged != 0 || again.RecordsSkippedPresent != first.RecordsMerged {
		t.Fatalf("re-merge = %+v after first %+v", again, first)
	}
}

const (
	redactSecretBearer = "Bearer s3cr3t-bearer"
	redactSecretCookie = "sid=c00kie-value"
	redactSecretToken  = "tok-in-query"
	redactSecretSet    = "fresh-session-123"
)

func credentialedRequest() string {
	return "GET /api/me?access_token=" + redactSecretToken + "&page=2 HTTP/1.1\r\n" +
		"Host: app.example\r\n" +
		"Authorization: " + redactSecretBearer + "\r\n" +
		"Proxy-Authorization: Basic cHJveHk6cGFzcw==\r\n" +
		"Cookie: " + redactSecretCookie + "; theme=dark\r\n" +
		"Accept: */*\r\n\r\n"
}

func credentialedResponse() string {
	return "HTTP/1.1 302 Found\r\n" +
		"Set-Cookie: session=" + redactSecretSet + "; Path=/; HttpOnly\r\n" +
		"Location: /next?token=loc-token\r\n" +
		"Content-Type: application/json\r\n\r\n" +
		`{"ok":true}`
}

// --redact credentials: every credential copy a written record and finding
// carries is masked inside the merge, the source is untouched, and the
// response hash describes the stored bytes.
func TestMergeRedactsCredentialsOfWrittenRows(t *testing.T) {
	ctx := context.Background()
	var recUUID string
	srcPath := closedSource(t, func(db *DB) {
		repo := NewRepository(db)
		var err error
		recUUID, err = repo.SaveRecord(ctx,
			provRR(t, credentialedRequest(), "https://app.example/api/me?access_token="+redactSecretToken+"&page=2", credentialedResponse()),
			RecordSourceIngestCLI, DefaultProjectUUID)
		if err != nil {
			t.Fatalf("SaveRecord: %v", err)
		}
		mustExec(t, db, `INSERT INTO findings (project_uuid, http_record_uuids, module_id, module_name, severity, finding_hash, request, response, additional_evidence)
			VALUES (?, ?, 'idor', 'IDOR', 'high', 'fh-red', ?, ?, ?)`,
			DefaultProjectUUID, `["`+recUUID+`"]`, credentialedRequest(), credentialedResponse(),
			`["GET / HTTP/1.1\r\nCookie: `+redactSecretCookie+`\r\n\r\n"]`)
	})

	dest, _ := newFileDB(t, "dest.sqlite")
	stats, err := MergeSQLiteFileWithOptions(ctx, dest, srcPath, MergeOptions{RedactCredentials: true})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if stats.RecordsRedacted != 1 || stats.FindingsRedacted != 1 {
		t.Fatalf("stats = %+v, want 1 record and 1 finding redacted", stats)
	}

	var (
		rawReq, rawResp                    []byte
		auth, url, path, loc, params, hash string
	)
	if err := dest.QueryRowContext(ctx, `SELECT raw_request, raw_response, request_authorization, url, path,
		COALESCE(response_location, ''), COALESCE(parameters, ''), response_hash FROM http_records WHERE uuid = ?`, recUUID).
		Scan(&rawReq, &rawResp, &auth, &url, &path, &loc, &params, &hash); err != nil {
		t.Fatal(err)
	}
	stored := strings.Join([]string{string(rawReq), string(rawResp), auth, url, path, loc, params}, "\n")
	for _, secret := range []string{"s3cr3t-bearer", "c00kie-value", redactSecretToken, redactSecretSet, "cHJveHk6cGFzcw=="} {
		if strings.Contains(stored, secret) {
			t.Errorf("redacted record still carries %q:\n%s", secret, stored)
		}
	}
	for _, kept := range []string{"Cookie: sid=" + redact.Placeholder, "theme=", "page=2", "Accept: */*", `{"ok":true}`, "Path=/; HttpOnly"} {
		if !strings.Contains(stored, kept) {
			t.Errorf("redaction lost %q:\n%s", kept, stored)
		}
	}
	if auth != redact.Placeholder {
		t.Errorf("request_authorization = %q, want the placeholder", auth)
	}
	sum := sha256.Sum256(rawResp)
	if hash != hex.EncodeToString(sum[:]) {
		t.Errorf("response_hash does not describe the stored response")
	}

	var freq, fresp, fev string
	if err := dest.QueryRowContext(ctx, `SELECT request, response, additional_evidence FROM findings WHERE finding_hash = 'fh-red'`).
		Scan(&freq, &fresp, &fev); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"s3cr3t-bearer", "c00kie-value", redactSecretSet} {
		if strings.Contains(freq+fresp+fev, secret) {
			t.Errorf("redacted finding still carries %q", secret)
		}
	}

	// The source is evidence: read-only, never rewritten.
	src, _ := openFileDB(t, srcPath, false)
	if err := src.QueryRowContext(ctx, `SELECT raw_request FROM http_records WHERE uuid = ?`, recUUID).Scan(&rawReq); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawReq), "s3cr3t-bearer") {
		t.Error("the merge rewrote its source")
	}
}

// Without --redact the merge copies the exchange verbatim.
func TestMergeWithoutRedactionKeepsBytes(t *testing.T) {
	ctx := context.Background()
	srcPath := closedSource(t, func(db *DB) {
		if _, err := NewRepository(db).SaveRecord(ctx,
			provRR(t, credentialedRequest(), "https://app.example/api/me", credentialedResponse()),
			RecordSourceIngestCLI, DefaultProjectUUID); err != nil {
			t.Fatal(err)
		}
	})
	dest, _ := newFileDB(t, "dest.sqlite")
	stats, err := MergeSQLiteFile(ctx, dest, srcPath)
	if err != nil {
		t.Fatal(err)
	}
	if stats.RecordsRedacted != 0 {
		t.Fatalf("RecordsRedacted = %d without redaction", stats.RecordsRedacted)
	}
	if n := scalarInt(t, dest, `SELECT COUNT(*) FROM http_records WHERE CAST(raw_request AS TEXT) LIKE '%s3cr3t-bearer%'`); n != 1 {
		t.Fatal("an unredacted merge changed the bytes")
	}
}

// A tag selects records, and deleting by tag removes them, their labels and
// the findings only they evidence — never a finding another record still
// proves, nor an untagged record.
func TestTagFilterAndDeleteByTag(t *testing.T) {
	ctx := context.Background()
	db, _ := newFileDB(t, "store.sqlite")
	for _, u := range []string{"tagged-1", "tagged-2", "native"} {
		insertHTTPRecord(t, db, u, DefaultProjectUUID)
	}
	repo := NewRepository(db)
	if err := repo.TagRecords(ctx, []string{"tagged-1", "tagged-2"}, []RecordTag{{"carried", "1"}, {"engagement", "e1"}}); err != nil {
		t.Fatal(err)
	}
	only := insertFinding(t, db, DefaultProjectUUID, "fh-only", "tagged-1")
	mustExec(t, db, `INSERT INTO finding_records (finding_id, record_uuid) VALUES (?, 'tagged-1')`, only)
	shared := insertFinding(t, db, DefaultProjectUUID, "fh-shared", "tagged-2")
	mustExec(t, db, `INSERT INTO finding_records (finding_id, record_uuid) VALUES (?, 'tagged-2'), (?, 'native')`, shared, shared)

	filters := QueryFilters{ProjectUUID: DefaultProjectUUID, Tags: []RecordTag{{"carried", "1"}}}
	recs, err := NewQueryBuilder(db, filters).Execute(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("tag filter matched %d records, want 2", len(recs))
	}
	none, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID,
		Tags: []RecordTag{{"carried", "1"}, {"engagement", "other"}}}).Execute(ctx)
	if err != nil || len(none) != 0 {
		t.Fatalf("tags are AND-combined: got %d records, err %v", len(none), err)
	}

	preview, err := NewDeleteBuilder(db, filters).DeleteRecordsByTable(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if preview["http_records"] != 2 || preview["record_tags"] != 4 || preview["findings"] != 1 {
		t.Fatalf("dry-run counts = %v", preview)
	}
	if n := scalarInt(t, db, `SELECT COUNT(*) FROM http_records`); n != 3 {
		t.Fatalf("dry run deleted rows (%d records left)", n)
	}

	if _, err := NewDeleteBuilder(db, filters).DeleteRecordsByTable(ctx, false); err != nil {
		t.Fatal(err)
	}
	if n := scalarInt(t, db, `SELECT COUNT(*) FROM http_records WHERE uuid = 'native'`); n != 1 {
		t.Fatal("an untagged record was deleted")
	}
	if n := scalarInt(t, db, `SELECT COUNT(*) FROM record_tags`); n != 0 {
		t.Fatalf("%d labels outlived their records", n)
	}
	if n := scalarInt(t, db, `SELECT COUNT(*) FROM findings WHERE finding_hash = 'fh-only'`); n != 0 {
		t.Fatal("a finding only the tagged records evidenced survived")
	}
	if n := scalarInt(t, db, `SELECT COUNT(*) FROM findings WHERE finding_hash = 'fh-shared'`); n != 1 {
		t.Fatal("a finding an untagged record still proves was deleted")
	}
}

// LoadRecordTags on a store from before record_tags answers "no labels".
func TestLoadRecordTagsWithoutTable(t *testing.T) {
	db := newTestDB(t)
	mustExec(t, db, `DROP TABLE record_tags`)
	got, err := LoadRecordTags(context.Background(), db, []string{"x"})
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

// A scan started at a cursor (scan --only-new-since) rewinds to it, so the
// assessment serves only records created at or after the floor; a scan with no
// start cursor rewinds to the beginning.
func TestResetScanCursorRewindsToStartCursor(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	const host = "inc.example"
	for _, p := range []string{"/old", "/new"} {
		if _, err := repo.SaveRecord(ctx, provRR(t, "GET "+p+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n", "https://"+host+p, provOK),
			RecordSourceIngestCLI, DefaultProjectUUID); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(t, db, `UPDATE http_records SET created_at = '2026-01-01 00:00:00' WHERE path = '/old'`)
	mustExec(t, db, `UPDATE http_records SET created_at = '2026-06-01 00:00:00' WHERE path = '/new'`)
	floor := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	newScan := func(start time.Time) string {
		s := &Scan{UUID: "scan-" + start.Format("20060102"), ProjectUUID: DefaultProjectUUID, Status: "running",
			ScanMode: "incremental", StartCursorAt: start, CursorAt: start}
		if err := repo.CreateScan(ctx, s); err != nil {
			t.Fatal(err)
		}
		// The seed phase advances the cursor past everything; the assessment
		// rewinds it.
		if err := repo.AdvanceScanCursor(ctx, s.UUID, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), "zzz"); err != nil {
			t.Fatal(err)
		}
		if err := repo.ResetScanCursor(ctx, s.UUID); err != nil {
			t.Fatal(err)
		}
		return s.UUID
	}
	scopes := []HostTarget{{Hostname: host}}

	inc := newScan(floor)
	row, err := repo.GetScanByUUID(ctx, inc)
	if err != nil || !row.CursorAt.Equal(floor) || row.CursorUUID != "" {
		t.Fatalf("rewound cursor = %v %q, want %v (err %v)", row.CursorAt, row.CursorUUID, floor, err)
	}
	if got := drainDA(t, NewRiskPrioritizedDBInputSource(db, repo, inc).WithHostScopes(scopes)); len(got) != 1 || got[0] != "GET /new" {
		t.Fatalf("incremental scan served %v, want only GET /new", got)
	}

	full := newScan(time.Time{})
	if got := drainDA(t, NewRiskPrioritizedDBInputSource(db, repo, full).WithHostScopes(scopes)); len(got) != 2 {
		t.Fatalf("a scan with no start cursor served %v, want both records", got)
	}
}
