package dbimport

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/redact"
	"github.com/vigolium/vigolium/pkg/database"
)

const (
	tagRedactRequest  = "GET /me?api_key=k3y-in-query HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer jsonl-bearer\r\nCookie: sid=jsonl-cookie\r\n\r\n"
	tagRedactResponse = "HTTP/1.1 200 OK\r\nSet-Cookie: sid=jsonl-new; Path=/\r\nContent-Type: text/plain\r\n\r\nhello"
)

// A JSONL import with --tag and --redact credentials: the records it writes
// are labelled and stored masked, and a re-import (nothing written) neither
// tags nor counts anything.
func TestImportJSONLTagsAndRedactsWrittenRecords(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()
	rec := database.HTTPRecord{
		UUID: "jsonl-1", Scheme: "https", Hostname: "example.com", Port: 443, Method: "GET",
		Path: "/me?api_key=k3y-in-query", URL: "https://example.com/me?api_key=k3y-in-query", HTTPVersion: "HTTP/1.1",
		RequestHash: "h-1", StatusCode: 200, HasResponse: true, RequestAuthorization: "Bearer jsonl-bearer",
		RawRequest: []byte(tagRedactRequest), RawResponse: []byte(tagRedactResponse),
	}
	finding := database.Finding{
		ModuleID: "idor", ModuleName: "IDOR", Severity: "high", FindingHash: "fh-jsonl",
		HTTPRecordUUIDs: []string{"jsonl-1"}, Request: tagRedactRequest, Response: tagRedactResponse,
	}
	stream := jsonlEnvelope(t, "http_record", rec) + "\n" + jsonlEnvelope(t, "finding", finding) + "\n"
	opts := Options{Tags: []database.RecordTag{{Key: "carried", Value: "1"}}, RedactCredentials: true}

	res, err := ImportJSONL(ctx, repo, strings.NewReader(stream), "", opts)
	if err != nil {
		t.Fatalf("ImportJSONL: %v", err)
	}
	if res.RecordsImported != 1 || res.RecordsTagged != 1 || res.RecordsRedacted != 1 || res.FindingsRedacted != 1 {
		t.Fatalf("result = imported %d tagged %d redacted %d/%d, want 1 each",
			res.RecordsImported, res.RecordsTagged, res.RecordsRedacted, res.FindingsRedacted)
	}

	stored, err := repo.GetRecordByUUID(ctx, "jsonl-1")
	if err != nil {
		t.Fatal(err)
	}
	all := string(stored.RawRequest) + string(stored.RawResponse) + stored.RequestAuthorization + stored.URL + stored.Path
	for _, secret := range []string{"jsonl-bearer", "jsonl-cookie", "jsonl-new", "k3y-in-query"} {
		if strings.Contains(all, secret) {
			t.Errorf("stored record carries %q", secret)
		}
	}
	if !strings.Contains(string(stored.RawResponse), "hello") || stored.RequestAuthorization != redact.Placeholder {
		t.Errorf("redaction lost the body or left request_authorization %q", stored.RequestAuthorization)
	}
	tags, err := database.LoadRecordTags(ctx, repo.DB(), []string{"jsonl-1"})
	if err != nil || tags["jsonl-1"]["carried"] != "1" {
		t.Fatalf("tags = %v, %v", tags, err)
	}
	var f database.Finding
	if err := repo.DB().NewSelect().Model(&f).Where("finding_hash = ?", "fh-jsonl").Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.Request+f.Response, "jsonl-bearer") || strings.Contains(f.Request+f.Response, "jsonl-new") {
		t.Errorf("stored finding carries a credential:\n%s\n%s", f.Request, f.Response)
	}

	again, err := ImportJSONL(ctx, repo, strings.NewReader(stream), "", opts)
	if err != nil {
		t.Fatalf("re-import: %v", err)
	}
	if again.RecordsImported != 0 || again.RecordsTagged != 0 || again.RecordsRedacted != 0 {
		t.Fatalf("re-import tagged/redacted rows it did not write: %+v", again)
	}
}

// ImportPath carries the options into a SQLite merge and maps its counters.
func TestImportPathSQLiteTagsAndRedacts(t *testing.T) {
	ctx := context.Background()
	srcPath := filepath.Join(t.TempDir(), "board.sqlite")
	src := newFileDBForTest(t, srcPath)
	if _, err := src.ExecContext(ctx, `INSERT INTO http_records
		(uuid, project_uuid, scheme, hostname, port, method, path, url, http_version, request_hash, raw_request)
		VALUES ('rec-1', ?, 'https', 'example.com', 443, 'GET', '/me', 'https://example.com/me', 'HTTP/1.1', 'rh-1', ?)`,
		database.DefaultProjectUUID, []byte(tagRedactRequest)); err != nil {
		t.Fatal(err)
	}
	if err := src.Close(); err != nil {
		t.Fatal(err)
	}
	dest := newFileDBForTest(t, filepath.Join(t.TempDir(), "dest.sqlite"))
	t.Cleanup(func() { _ = dest.Close() })
	repo := database.NewRepository(dest)

	opts := Options{Tags: []database.RecordTag{{Key: "engagement", Value: "e9"}}, RedactCredentials: true}
	res, err := ImportPath(ctx, repo, srcPath, database.DefaultProjectUUID, opts)
	if err != nil {
		t.Fatalf("ImportPath: %v", err)
	}
	if res.RecordsTagged != 1 || res.RecordsRedacted != 1 || res.MergeStats.RecordsSkippedPresent != 0 {
		t.Fatalf("result = %+v / %+v", res, res.MergeStats)
	}
	again, err := ImportPath(ctx, repo, srcPath, database.DefaultProjectUUID, opts)
	if err != nil {
		t.Fatal(err)
	}
	if again.MergeStats.RecordsSkippedPresent != 1 || again.RecordsImported != 0 {
		t.Fatalf("re-import is not a delta: %+v", again.MergeStats)
	}
	agg := MergeResults([]*Result{res, again})
	if agg.RecordsTagged != 1 || agg.RecordsRedacted != 1 || agg.MergeStats.RecordsSkippedPresent != 1 {
		t.Fatalf("aggregate = tagged %d redacted %d skipped %d", agg.RecordsTagged, agg.RecordsRedacted, agg.MergeStats.RecordsSkippedPresent)
	}
}
