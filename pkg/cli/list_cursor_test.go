package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

// seedCursorStore opens e's store and writes n findings and n records, newest
// last, and returns the open database for writes between pages.
func seedCursorStore(t *testing.T, e *b5Env, n int) *database.DB {
	t.Helper()
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = e.db
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.EnsureSchemaReady(context.Background()))
	base := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	for i := range n {
		addCursorFinding(t, db, base.Add(time.Duration(i)*time.Minute))
		addCursorRecord(t, db, base.Add(time.Duration(i)*time.Minute))
	}
	return db
}

func addCursorFinding(t *testing.T, db *database.DB, at time.Time) {
	t.Helper()
	_, err := db.NewInsert().Model(&database.Finding{
		ProjectUUID: database.DefaultProjectUUID, ModuleID: "m", ModuleName: "m", Severity: "low",
		Confidence: "firm", FindingHash: uuid.NewString(), HTTPRecordUUIDs: []string{},
		RecordKind: database.RecordKindFinding, FoundAt: at, CreatedAt: at,
	}).Exec(context.Background())
	require.NoError(t, err)
}

func addCursorRecord(t *testing.T, db *database.DB, at time.Time) {
	t.Helper()
	id := uuid.NewString()
	_, err := db.NewInsert().Model(&database.HTTPRecord{
		UUID: id, ProjectUUID: database.DefaultProjectUUID, Scheme: "https", Hostname: "h.test", Port: 443,
		Method: "GET", Path: "/" + id[:8], URL: "https://h.test/" + id[:8], HTTPVersion: "HTTP/1.1",
		RequestHash: id, StatusCode: 200, HasResponse: true, SentAt: at, CreatedAt: at,
	}).Exec(context.Background())
	require.NoError(t, err)
}

// itemKeys returns each item's identity: the finding id or the record uuid.
func itemKeys(t *testing.T, items []any) []string {
	t.Helper()
	out := make([]string, 0, len(items))
	for _, it := range items {
		m := it.(map[string]any)
		switch {
		case m["uuid"] != nil:
			out = append(out, m["uuid"].(string))
		case m["id"] != nil:
			out = append(out, fmt.Sprint(m["id"]))
		default:
			t.Fatalf("item has no identity: %v", m)
		}
	}
	return out
}

// Both listings state truncated, hand back next_cursor while rows remain, and
// --cursor resumes after the page: followed to the end, the pages deliver the
// whole listing once, even with a newer row written between pages.
func TestListCursorsPageFindingAndTraffic(t *testing.T) {
	e := newB5Env(t)
	db := seedCursorStore(t, e, 5)
	for _, list := range []string{"finding", "traffic"} {
		t.Run(list, func(t *testing.T) {
			code, stdout, stderr := e.run(t, nil, list, "-j", "-n", "0")
			require.Equal(t, 0, code, stderr)
			full := oneDoc(t, stdout, stderr)
			assert.Equal(t, false, full["truncated"], "an unlimited listing is not truncated")
			assert.NotContains(t, full, "next_cursor")
			want := itemKeys(t, requireEnvelope(t, full, list, "read"))
			require.Len(t, want, 5)

			var got []string
			cursor := ""
			for page := 0; ; page++ {
				require.Less(t, page, 10, "paging did not end")
				args := []string{list, "-j", "-n", "2"}
				if cursor != "" {
					args = append(args, "--cursor", cursor)
				}
				code, stdout, stderr := e.run(t, nil, args...)
				require.Equal(t, 0, code, stderr)
				doc := oneDoc(t, stdout, stderr)
				got = append(got, itemKeys(t, requireEnvelope(t, doc, list, "read"))...)
				truncated, _ := doc["truncated"].(bool)
				if !truncated {
					assert.NotContains(t, doc, "next_cursor")
					break
				}
				assert.EqualValues(t, 5+page, doc["total"], "total counts the whole result, not what is left")
				cursor, _ = doc["next_cursor"].(string)
				require.NotEmpty(t, cursor, "a truncated page carries next_cursor")
				if page == 0 {
					// A scan writes a newer row: newest-first, it lands ahead
					// of the cursor and does not shift the next page.
					if list == "finding" {
						addCursorFinding(t, db, time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))
					} else {
						addCursorRecord(t, db, time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))
					}
				}
			}
			assert.Equal(t, want, got, "every row of the original listing, once, in order")
		})
	}
}

// A page the output budget cuts resumes at the first row it dropped.
func TestListCursorFollowsOutputBudgetCut(t *testing.T) {
	e := newB5Env(t)
	seedCursorStore(t, e, 6)
	code, stdout, stderr := e.run(t, nil, "finding", "-j", "-n", "6")
	require.Equal(t, 0, code, stderr)
	full := oneDoc(t, stdout, stderr)
	want := itemKeys(t, requireEnvelope(t, full, "finding", "read"))
	assert.Equal(t, false, full["truncated"])

	budget := len(stdout) - 200
	code, stdout, stderr = e.run(t, nil, "finding", "-j", "-n", "6", "--max-output-bytes", strconv.Itoa(budget))
	require.Equal(t, 0, code, stderr)
	cut := oneDoc(t, stdout, stderr)
	kept := itemKeys(t, cut["items"].([]any))
	require.Less(t, len(kept), 6, "the budget cut the page")
	assert.Equal(t, true, cut["truncated"])
	cursor, _ := cut["next_cursor"].(string)
	require.NotEmpty(t, cursor)

	code, stdout, stderr = e.run(t, nil, "finding", "-j", "-n", "6", "--cursor", cursor)
	require.Equal(t, 0, code, stderr)
	rest := itemKeys(t, oneDoc(t, stdout, stderr)["items"].([]any))
	assert.Equal(t, want, append(kept, rest...), "the next page starts at the first dropped row")
}

// A cursor is refused (exit 2) with --offset, under another order, from the
// other listing, or when it is not a cursor at all.
func TestListCursorRefusals(t *testing.T) {
	e := newB5Env(t)
	seedCursorStore(t, e, 3)
	code, stdout, stderr := e.run(t, nil, "finding", "-j", "-n", "1")
	require.Equal(t, 0, code, stderr)
	cursor, _ := oneDoc(t, stdout, stderr)["next_cursor"].(string)
	require.NotEmpty(t, cursor)

	for name, args := range map[string][]string{
		"with --offset":   {"finding", "-j", "--cursor", cursor, "--offset", "1"},
		"other order":     {"finding", "-j", "--cursor", cursor, "--sort", "severity"},
		"other direction": {"finding", "-j", "--cursor", cursor, "--asc"},
		"other listing":   {"traffic", "-j", "--cursor", cursor},
		"not a cursor":    {"finding", "-j", "--cursor", "not-a-cursor"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := e.run(t, nil, args...)
			require.Equal(t, ExitUsageError, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
			var doc map[string]any
			require.NoError(t, json.Unmarshal([]byte(stdout), &doc), stdout)
			assert.Equal(t, "usage_error", doc["error"].(map[string]any)["code"])
		})
	}
}

// The cursor codec round-trips both value kinds and both tie kinds.
func TestListCursorCodec(t *testing.T) {
	for _, k := range []*database.Keyset{
		{Value: "2026-11-01 10:00:00", Tie: int64(7)},
		{Value: int64(4), Tie: "0b7c-uuid"},
	} {
		c := encodeListCursor("finding", "f.found_at desc", k)
		require.NotEmpty(t, c)
		got, err := decodeListCursor(c, "finding", "f.found_at desc")
		require.NoError(t, err)
		assert.Equal(t, k, got)
	}
	got, err := decodeListCursor("  ", "finding", "x")
	assert.NoError(t, err)
	assert.Nil(t, got)
}
