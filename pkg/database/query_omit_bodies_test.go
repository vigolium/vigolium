package database

import (
	"context"
	"testing"
)

// seedBodyRecord inserts one http_record carrying a raw request/response, so a
// test can tell a projected-away body from an absent one. Layered on
// insertHTTPRecord (which writes metadata only) the way merge_test.go does.
func seedBodyRecord(t *testing.T, db *DB, uuid string, status int, body string) {
	t.Helper()
	insertHTTPRecord(t, db, uuid, DefaultProjectUUID)
	mustExec(t, db, `UPDATE http_records
		SET status_code = ?, has_response = 1, raw_request = ?, raw_response = ?
		WHERE uuid = ?`,
		status,
		[]byte("GET /"+uuid+" HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\n\r\n"+body),
		uuid)
}

// TestQueryBuilder_OmitBodies covers the contract callers rely on: the raw
// request/response come back empty, while every other field — and, critically,
// every filter — behaves exactly as it does without the projection.
func TestQueryBuilder_OmitBodies(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	seedBodyRecord(t, db, "rec1", 200, "needle-in-body")
	seedBodyRecord(t, db, "rec2", 404, "other")

	t.Run("bodies omitted, metadata kept", func(t *testing.T) {
		records, err := NewQueryBuilder(db, QueryFilters{}).OmitBodies().Execute(ctx)
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if len(records) != 2 {
			t.Fatalf("got %d records, want 2", len(records))
		}
		for _, r := range records {
			if len(r.RawRequest) != 0 || len(r.RawResponse) != 0 {
				t.Fatalf("record %s kept its bodies (req=%d resp=%d bytes)", r.UUID, len(r.RawRequest), len(r.RawResponse))
			}
			if r.Hostname != "example.com" || r.Method != "GET" || r.URL == "" {
				t.Fatalf("record %s lost metadata: %+v", r.UUID, r)
			}
		}
	})

	t.Run("default keeps bodies", func(t *testing.T) {
		records, err := NewQueryBuilder(db, QueryFilters{}).Execute(ctx)
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		for _, r := range records {
			if len(r.RawRequest) == 0 || len(r.RawResponse) == 0 {
				t.Fatalf("default query dropped bodies for %s", r.UUID)
			}
		}
	})

	// The reason OmitBodies is separate from MergeOptions.SkipRecordBodies: the
	// columns still exist, so a WHERE over them is unaffected by the projection.
	t.Run("body search still matches with bodies omitted", func(t *testing.T) {
		f := QueryFilters{SearchTerms: []string{"needle-in-body"}}
		withBodies, err := NewQueryBuilder(db, f).Execute(ctx)
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		omitted, err := NewQueryBuilder(db, f).OmitBodies().Execute(ctx)
		if err != nil {
			t.Fatalf("Execute (omitted): %v", err)
		}
		if len(withBodies) != 1 {
			t.Fatalf("baseline search matched %d records, want 1", len(withBodies))
		}
		if len(omitted) != len(withBodies) {
			t.Fatalf("OmitBodies changed the result set: %d vs %d — the projection must not affect the WHERE",
				len(omitted), len(withBodies))
		}
		if omitted[0].UUID != "rec1" {
			t.Fatalf("matched %s, want rec1", omitted[0].UUID)
		}
	})

	t.Run("metadata filter and count unaffected", func(t *testing.T) {
		records, total, err := NewQueryBuilder(db, QueryFilters{StatusCodes: []int{200}}).OmitBodies().ExecuteWithCount(ctx)
		if err != nil {
			t.Fatalf("ExecuteWithCount: %v", err)
		}
		if total != 1 || len(records) != 1 || records[0].UUID != "rec1" {
			t.Fatalf("status filter broke under OmitBodies: total=%d len=%d", total, len(records))
		}
	})
}

// TestRepository_ExistingRecordUUIDs covers the projected existence check used to
// validate caller-supplied UUID lists.
func TestRepository_ExistingRecordUUIDs(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	insertHTTPRecord(t, db, "rec1", DefaultProjectUUID)
	insertHTTPRecord(t, db, "rec2", DefaultProjectUUID)
	repo := NewRepository(db)

	got, err := repo.ExistingRecordUUIDs(ctx, []string{"rec1", "missing", "rec2"})
	if err != nil {
		t.Fatalf("ExistingRecordUUIDs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %v, want the 2 existing uuids", got)
	}
	for _, u := range got {
		if u != "rec1" && u != "rec2" {
			t.Fatalf("unexpected uuid %q", u)
		}
	}

	empty, err := repo.ExistingRecordUUIDs(ctx, []string{"nope"})
	if err != nil {
		t.Fatalf("ExistingRecordUUIDs (none): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("got %v, want none", empty)
	}
}

// TestRepository_RecordProjectUUID covers the projected scope lookup, including
// the not-found signal the handlers branch on.
func TestRepository_RecordProjectUUID(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	insertHTTPRecord(t, db, "rec1", DefaultProjectUUID)
	repo := NewRepository(db)

	got, err := repo.RecordProjectUUID(ctx, "rec1")
	if err != nil {
		t.Fatalf("RecordProjectUUID: %v", err)
	}
	if got != DefaultProjectUUID {
		t.Fatalf("got project %q, want %q", got, DefaultProjectUUID)
	}

	// Handlers map this to 404, so it must stay a no-rows error.
	if _, err := repo.RecordProjectUUID(ctx, "missing"); err == nil {
		t.Fatal("expected an error for a missing record")
	}
}
