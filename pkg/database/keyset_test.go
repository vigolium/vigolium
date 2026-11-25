package database

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

func insertKeysetFinding(t *testing.T, db *DB, module, severity string, at time.Time) int64 {
	t.Helper()
	f := &Finding{
		ProjectUUID: DefaultProjectUUID, ModuleID: module, ModuleName: module, Severity: severity,
		Confidence: "firm", FindingHash: uuid.NewString(), HTTPRecordUUIDs: []string{},
		RecordKind: RecordKindFinding, FoundAt: at, CreatedAt: at,
	}
	if _, err := db.NewInsert().Model(f).Exec(context.Background()); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	return f.ID
}

// pageFindings follows ExecutePage + KeysetAt to the end and returns the ids
// in the order they arrived. between runs after the first page.
func pageFindings(t *testing.T, db *DB, filters QueryFilters, between func()) []int64 {
	t.Helper()
	ctx := context.Background()
	var got []int64
	var after *Keyset
	for page := 0; page < 50; page++ {
		fqb := NewFindingsQueryBuilder(db, filters)
		rows, _, more, err := fqb.ExecutePage(ctx, after)
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		for _, f := range rows {
			got = append(got, f.ID)
		}
		if !more {
			return got
		}
		k, ok, err := fqb.KeysetAt(ctx, rows[len(rows)-1])
		if err != nil || !ok {
			t.Fatalf("KeysetAt: ok=%v err=%v", ok, err)
		}
		after = k
		if page == 0 && between != nil {
			between()
		}
	}
	t.Fatal("paging did not end")
	return nil
}

func findingIDs(t *testing.T, db *DB, filters QueryFilters) []int64 {
	t.Helper()
	filters.Limit = 0
	rows, _, err := NewFindingsQueryBuilder(db, filters).ExecuteWithCount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]int64, len(rows))
	for i, f := range rows {
		ids[i] = f.ID
	}
	return ids
}

// Keyset pages, followed to the end, yield the same rows in the same order as
// one unpaged read, for every sort the list accepts and in both directions,
// including timestamps stored in two text layouts and tied sort values.
func TestFindingKeysetPagesMatchFullOrder(t *testing.T) {
	db := newTestDB(t)
	base := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	sevs := []string{"high", "info", "medium", "critical", "low", "medium", "info"}
	for i, sev := range sevs {
		at := base.Add(time.Duration(i/2) * time.Minute) // pairs share found_at
		insertKeysetFinding(t, db, fmt.Sprintf("mod-%d", i%3), sev, at)
	}
	// One row in SQLite's CURRENT_TIMESTAMP layout, as a default-filled insert
	// stores it.
	if _, err := db.NewRaw("UPDATE findings SET found_at = '2026-11-01 10:01:00' WHERE id = (SELECT MIN(id) FROM findings)").Exec(context.Background()); err != nil {
		t.Fatal(err)
	}

	for _, sort := range []string{"found_at", "created_at", "severity", "module", "module_id", "confidence"} {
		for _, asc := range []bool{false, true} {
			filters := QueryFilters{ProjectUUID: DefaultProjectUUID, SortBy: sort, SortAsc: asc, Limit: 2}
			want := findingIDs(t, db, filters)
			got := pageFindings(t, db, filters, nil)
			if !slices.Equal(got, want) {
				t.Errorf("sort %s asc=%v: pages %v, unpaged %v", sort, asc, got, want)
			}
		}
	}
}

// Rows written ahead of the cursor and rows removed behind it do not move the
// next page: every surviving original row arrives exactly once.
func TestFindingKeysetStableUnderConcurrentWrites(t *testing.T) {
	db := newTestDB(t)
	base := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	for i := range 9 {
		insertKeysetFinding(t, db, "m", "low", base.Add(time.Duration(i)*time.Second))
	}
	filters := QueryFilters{ProjectUUID: DefaultProjectUUID, Limit: 3}
	original := findingIDs(t, db, filters)

	removed := original[1] // already delivered on page one
	got := pageFindings(t, db, filters, func() {
		// A scan stores newer findings (they sort first, newest-first) and the
		// dedup pass merges one already delivered.
		insertKeysetFinding(t, db, "m", "low", base.Add(time.Hour))
		insertKeysetFinding(t, db, "m", "low", base.Add(2*time.Hour))
		if _, err := db.NewDelete().Model((*Finding)(nil)).Where("id = ?", removed).Exec(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	if !slices.Equal(got, original) {
		t.Fatalf("pages under concurrent writes = %v, want every original row once %v", got, original)
	}

	// total counts the store as it is now: 9 + 2 written - 1 removed.
	_, total, more, err := NewFindingsQueryBuilder(db, filters).ExecutePage(context.Background(), nil)
	if err != nil || !more || total != 10 {
		t.Fatalf("first page: total=%d more=%v err=%v", total, more, err)
	}
}

// The last page reports no more rows; a limit of 0 reads everything.
func TestFindingExecutePageMoreAndTotal(t *testing.T) {
	db := newTestDB(t)
	for i := range 4 {
		insertKeysetFinding(t, db, "m", "low", time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC))
	}
	ctx := context.Background()
	rows, total, more, err := NewFindingsQueryBuilder(db, QueryFilters{Limit: 4}).ExecutePage(ctx, nil)
	if err != nil || len(rows) != 4 || total != 4 || more {
		t.Fatalf("exact page: rows=%d total=%d more=%v err=%v", len(rows), total, more, err)
	}
	rows, total, more, err = NewFindingsQueryBuilder(db, QueryFilters{Limit: 3, Offset: 2}).ExecutePage(ctx, nil)
	if err != nil || len(rows) != 2 || total != 4 || more {
		t.Fatalf("offset page: rows=%d total=%d more=%v err=%v", len(rows), total, more, err)
	}
	rows, _, more, err = NewFindingsQueryBuilder(db, QueryFilters{}).ExecutePage(ctx, nil)
	if err != nil || len(rows) != 4 || more {
		t.Fatalf("unlimited: rows=%d more=%v err=%v", len(rows), more, err)
	}
}

// Record pages follow the same contract, including the nullable source column
// (NULL and "" are one value) and numeric sorts.
func TestRecordKeysetPagesMatchFullOrder(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	base := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	sources := []string{"", "deparos", "", "spider", "deparos", "", "ingest-cli"}
	for i, src := range sources {
		id := uuid.NewString()
		at := base.Add(time.Duration(i/2) * time.Second)
		if _, err := db.NewInsert().Model(&HTTPRecord{
			UUID: id, ProjectUUID: DefaultProjectUUID, Scheme: "https", Hostname: "h.com", Port: 443,
			Method: "GET", Path: fmt.Sprintf("/p%d", i), URL: fmt.Sprintf("https://h.com/p%d", i), HTTPVersion: "HTTP/1.1",
			RequestHash: id, StatusCode: 200 + i%3, HasResponse: true, Source: src, SentAt: at, CreatedAt: at,
		}).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.NewRaw("UPDATE http_records SET source = '' WHERE path = '/p5'").Exec(ctx); err != nil {
		t.Fatal(err)
	}

	for _, sort := range []string{"created_at", "sent_at", "source", "status", "path", "uuid"} {
		for _, asc := range []bool{false, true} {
			filters := QueryFilters{ProjectUUID: DefaultProjectUUID, SortBy: sort, SortAsc: asc}
			all, _, more, err := NewQueryBuilder(db, filters).OmitBodies().ExecutePage(ctx, nil)
			if err != nil || more {
				t.Fatalf("unpaged %s: more=%v err=%v", sort, more, err)
			}
			var want []string
			for _, r := range all {
				want = append(want, r.UUID)
			}

			filters.Limit = 2
			var got []string
			var after *Keyset
			for {
				qb := NewQueryBuilder(db, filters).OmitBodies()
				rows, _, more, err := qb.ExecutePage(ctx, after)
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range rows {
					got = append(got, r.UUID)
				}
				if !more {
					break
				}
				k, ok, err := qb.KeysetAt(ctx, rows[len(rows)-1])
				if err != nil || !ok {
					t.Fatalf("KeysetAt: ok=%v err=%v", ok, err)
				}
				after = k
			}
			if !slices.Equal(got, want) {
				t.Errorf("sort %s asc=%v: pages %v, unpaged %v", sort, asc, got, want)
			}
		}
	}
}

// KeysetAt reports a row that is no longer stored.
func TestKeysetAtMissingRow(t *testing.T) {
	db := newTestDB(t)
	_, ok, err := NewFindingsQueryBuilder(db, QueryFilters{}).KeysetAt(context.Background(), &Finding{ID: 4242})
	if err != nil || ok {
		t.Fatalf("missing row: ok=%v err=%v", ok, err)
	}
}
