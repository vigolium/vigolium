package database

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// insertValueFinding inserts a finding row with the fields value-grouping keys on.
func insertValueFinding(t *testing.T, db *DB, ctx context.Context, projectUUID, module, sev, host, matchedURL, extracted, tagsJSON string) int64 {
	t.Helper()
	matchedAt := "[]"
	if matchedURL != "" {
		matchedAt = `["` + matchedURL + `"]`
	}
	if extracted == "" {
		extracted = "[]"
	}
	if tagsJSON == "" {
		tagsJSON = "[]"
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO findings (project_uuid, scan_uuid, module_id, module_name,
			finding_hash, severity, confidence, http_record_uuids, hostname, matched_at,
			extracted_results, tags)
		VALUES (?, 'scan1', ?, ?, ?, ?, 'firm', '[]', ?, ?, ?, ?)`,
		projectUUID, module, module, uuid.NewString(), sev, host, matchedAt, extracted, tagsJSON)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

func TestGroupFindingsByValue(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	projectUUID := DefaultProjectUUID

	// Group: same module/severity/host/value across 3 URLs — collapses to 1.
	survivor := insertValueFinding(t, db, ctx, projectUUID, "secret-scan", "high", "www.x.com", "https://www.x.com/a", `["AIzaKEY"]`, `["secret"]`)
	_ = insertValueFinding(t, db, ctx, projectUUID, "secret-scan", "high", "www.x.com", "https://www.x.com/b", `["AIzaKEY"]`, `["secret"]`)
	_ = insertValueFinding(t, db, ctx, projectUUID, "secret-scan", "high", "www.x.com", "https://www.x.com/c", `["AIzaKEY"]`, `["secret"]`)

	// Different value, same everything else — kept separate.
	other := insertValueFinding(t, db, ctx, projectUUID, "secret-scan", "high", "www.x.com", "https://www.x.com/d", `["OTHERKEY"]`, `["secret"]`)

	// Same value but different host — with PerHost, kept separate.
	otherHost := insertValueFinding(t, db, ctx, projectUUID, "secret-scan", "high", "api.x.com", "https://api.x.com/a", `["AIzaKEY"]`, `["secret"]`)

	// No extracted value — never grouped.
	noExtract := insertValueFinding(t, db, ctx, projectUUID, "secret-scan", "high", "www.x.com", "https://www.x.com/e", "[]", `["secret"]`)

	deleted, grouped, err := repo.GroupFindingsByValue(ctx, projectUUID, GroupFindingOptions{PerHost: true, MaxURLs: 50})
	if err != nil {
		t.Fatalf("GroupFindingsByValue: %v", err)
	}
	if deleted != 2 {
		t.Errorf("expected 2 deleted, got %d", deleted)
	}
	if grouped != 1 {
		t.Errorf("expected 1 grouped, got %d", grouped)
	}

	var remaining []*Finding
	if err := db.NewSelect().Model(&remaining).Scan(ctx); err != nil {
		t.Fatalf("select remaining: %v", err)
	}
	survivors := map[int64]bool{survivor: true, other: true, otherHost: true, noExtract: true}
	if len(remaining) != len(survivors) {
		t.Errorf("expected %d remaining findings, got %d", len(survivors), len(remaining))
	}
	for _, f := range remaining {
		if !survivors[f.ID] {
			t.Errorf("unexpected survivor: id=%d module=%s host=%s", f.ID, f.ModuleID, f.Hostname)
		}
	}

	// Survivor should have absorbed all 3 URLs into MatchedAt.
	s := &Finding{}
	if err := db.NewSelect().Model(s).Where("id = ?", survivor).Scan(ctx); err != nil {
		t.Fatalf("select survivor: %v", err)
	}
	if len(s.MatchedAt) != 3 {
		t.Fatalf("expected survivor to span 3 URLs, got %d: %v", len(s.MatchedAt), s.MatchedAt)
	}
	want := map[string]bool{
		"https://www.x.com/a": false, "https://www.x.com/b": false, "https://www.x.com/c": false,
	}
	for _, u := range s.MatchedAt {
		if _, ok := want[u]; !ok {
			t.Errorf("unexpected matched URL on survivor: %s", u)
		}
		want[u] = true
	}
	for u, seen := range want {
		if !seen {
			t.Errorf("survivor missing matched URL: %s", u)
		}
	}
}

func TestGroupFindingsByValue_SiteWide(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	projectUUID := DefaultProjectUUID

	// Same value across two hosts. PerHost=false should merge them.
	survivor := insertValueFinding(t, db, ctx, projectUUID, "secret-scan", "high", "www.x.com", "https://www.x.com/a", `["AIzaKEY"]`, `["secret"]`)
	_ = insertValueFinding(t, db, ctx, projectUUID, "secret-scan", "high", "api.x.com", "https://api.x.com/a", `["AIzaKEY"]`, `["secret"]`)

	deleted, grouped, err := repo.GroupFindingsByValue(ctx, projectUUID, GroupFindingOptions{PerHost: false})
	if err != nil {
		t.Fatalf("GroupFindingsByValue: %v", err)
	}
	if deleted != 1 || grouped != 1 {
		t.Fatalf("site-wide: expected 1 deleted / 1 grouped, got %d / %d", deleted, grouped)
	}

	s := &Finding{}
	if err := db.NewSelect().Model(s).Where("id = ?", survivor).Scan(ctx); err != nil {
		t.Fatalf("select survivor: %v", err)
	}
	if len(s.MatchedAt) != 2 {
		t.Errorf("expected survivor to span 2 URLs across hosts, got %d: %v", len(s.MatchedAt), s.MatchedAt)
	}
}

func TestGroupFindingsByValue_TagGate(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	projectUUID := DefaultProjectUUID

	// Two same-value findings, but neither carries the required tag — not grouped.
	insertValueFinding(t, db, ctx, projectUUID, "diffscan", "high", "www.x.com", "https://www.x.com/a", `["v1.2.3"]`, `["version"]`)
	insertValueFinding(t, db, ctx, projectUUID, "diffscan", "high", "www.x.com", "https://www.x.com/b", `["v1.2.3"]`, `["version"]`)

	deleted, grouped, err := repo.GroupFindingsByValue(ctx, projectUUID, GroupFindingOptions{PerHost: true, Tags: []string{"secret", "exposure"}})
	if err != nil {
		t.Fatalf("GroupFindingsByValue: %v", err)
	}
	if deleted != 0 || grouped != 0 {
		t.Fatalf("tag gate: expected nothing grouped, got %d deleted / %d grouped", deleted, grouped)
	}

	// With a matching tag present, the same pair groups.
	insertValueFinding(t, db, ctx, projectUUID, "secret-scan", "high", "www.x.com", "https://www.x.com/a", `["SECRET"]`, `["secret"]`)
	insertValueFinding(t, db, ctx, projectUUID, "secret-scan", "high", "www.x.com", "https://www.x.com/b", `["SECRET"]`, `["Secret"]`) // case-insensitive
	deleted, grouped, err = repo.GroupFindingsByValue(ctx, projectUUID, GroupFindingOptions{PerHost: true, Tags: []string{"secret"}})
	if err != nil {
		t.Fatalf("GroupFindingsByValue (tagged): %v", err)
	}
	if deleted != 1 || grouped != 1 {
		t.Fatalf("tag gate (matching): expected 1 deleted / 1 grouped, got %d / %d", deleted, grouped)
	}
}

func TestGroupFindingsByValue_NoFindings(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	deleted, grouped, err := repo.GroupFindingsByValue(ctx, DefaultProjectUUID, GroupFindingOptions{PerHost: true})
	if err != nil {
		t.Fatalf("GroupFindingsByValue: %v", err)
	}
	if deleted != 0 || grouped != 0 {
		t.Errorf("expected no-op on empty DB, got %d deleted / %d grouped", deleted, grouped)
	}
}
