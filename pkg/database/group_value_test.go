package database

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// insertGroupFinding inserts one finding row, defaulting empty JSON columns to
// "[]". The value/desc wrappers below pin the fields each test family cares about.
func insertGroupFinding(t *testing.T, db *DB, ctx context.Context, projectUUID, module, sev, conf, host, matchedURL, extracted, tagsJSON, desc string) int64 {
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
			extracted_results, tags, description)
		VALUES (?, 'scan1', ?, ?, ?, ?, ?, '[]', ?, ?, ?, ?, ?)`,
		projectUUID, module, module, uuid.NewString(), sev, conf, host, matchedAt, extracted, tagsJSON, desc)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

// insertValueFinding inserts a finding row with the fields value-grouping keys on.
func insertValueFinding(t *testing.T, db *DB, ctx context.Context, projectUUID, module, sev, host, matchedURL, extracted, tagsJSON string) int64 {
	t.Helper()
	return insertGroupFinding(t, db, ctx, projectUUID, module, sev, "firm", host, matchedURL, extracted, tagsJSON, "")
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

func TestGroupFindingsByValue_ByModule(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	projectUUID := DefaultProjectUUID

	// sourcemap-detect fires once per JS bundle, each with a DISTINCT extracted
	// value (the .map filename). Listed in ByModule, all three collapse to one
	// finding per (module, severity, host) despite the differing values.
	survivor := insertValueFinding(t, db, ctx, projectUUID, "sourcemap-detect", "low", "app.x.com", "https://app.x.com/main.111.js", `["main.111.js.map"]`, `["sourcemap"]`)
	_ = insertValueFinding(t, db, ctx, projectUUID, "sourcemap-detect", "low", "app.x.com", "https://app.x.com/polyfills.222.js", `["polyfills.222.js.map"]`, `["sourcemap"]`)
	_ = insertValueFinding(t, db, ctx, projectUUID, "sourcemap-detect", "low", "app.x.com", "https://app.x.com/runtime.333.js", `["runtime.333.js.map"]`, `["sourcemap"]`)

	// A higher-severity sourcemap finding (the .map file itself, full source) on
	// the same host must NOT merge into the Low group — severity is in the key.
	highMap := insertValueFinding(t, db, ctx, projectUUID, "sourcemap-detect", "high", "app.x.com", "https://app.x.com/main.111.js.map", `["src/secret.ts"]`, `["sourcemap","source-code"]`)

	// Same module on a different host stays separate under PerHost.
	otherHost := insertValueFinding(t, db, ctx, projectUUID, "sourcemap-detect", "low", "api.x.com", "https://api.x.com/app.444.js", `["app.444.js.map"]`, `["sourcemap"]`)

	// A non-by-module module with distinct values must stay separate (sanity).
	keepA := insertValueFinding(t, db, ctx, projectUUID, "secret-scan", "high", "app.x.com", "https://app.x.com/a", `["KEY-A"]`, `["secret"]`)
	keepB := insertValueFinding(t, db, ctx, projectUUID, "secret-scan", "high", "app.x.com", "https://app.x.com/b", `["KEY-B"]`, `["secret"]`)

	deleted, grouped, err := repo.GroupFindingsByValue(ctx, projectUUID, GroupFindingOptions{
		PerHost:  true,
		ByModule: []string{"sourcemap-detect"},
		MaxURLs:  50,
	})
	if err != nil {
		t.Fatalf("GroupFindingsByValue: %v", err)
	}
	if deleted != 2 {
		t.Errorf("expected 2 deleted (the two extra Low sourcemap findings), got %d", deleted)
	}
	if grouped != 1 {
		t.Errorf("expected 1 grouped, got %d", grouped)
	}

	var remaining []*Finding
	if err := db.NewSelect().Model(&remaining).Scan(ctx); err != nil {
		t.Fatalf("select remaining: %v", err)
	}
	survivors := map[int64]bool{survivor: true, highMap: true, otherHost: true, keepA: true, keepB: true}
	if len(remaining) != len(survivors) {
		t.Errorf("expected %d remaining findings, got %d", len(survivors), len(remaining))
	}
	for _, f := range remaining {
		if !survivors[f.ID] {
			t.Errorf("unexpected survivor: id=%d module=%s sev=%s host=%s", f.ID, f.ModuleID, f.Severity, f.Hostname)
		}
	}

	// The Low survivor should span all three JS bundle URLs.
	s := &Finding{}
	if err := db.NewSelect().Model(s).Where("id = ?", survivor).Scan(ctx); err != nil {
		t.Fatalf("select survivor: %v", err)
	}
	if len(s.MatchedAt) != 3 {
		t.Fatalf("expected survivor to span 3 URLs, got %d: %v", len(s.MatchedAt), s.MatchedAt)
	}
}

// insertDescFinding inserts a by-module-style finding carrying a description so the
// rollup-note behaviour can be asserted.
func insertDescFinding(t *testing.T, db *DB, ctx context.Context, projectUUID, module, host, matchedURL, extracted, desc string) int64 {
	t.Helper()
	return insertGroupFinding(t, db, ctx, projectUUID, module, "info", "certain", host, matchedURL, extracted, "[]", desc)
}

// TestGroupFindingsByValue_ByModuleMergesValues verifies that collapsing a
// by-module group unions the distinct per-URL extracted values onto the survivor
// (not just the URLs) and annotates the description with an idempotent rollup note.
func TestGroupFindingsByValue_ByModuleMergesValues(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	projectUUID := DefaultProjectUUID

	// baas-endpoint-fingerprint fires once per response, each naming a DIFFERENT
	// third-party service. By-module grouping collapses them but must keep every
	// service name visible on the survivor.
	survivor := insertDescFinding(t, db, ctx, projectUUID, "baas-endpoint-fingerprint", "portal.x.com",
		"https://portal.x.com/a", `["AWS API Gateway: pgnsgvwfw0"]`, "AWS API Gateway endpoint referenced")
	insertDescFinding(t, db, ctx, projectUUID, "baas-endpoint-fingerprint", "portal.x.com",
		"https://portal.x.com/b", `["AWS Cognito (Hosted UI): portal-kios"]`, "AWS Cognito endpoint referenced")
	insertDescFinding(t, db, ctx, projectUUID, "baas-endpoint-fingerprint", "portal.x.com",
		"https://portal.x.com/c", `["AWS Cognito (IdP): ap-southeast-1"]`, "AWS Cognito IdP referenced")

	opts := GroupFindingOptions{PerHost: true, ByModule: []string{"baas-endpoint-fingerprint"}, MaxURLs: 50}
	deleted, grouped, err := repo.GroupFindingsByValue(ctx, projectUUID, opts)
	if err != nil {
		t.Fatalf("GroupFindingsByValue: %v", err)
	}
	if deleted != 2 || grouped != 1 {
		t.Fatalf("expected 2 deleted / 1 grouped, got %d / %d", deleted, grouped)
	}

	s := &Finding{}
	if err := db.NewSelect().Model(s).Where("id = ?", survivor).Scan(ctx); err != nil {
		t.Fatalf("select survivor: %v", err)
	}
	// All three distinct service names must be unioned onto the survivor.
	if len(s.ExtractedResults) != 3 {
		t.Fatalf("expected survivor to carry 3 distinct values, got %d: %v", len(s.ExtractedResults), s.ExtractedResults)
	}
	wantVals := map[string]bool{
		"AWS API Gateway: pgnsgvwfw0":          false,
		"AWS Cognito (Hosted UI): portal-kios": false,
		"AWS Cognito (IdP): ap-southeast-1":    false,
	}
	for _, v := range s.ExtractedResults {
		if _, ok := wantVals[v]; !ok {
			t.Errorf("unexpected value on survivor: %q", v)
		}
		wantVals[v] = true
	}
	for v, seen := range wantVals {
		if !seen {
			t.Errorf("survivor missing value: %q", v)
		}
	}
	if len(s.MatchedAt) != 3 {
		t.Errorf("expected survivor to span 3 URLs, got %d: %v", len(s.MatchedAt), s.MatchedAt)
	}
	// Description keeps its original lead and gains a single rollup note.
	if !strings.HasPrefix(s.Description, "AWS API Gateway endpoint referenced") {
		t.Errorf("survivor lost its base description: %q", s.Description)
	}
	if c := strings.Count(s.Description, groupRollupMarker); c != 1 {
		t.Errorf("expected exactly one rollup marker, got %d: %q", c, s.Description)
	}
	if !strings.Contains(s.Description, "3 distinct value(s)") {
		t.Errorf("rollup note missing distinct-value count: %q", s.Description)
	}

	// Idempotency: a later pass that folds in one more occurrence must rewrite the
	// note in place (not stack a second marker) and grow the value union to 4.
	insertDescFinding(t, db, ctx, projectUUID, "baas-endpoint-fingerprint", "portal.x.com",
		"https://portal.x.com/d", `["AWS AppSync: graphql-xyz"]`, "AWS AppSync endpoint referenced")
	if _, _, err := repo.GroupFindingsByValue(ctx, projectUUID, opts); err != nil {
		t.Fatalf("GroupFindingsByValue (second pass): %v", err)
	}
	if err := db.NewSelect().Model(s).Where("id = ?", survivor).Scan(ctx); err != nil {
		t.Fatalf("re-select survivor: %v", err)
	}
	if len(s.ExtractedResults) != 4 {
		t.Errorf("expected 4 distinct values after second pass, got %d: %v", len(s.ExtractedResults), s.ExtractedResults)
	}
	if c := strings.Count(s.Description, groupRollupMarker); c != 1 {
		t.Errorf("rollup note stacked across passes (got %d markers): %q", c, s.Description)
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
