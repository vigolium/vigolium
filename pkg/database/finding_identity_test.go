package database

import (
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func ipEvent(desc string) *output.ResultEvent {
	ev := makeFindingEvent("command-injection-timing", "/run?cmd=x", severity.High)
	ev.Info.Description = desc
	ev.InsertionPointType = "URL_PARAM"
	ev.FuzzingParameter = "cmd"
	ev.BaseURL = "https://t.example.com/run?cmd=ls"
	return ev
}

// TestRedetection_DifferentProseIsOneRow: the same location found
// again with a different measured delay updates one row, reopens `fixed`, and
// records who reopened it.
func TestRedetection_DifferentProseIsOneRow(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	if err := repo.SaveFinding(ctx, ipEvent("delayed 5012ms"), nil, "S1", DefaultProjectUUID); err != nil {
		t.Fatal(err)
	}
	var first Finding
	if err := db.NewSelect().Model(&first).Limit(1).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetFindingStatus(ctx, DefaultProjectUUID, first.ID, StatusFixed, "patched", "alice"); err != nil {
		t.Fatal(err)
	}
	ev2 := ipEvent("delayed 5023ms")
	ev2.Info.Severity = severity.Critical
	if err := repo.SaveFinding(ctx, ev2, nil, "S2", DefaultProjectUUID); err != nil {
		t.Fatal(err)
	}

	var rows []Finding
	if err := db.NewSelect().Model(&rows).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1 (re-detection must not fork the finding)", len(rows))
	}
	got := rows[0]
	if got.Status != StatusTriaged || got.StatusActor != StatusActorRescan {
		t.Errorf("status = %q by %q, want triaged by %q", got.Status, got.StatusActor, StatusActorRescan)
	}
	if got.Description != "delayed 5023ms" || got.Severity != "critical" || got.ScanUUID != "S2" {
		t.Errorf("latest fields not applied: desc=%q sev=%q scan=%q", got.Description, got.Severity, got.ScanUUID)
	}
	if got.LastSeenAt == nil {
		t.Error("last_seen_at not set")
	}
	events, err := repo.ListFindingStatusEvents(ctx, DefaultProjectUUID, got.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(events); n != 2 || events[1].Actor != StatusActorRescan || events[1].FromStatus != StatusFixed {
		t.Errorf("status events = %+v, want fixed→triaged by rescan last", events)
	}
}

// TestRekeyFindingIdentities_PreservesTriageAndHashes is the v6 migration
// fixture: two pre-v6 rows for one location (prose differed), the newer one
// marked false_positive. After the re-key there is one row carrying the
// verdict, and both old hashes still resolve.
func TestRekeyFindingIdentities_PreservesTriageAndHashes(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	insertV1 := func(desc, scan string, created time.Time) string {
		matched := "https://t.example.com/run?cmd=x"
		h := output.HashContentV1(output.RecordKindFinding, "command-injection-timing", desc, "high", matched)
		if _, err := db.ExecContext(ctx,
			`INSERT INTO findings (project_uuid, scan_uuid, module_id, module_name, finding_hash, severity, confidence,
				http_record_uuids, matched_at, url, description, request, insertion_point, created_at, found_at)
			 VALUES (?, ?, 'command-injection-timing', 'command-injection-timing', ?, 'high', 'firm', '[]', ?, ?, ?,
				'GET /run?cmd=x HTTP/1.1', '{"type":"URL_PARAM","name":"cmd"}', ?, ?)`,
			DefaultProjectUUID, scan, h, `["`+matched+`"]`, matched, desc, created, created); err != nil {
			t.Fatal(err)
		}
		var id int64
		if err := db.NewRaw("SELECT id FROM findings WHERE finding_hash = ?", h).Scan(ctx, &id); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx,
			"INSERT INTO finding_observations (project_uuid, finding_id, finding_hash, scan_uuid, observed_at) VALUES (?, ?, ?, ?, ?)",
			DefaultProjectUUID, id, h, scan, created); err != nil {
			t.Fatal(err)
		}
		return h
	}
	base := time.Now().Add(-time.Hour).UTC()
	h1 := insertV1("delayed 5012ms", "S1", base)
	h2 := insertV1("delayed 5023ms", "S2", base.Add(time.Minute))
	// A row with no insertion point keeps its v1 identity.
	h3 := output.HashContentV1(output.RecordKindFinding, "header-check", "missing hsts", "low", "https://t.example.com/")
	if _, err := db.ExecContext(ctx,
		`INSERT INTO findings (project_uuid, module_id, module_name, finding_hash, severity, http_record_uuids, matched_at)
		 VALUES (?, 'header-check', 'header-check', ?, 'low', '[]', '["https://t.example.com/"]')`, DefaultProjectUUID, h3); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdateFindingStatusScoped(ctx, DefaultProjectUUID, FindingStatusUpdate{
		Hashes: []string{h2}, Status: StatusFalsePositive, Note: "WAF delay", Actor: "bob",
	}); err != nil {
		t.Fatal(err)
	}

	stats, err := db.RekeyFindingIdentities(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Merged != 1 || stats.Rekeyed != 1 {
		t.Fatalf("stats = %+v, want 1 merged, 1 re-keyed", stats)
	}
	var rows []Finding
	if err := db.NewSelect().Model(&rows).Where("module_id = ?", "command-injection-timing").Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	f := rows[0]
	if f.Status != StatusFalsePositive || f.StatusActor != "bob" {
		t.Errorf("verdict = %q by %q, want false_positive by bob", f.Status, f.StatusActor)
	}
	if f.ScanUUID != "S2" {
		t.Errorf("scan_uuid = %q, want S2 (latest observer)", f.ScanUUID)
	}
	want := ipEvent("anything").ID()
	if f.FindingHash != want {
		t.Errorf("finding_hash = %s, want the v2 hash %s a re-detection computes", f.FindingHash, want)
	}
	for _, h := range []string{h1, h2, h1[:12]} {
		found, nf, err := repo.ResolveFindings(ctx, DefaultProjectUUID, nil, []string{h})
		if err != nil || len(nf) != 0 || len(found) != 1 || found[0].ID != f.ID {
			t.Errorf("old hash %s: found=%d notFound=%v err=%v", h, len(found), nf, err)
		}
	}
	if d, err := repo.DismissedFindingHashes(ctx, DefaultProjectUUID, []string{h1}); err != nil || !d[h1] {
		t.Errorf("old hash %s not seen as dismissed: %v %v", h1, d, err)
	}
	var keep int
	if err := db.NewRaw("SELECT COUNT(*) FROM findings WHERE finding_hash = ?", h3).Scan(ctx, &keep); err != nil || keep != 1 {
		t.Errorf("v1 row without insertion point was re-keyed (count=%d err=%v)", keep, err)
	}

	// Idempotent; and a re-detection now lands on the migrated row.
	if again, err := db.RekeyFindingIdentities(ctx, ""); err != nil || again != (RekeyStats{}) {
		t.Errorf("second pass = %+v, %v; want no-op", again, err)
	}
	if err := repo.SaveFinding(ctx, ipEvent("delayed 4999ms"), nil, "S3", DefaultProjectUUID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.NewRaw("SELECT COUNT(*) FROM findings WHERE module_id = 'command-injection-timing'").Scan(ctx, &n); err != nil || n != 1 {
		t.Errorf("after re-detection rows = %d (err %v), want 1", n, err)
	}
}
