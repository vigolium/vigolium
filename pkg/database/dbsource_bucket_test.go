package database

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

// The bucket page query is served in order by idx_records_project_risk_order:
// no TEMP B-TREE sort (ECON-10). The old single risk_score keyset re-sorted the
// whole equal-score block on every page.
func TestRiskBucketPageQueryUsesIndexOrder(t *testing.T) {
	db := newTestDB(t)
	s := NewRiskPrioritizedDBInputSource(db, NewRepository(db), "scan-x")
	s.projectUUID = DefaultProjectUUID
	s.boundAt, s.boundID = time.Now(), "zzzz"
	s.bucketRisk, s.bucketSurface, s.bucketSet = 5, 3, true
	s.keyAt, s.keyID, s.started = time.Now().Add(-time.Hour), "a", true

	query := s.bucketPageQueryLocked().String()
	rows, err := db.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+query)
	if err != nil {
		t.Fatalf("explain: %v\n%s", err, query)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail sql.NullString
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail.String)
	}
	joined := strings.Join(plan, "\n")
	if strings.Contains(joined, "TEMP B-TREE") {
		t.Fatalf("bucket page query sorts in a temp b-tree:\n%s\n%s", joined, query)
	}
	if !strings.Contains(joined, "idx_records_project_risk_order") {
		t.Fatalf("bucket page query does not use idx_records_project_risk_order:\n%s", joined)
	}
}

// The bucket walk serves records risk DESC, surface DESC, then chronological.
func TestRiskBucketOrder(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	if err := repo.CreateScan(ctx, &Scan{UUID: "scan-b", ProjectUUID: DefaultProjectUUID, Status: "running"}); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	type rec struct {
		uuid          string
		risk, surface int
		age           int
	}
	for _, r := range []rec{
		{"u1", 0, 0, 0}, {"u2", 9, 1, 1}, {"u3", 9, 7, 2}, {"u4", 0, 50, 3}, {"u5", 9, 7, 4}, {"u6", 3, 0, 5},
	} {
		_, err := db.NewInsert().Model(&HTTPRecord{
			UUID: r.uuid, ProjectUUID: DefaultProjectUUID, Method: "GET", URL: "https://o.test/" + r.uuid,
			Hostname: "o.test", Scheme: "https", Port: 443, Path: "/" + r.uuid,
			RiskScore: r.risk, SurfaceScore: r.surface, CreatedAt: base.Add(time.Duration(r.age) * time.Second),
			RawRequest: []byte("GET /" + r.uuid + " HTTP/1.1\r\nHost: o.test\r\n\r\n"),
		}).Exec(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// Store created_at in the text form the write paths use (and the
		// keyset compares against), not bun's time encoding.
		if _, err := db.ExecContext(ctx, "UPDATE http_records SET created_at = ? WHERE uuid = ?",
			dbTimestampString(db.Driver(), base.Add(time.Duration(r.age)*time.Second)), r.uuid); err != nil {
			t.Fatal(err)
		}
	}
	src := NewRiskPrioritizedDBInputSource(db, repo, "scan-b")
	var got []string
	for i := 0; i < 20; i++ {
		item, err := src.Next(ctx)
		if err != nil {
			break
		}
		got = append(got, item.RecordUUID)
		item.Complete()
	}
	want := []string{"u3", "u5", "u2", "u6", "u4", "u1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v, want %v", got, want)
	}
}
