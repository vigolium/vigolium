package database

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/uptrace/bun"
)

type txCounter struct{ begins, updates atomic.Int64 }

func (c *txCounter) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context { return ctx }
func (c *txCounter) AfterQuery(_ context.Context, ev *bun.QueryEvent) {
	q := strings.ToUpper(strings.TrimSpace(ev.Query))
	switch {
	case strings.HasPrefix(q, "BEGIN"):
		c.begins.Add(1)
	case strings.HasPrefix(q, "UPDATE"):
		c.updates.Add(1)
	}
}

// A batch of adoptions runs in one transaction (ECON-10), and still applies
// each row's promote-only backfill.
func TestAdoptRecordsOneTransaction(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for _, u := range []string{"r1", "r2", "r3"} {
		if _, err := db.NewInsert().Model(&HTTPRecord{
			UUID: u, ProjectUUID: DefaultProjectUUID, Method: "GET", URL: "https://a.test/" + u,
			Hostname: "a.test", Scheme: "https", Port: 443, Path: "/" + u, Source: RecordKindFinding,
		}).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	counter := &txCounter{}
	hooked := NewRepository(&DB{DB: db.WithQueryHook(counter), driver: db.driver})

	hooked.AdoptRecords(ctx, []RecordAdoption{
		{UUID: "r1", Lineage: RecordLineage{ParentUUID: "p1"}, Source: "probe"},
		{UUID: "r2", Lineage: RecordLineage{Target: "https://a.test/"}, Source: "probe"},
		{UUID: "r3", Source: "probe"},
	})
	if got := counter.begins.Load(); got != 1 {
		t.Fatalf("transactions = %d, want 1", got)
	}
	if got := counter.updates.Load(); got != 3 {
		t.Fatalf("updates = %d, want 3", got)
	}
	var rec HTTPRecord
	if err := db.NewSelect().Model(&rec).Where("uuid = ?", "r1").Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if rec.ParentUUID != "p1" || rec.Source != "probe" {
		t.Fatalf("adoption not applied: parent=%q source=%q", rec.ParentUUID, rec.Source)
	}
}
