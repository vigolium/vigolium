package database

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/recon"
)

// v4Columns are the host_observations columns schema v4 added.
var v4Columns = []string{"dns_mx", "dns_ns", "dns_txt", "dns_soa", "dns_caa", "fingerprint", "not_found"}

// TestSchemaV4_MigratesV3Store upgrades a v3 store holding a host observation:
// the new columns appear, the existing row keeps its answer, and the row can
// then take the new facts.
func TestSchemaV4_MigratesV3Store(t *testing.T) {
	ctx := context.Background()
	db, path := newFileDB(t, "v3.sqlite")
	mustExec(t, db, `INSERT INTO host_observations (project_uuid, scan_uuid, hostname, port, dns_a, complete)
		VALUES (?, 's1', 'old.example', 443, '["192.0.2.1"]', 1)`, DefaultProjectUUID)
	for _, c := range v4Columns {
		mustExec(t, db, "ALTER TABLE host_observations DROP COLUMN "+c)
	}
	mustExec(t, db, "UPDATE schema_meta SET version = 3, min_reader_version = 1 WHERE id = 1")
	_ = db.Close()

	w := openDBFile(t, path, false)
	defer func() { _ = w.Close() }()
	res, err := w.Migrate(ctx)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if res.FromVersion != 3 || res.ToVersion != currentSchemaVersion || res.MinReaderVersion != minReaderVersion {
		t.Fatalf("Migrate result = %+v, want 3 -> %d with min_reader %d", res, currentSchemaVersion, minReaderVersion)
	}
	cols, err := listAllColumns(ctx, w)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v4Columns {
		if !cols["host_observations"][c] {
			t.Errorf("host_observations.%s missing after migrate", c)
		}
	}

	repo := NewRepository(w)
	facts, err := repo.LookupHostObservation(ctx, DefaultProjectUUID, "s1", "old.example", 443)
	if err != nil || len(facts.A) != 1 {
		t.Fatalf("the v3 row kept its answer: %+v %v", facts, err)
	}

	// A later write in the same run adds facts without erasing the stored ones.
	err = repo.SaveHostObservations(ctx, DefaultProjectUUID, "s1", []HostObservationInput{{
		Hostname: "old.example", Port: 443, Complete: true,
		Fingerprint: &recon.TechStackReport{Title: "Old"},
		NotFound:    &NotFoundBaseline{Status: 200, SoftNotFound: true},
	}})
	if err != nil {
		t.Fatalf("SaveHostObservations: %v", err)
	}
	rows, _, err := repo.ListHostObservationsWithCount(ctx, HostObservationQuery{ProjectUUID: DefaultProjectUUID})
	if err != nil || len(rows) != 1 {
		t.Fatalf("list: %d rows, %v", len(rows), err)
	}
	got := rows[0]
	if len(got.DNSA) != 1 || got.Fingerprint == nil || got.Fingerprint.Title != "Old" || got.NotFound == nil || !got.NotFound.SoftNotFound {
		t.Errorf("merged row = %+v", got)
	}
}
