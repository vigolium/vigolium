package database

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/recon"
)

// TestSchemaV5_MigratesV4Store upgrades a v4 store holding a host observation:
// the favicon column appears, the existing row keeps its answer, and a later
// write in the same run adds the icon without erasing what was stored. The icon
// then reads back as a host fact (the export's `favicon` key) and through
// `hosts --has favicon`.
func TestSchemaV5_MigratesV4Store(t *testing.T) {
	ctx := context.Background()
	db, path := newFileDB(t, "v4.sqlite")
	mustExec(t, db, `INSERT INTO host_observations (project_uuid, scan_uuid, hostname, port, dns_a, complete)
		VALUES (?, 's1', 'old.example', 443, '["192.0.2.1"]', 1)`, DefaultProjectUUID)
	mustExec(t, db, "ALTER TABLE host_observations DROP COLUMN favicon")
	mustExec(t, db, "UPDATE schema_meta SET version = 4, min_reader_version = 1 WHERE id = 1")
	_ = db.Close()

	w := openDBFile(t, path, false)
	defer func() { _ = w.Close() }()
	res, err := w.Migrate(ctx)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if res.FromVersion != 4 || res.ToVersion != currentSchemaVersion || res.MinReaderVersion != minReaderVersion {
		t.Fatalf("Migrate result = %+v, want 4 -> %d with min_reader %d", res, currentSchemaVersion, minReaderVersion)
	}
	cols, err := listAllColumns(ctx, w)
	if err != nil {
		t.Fatal(err)
	}
	if !cols["host_observations"]["favicon"] {
		t.Fatal("host_observations.favicon missing after migrate")
	}

	repo := NewRepository(w)
	icon := &recon.FaviconInfo{URL: "https://old.example/favicon.ico", MMH3: -12345, MD5: "abc"}
	err = repo.SaveHostObservations(ctx, DefaultProjectUUID, "s1", []HostObservationInput{{
		Hostname: "old.example", Port: 443, Complete: true, HostFacts: HostFacts{Favicon: icon},
	}})
	if err != nil {
		t.Fatalf("SaveHostObservations: %v", err)
	}
	facts, err := repo.LookupHostObservation(ctx, DefaultProjectUUID, "s1", "old.example", 443)
	if err != nil || len(facts.A) != 1 || facts.Favicon == nil || facts.Favicon.MMH3 != -12345 {
		t.Fatalf("facts = %+v, %v; want the stored A record and the icon", facts, err)
	}
	if m := facts.AsMap(); m["favicon"] == nil {
		t.Errorf("AsMap() = %v, want a favicon key", m)
	}

	rows, _, err := repo.ListHostObservationsWithCount(ctx, HostObservationQuery{ProjectUUID: DefaultProjectUUID, Has: "favicon"})
	if err != nil || len(rows) != 1 || rows[0].Favicon == nil || rows[0].Favicon.URL != icon.URL {
		t.Fatalf("--has favicon: %d rows, %v", len(rows), err)
	}
}
