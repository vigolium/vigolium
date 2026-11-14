package database

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// TestSchemaMigrate_RelabelsLegacyKISEvidence: known-issue-scan evidence stored
// under the old "spa" source is relabelled RecordSourceFinding by the next
// schema migration, so evidence filters recognise it.
func TestSchemaMigrate_RelabelsLegacyKISEvidence(t *testing.T) {
	ctx := context.Background()
	db, path := newFileDB(t, "legacy-spa.sqlite")
	repo := NewRepository(db)
	rr, err := httpmsg.GetRawRequestFromURL("https://app.test/nuclei-evidence")
	if err != nil {
		t.Fatal(err)
	}
	uuid, err := repo.SaveRecord(ctx, rr, legacyKISEvidenceSource, DefaultProjectUUID)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, "UPDATE schema_meta SET version = ? WHERE id = 1", currentSchemaVersion-1)
	_ = db.Close()

	w := openDBFile(t, path, false)
	defer func() { _ = w.Close() }()
	if _, err := w.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	var source string
	if err := w.NewRaw("SELECT source FROM http_records WHERE uuid = ?", uuid).Scan(ctx, &source); err != nil {
		t.Fatal(err)
	}
	if source != RecordSourceFinding {
		t.Fatalf("source = %q, want %q", source, RecordSourceFinding)
	}
}
