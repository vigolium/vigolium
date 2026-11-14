package database

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// TestRiskPrioritizedDBInputSource_SkipsFindingEvidence: the
// payload-bearing request a finding stored as its evidence (source finding /
// candidate / observation, or the legacy known-issue "spa") is not served to
// the next assessment as input, and the round's count excludes it too.
func TestRiskPrioritizedDBInputSource_SkipsFindingEvidence(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	host := "evidence.example.com"
	inserted := insertTestRecordsWithHost(t, repo, host, 6)
	evidence := map[string]string{inserted[1]: RecordKindFinding, inserted[3]: RecordKindCandidate, inserted[5]: legacyKISEvidenceSource}
	for uuid, src := range evidence {
		if _, err := db.ExecContext(ctx, "UPDATE http_records SET source = ? WHERE uuid = ?", src, uuid); err != nil {
			t.Fatal(err)
		}
	}

	before, err := repo.CountRecordsAfterCursor(ctx, DefaultProjectUUID, time.Time{}, "", HostTarget{Hostname: host})
	if err != nil || before != 3 {
		t.Fatalf("count = %d (%v), want 3 scannable records", before, err)
	}

	source := NewRiskPrioritizedDBInputSource(db, repo, scanUUID).WithHostScopes([]HostTarget{{Hostname: host}})
	var got []string
	for {
		item, err := source.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Next(): %v", err)
		}
		got = append(got, item.RecordUUID)
		item.Complete()
	}
	if len(got) != 3 {
		t.Fatalf("served %d records, want 3", len(got))
	}
	for _, uuid := range got {
		if _, isEvidence := evidence[uuid]; isEvidence {
			t.Fatalf("served finding evidence %s as input", uuid)
		}
	}
	if source.Count() != 3 {
		t.Fatalf("Count() = %d, want 3", source.Count())
	}
}
