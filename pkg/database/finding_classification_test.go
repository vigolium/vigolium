package database

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/types/severity"
)

// A Tentative finding filed below the module's claim keeps the claim on the
// row (claimed_severity), and every finding carries its reported class
// (vuln_class); a re-detection at the module's own severity clears the claim.
func TestFindingStoresClaimedSeverityAndVulnClass(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	ev := ipEvent("delayed 5012ms")
	ev.Info.Severity = severity.Suspect
	ev.Info.Confidence = severity.Tentative
	ev.Metadata = map[string]any{"claimed_severity": "high"}
	if err := repo.SaveFinding(ctx, ev, nil, "S1", DefaultProjectUUID); err != nil {
		t.Fatal(err)
	}
	var row Finding
	if err := db.NewSelect().Model(&row).Limit(1).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if row.Severity != "suspect" || row.ClaimedSeverity != "high" {
		t.Fatalf("severity/claimed = %q/%q, want suspect/high", row.Severity, row.ClaimedSeverity)
	}
	if row.VulnClass != "cmdi" {
		t.Fatalf("vuln_class = %q, want cmdi (command-injection-timing's declared class)", row.VulnClass)
	}

	ev2 := ipEvent("delayed 5023ms")
	ev2.Info.Severity = severity.High
	ev2.Info.Confidence = severity.Firm
	if err := repo.SaveFinding(ctx, ev2, nil, "S2", DefaultProjectUUID); err != nil {
		t.Fatal(err)
	}
	var rows []Finding
	if err := db.NewSelect().Model(&rows).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].Severity != "high" || rows[0].ClaimedSeverity != "" {
		t.Fatalf("after a re-detection at the module's own severity: %q/%q, want high and no claim", rows[0].Severity, rows[0].ClaimedSeverity)
	}
}

func TestClaimedSeverityFromMetadata(t *testing.T) {
	for _, tc := range []struct {
		meta   map[string]any
		stored string
		want   string
	}{
		{nil, "suspect", ""},
		{map[string]any{"claimed_severity": "High"}, "suspect", "high"},
		{map[string]any{"claimed_severity": "suspect"}, "suspect", ""},
		{map[string]any{"claimed_severity": 3}, "suspect", ""},
	} {
		if got := claimedSeverityFromMetadata(tc.meta, tc.stored); got != tc.want {
			t.Errorf("claimedSeverityFromMetadata(%v, %q) = %q, want %q", tc.meta, tc.stored, got, tc.want)
		}
	}
}
