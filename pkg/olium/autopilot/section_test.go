package autopilot

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"

	"github.com/vigolium/vigolium/pkg/database"
)

func newSectionTestRepo(t *testing.T) *database.Repository {
	t.Helper()
	sqldb, err := sql.Open(sqliteshim.ShimName, ":memory:?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqldb.SetMaxOpenConns(1)
	sqldb.SetMaxIdleConns(1)
	db := database.NewDBFromBun(bun.NewDB(sqldb, sqlitedialect.New()), "sqlite")
	if err := db.CreateSchema(context.Background()); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return database.NewRepository(db)
}

// recordingSectionRecorder captures the lifecycle calls so BeginSection /
// EndSection wiring can be asserted without a transcript file.
type recordingSectionRecorder struct {
	starts       []string
	ends         []string
	interrupts   []string
	lastRotation string
}

func (r *recordingSectionRecorder) SectionStart(id string, seq int, kind, task string) {
	r.starts = append(r.starts, id)
}
func (r *recordingSectionRecorder) SectionEnd(id, status, rotationReason, summary string, durationMs int64) {
	r.ends = append(r.ends, id)
	r.lastRotation = rotationReason
}
func (r *recordingSectionRecorder) SectionInterrupted(id string) {
	r.interrupts = append(r.interrupts, id)
}

func TestShouldRotateTriggers(t *testing.T) {
	// Turn cap.
	c := NewSectionController("", nil, "", "", nil, nil, 40, 12, 0)
	if rotate, reason := c.ShouldRotate(40, 0, true); !rotate || reason != rotationReasonTurnCap {
		t.Errorf("turn cap: rotate=%v reason=%q", rotate, reason)
	}

	// Token soft cap.
	c = NewSectionController("", nil, "", "", nil, nil, 40, 12, 1000)
	if rotate, reason := c.ShouldRotate(5, 1000, true); !rotate || reason != rotationReasonTokenCap {
		t.Errorf("token cap: rotate=%v reason=%q", rotate, reason)
	}
	// Below the token cap and making progress: no rotation.
	c = NewSectionController("", nil, "", "", nil, nil, 40, 12, 1000)
	if rotate, _ := c.ShouldRotate(5, 500, true); rotate {
		t.Error("should not rotate below all thresholds")
	}

	// Stall: StallTurns consecutive unproductive turns.
	c = NewSectionController("", nil, "", "", nil, nil, 40, 3, 0)
	var rotate bool
	var reason string
	for i := 0; i < 3; i++ {
		rotate, reason = c.ShouldRotate(i+1, 0, false)
	}
	if !rotate || reason != rotationReasonStall {
		t.Errorf("stall: rotate=%v reason=%q", rotate, reason)
	}

	// Progress resets the stall counter.
	c = NewSectionController("", nil, "", "", nil, nil, 40, 3, 0)
	c.ShouldRotate(1, 0, false) // stall=1
	c.ShouldRotate(2, 0, false) // stall=2
	c.ShouldRotate(3, 0, true)  // progress -> stall=0
	if rotate, _ := c.ShouldRotate(4, 0, false); rotate {
		t.Error("stall counter should have reset on a progressing turn")
	}
}

func TestBeginEndSectionPersistsAndRecords(t *testing.T) {
	repo := newSectionTestRepo(t)
	ctx := context.Background()
	scanUUID := uuid.NewString()
	proj := uuid.NewString()
	rec := &recordingSectionRecorder{}

	c := NewSectionController("", repo, proj, scanUUID, nil, rec, 40, 12, 0)
	st := c.BeginSection(ctx, "map the surface", "operator")
	if st.Seq != 1 {
		t.Errorf("first section seq = %d, want 1", st.Seq)
	}
	if c.CurrentSectionUUID() != st.UUID {
		t.Error("CurrentSectionUUID mismatch")
	}
	if len(rec.starts) != 1 {
		t.Errorf("section_start emits = %d, want 1", len(rec.starts))
	}

	c.EndSection(ctx, database.SectionStatusCompleted, rotationReasonTurnCap, "found login form", 40, 1200, 600)
	if len(rec.ends) != 1 || rec.lastRotation != rotationReasonTurnCap {
		t.Errorf("section_end: ends=%d rotation=%q", len(rec.ends), rec.lastRotation)
	}

	// Second section continues seq numbering.
	st2 := c.BeginSection(ctx, "probe idor", "operator")
	if st2.Seq != 2 {
		t.Errorf("second section seq = %d, want 2", st2.Seq)
	}

	rows, err := repo.ListAgentSections(ctx, scanUUID)
	if err != nil {
		t.Fatalf("ListAgentSections: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("persisted sections = %d, want 2", len(rows))
	}
	if rows[0].Status != database.SectionStatusCompleted || rows[0].ClosingSummary != "found login form" {
		t.Errorf("section 1 not finalized: %+v", rows[0])
	}
	if rows[0].TurnCount != 40 || rows[0].InputTokens != 1200 {
		t.Errorf("section 1 counts wrong: turns=%d in=%d", rows[0].TurnCount, rows[0].InputTokens)
	}
}

func TestBuildReconstructedBriefContent(t *testing.T) {
	repo := newSectionTestRepo(t)
	ctx := context.Background()
	scanUUID := uuid.NewString()
	proj := uuid.NewString()

	// Seed a scratchpad with a plan + a note.
	scratch := NewScratchpadContext("") // in-memory only
	scratch.plan = []PlanItem{{ID: "auth", Task: "test the JWT verifier", Status: planInProgress}}
	scratch.Remember("auth-scheme", "target uses HS256 JWT in Authorization header", nil)

	// Seed a couple of candidates so the ledger shows up.
	if _, err := repo.SaveCandidate(ctx, &database.AgentFindingCandidate{
		UUID: uuid.NewString(), AgenticScanUUID: scanUUID, ProjectUUID: proj,
		Title: "IDOR on /api/orders", Severity: "high", Class: "idor",
		Status: database.CandidateStatusProposed, DedupHash: "h1",
	}); err != nil {
		t.Fatalf("SaveCandidate: %v", err)
	}

	c := NewSectionController("", repo, proj, scanUUID, scratch, nil, 40, 12, 0)
	// Store a prior closing summary so it surfaces (seq-1 = 0 won't; begin two).
	c.BeginSection(ctx, "first task", "operator")
	c.StoreClosingSummary("established that auth is JWT; orders endpoint looks vulnerable", 1)
	c.EndSection(ctx, database.SectionStatusCompleted, rotationReasonTurnCap, "", 40, 0, 0)
	c.BeginSection(ctx, "verify the IDOR on /api/orders", "operator")

	brief := c.BuildReconstructedBrief("MISSION: audit test.example.com", "replayed GET /api/orders/123 -> 200")

	checks := []string{
		"MISSION: audit test.example.com",
		"## Working memory",
		"test the JWT verifier",      // plan item
		"Candidate ledger",           // ledger header
		"IDOR on /api/orders",        // candidate entry
		"## Current task",            // current task section
		"verify the IDOR",            // current task text
		"Recent actions",             // recent-actions window
		"replayed GET /api/orders",   // recent action text
		"Previous section summary",   // prior closing summary section
		"established that auth is J", // prior closing summary text
	}
	for _, want := range checks {
		if !strings.Contains(brief, want) {
			t.Errorf("reconstructed brief missing %q\n---\n%s", want, brief)
		}
	}
}
