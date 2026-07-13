package autopilot

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/database"
)

// A durable-autopilot run is split into bounded "sections". Each section is one
// engine.Reset() + Run(reconstructedBrief) cycle: the operator works with a
// fresh, bounded conversation window whose prefix is rebuilt from the durable
// scratchpad + the previous section's closing summary + a compact candidate
// ledger, instead of an ever-growing history that eventually hits the provider
// context ceiling. The SectionController owns the rotation decision (turn cap /
// token soft cap / stall) and the persistence of section state. Legacy runs
// never construct one.

// Default rotation knobs.
const (
	DefaultMaxTurnsPerSection = 40
	DefaultStallTurns         = 12
)

// Rotation-reason strings surfaced on section rows and section_end events.
const (
	rotationReasonTurnCap  = "turn-cap"
	rotationReasonTokenCap = "token-soft-cap"
	rotationReasonStall    = "stall"
)

// SectionRecorder receives section lifecycle events for the transcript. It is
// additive to the Pi schema (viewers ignore unknown types). Nil-safe: the
// controller guards every call, so a run without a recorder still rotates.
// *sessionlog.Recorder implements this (see Stage E).
type SectionRecorder interface {
	SectionStart(id string, seq int, kind, task string)
	SectionEnd(id, status, rotationReason, summary string, durationMs int64)
	SectionInterrupted(id string)
}

// sectionState is the in-flight section the controller is tracking.
type sectionState struct {
	UUID      string
	Seq       int
	Kind      string
	Task      string
	StartedAt time.Time
}

// SectionController drives bounded operator sections with context rotation.
// Repo is optional — when nil, sections are in-memory only (rotation still
// works; nothing is persisted). Not safe for concurrent use: the operator loop
// drives it from a single goroutine (sections are strictly serial).
type SectionController struct {
	SessionDir      string
	Repo            *database.Repository
	ProjectUUID     string
	AgenticScanUUID string
	Scratch         *ScratchpadContext
	Recorder        SectionRecorder

	// Knobs (constructor fills defaults for the zero value).
	MaxTurnsPerSection  int
	StallTurns          int
	ContextTokenSoftCap int64 // 0 = disabled; caller passes a fraction of the model ceiling

	seq          int
	current      *sectionState
	stallCounter int
}

// NewSectionController builds a controller with defaults applied for any
// zero-valued knob. maxTurns / stallTurns <= 0 fall back to the package
// defaults; softCap <= 0 disables the token trigger.
func NewSectionController(sessionDir string, repo *database.Repository, projectUUID, agenticScanUUID string, scratch *ScratchpadContext, rec SectionRecorder, maxTurns, stallTurns int, softCap int64) *SectionController {
	if maxTurns <= 0 {
		maxTurns = DefaultMaxTurnsPerSection
	}
	if stallTurns <= 0 {
		stallTurns = DefaultStallTurns
	}
	if softCap < 0 {
		softCap = 0
	}
	return &SectionController{
		SessionDir:          sessionDir,
		Repo:                repo,
		ProjectUUID:         projectUUID,
		AgenticScanUUID:     agenticScanUUID,
		Scratch:             scratch,
		Recorder:            rec,
		MaxTurnsPerSection:  maxTurns,
		StallTurns:          stallTurns,
		ContextTokenSoftCap: softCap,
	}
}

// CurrentSectionUUID returns the uuid of the in-flight section, or "" when no
// section is open. Used to point the propose_candidate tool at the current
// section without racing the controller.
func (c *SectionController) CurrentSectionUUID() string {
	if c == nil || c.current == nil {
		return ""
	}
	return c.current.UUID
}

// CurrentSeq returns the seq of the in-flight section, or 0 when none is open.
func (c *SectionController) CurrentSeq() int {
	if c == nil || c.current == nil {
		return 0
	}
	return c.current.Seq
}

// BeginSection opens a new section: mints a uuid, resets the stall counter,
// assigns the next seq (continuing across a resume when prior sections exist in
// the DB), persists a running row when a Repo is set, and emits section_start.
func (c *SectionController) BeginSection(ctx context.Context, task, kind string) *sectionState {
	// Continue seq numbering across a resume: on the first section of this
	// process, seed from the max seq already persisted for this agentic scan.
	if c.seq == 0 && c.Repo != nil && c.AgenticScanUUID != "" {
		if existing, err := c.Repo.ListAgentSections(ctx, c.AgenticScanUUID); err == nil {
			for _, s := range existing {
				if s.Seq > c.seq {
					c.seq = s.Seq
				}
			}
		}
	}
	c.seq++
	c.stallCounter = 0
	st := &sectionState{
		UUID:      uuid.NewString(),
		Seq:       c.seq,
		Kind:      kind,
		Task:      task,
		StartedAt: time.Now().UTC(),
	}
	c.current = st

	if c.Repo != nil && c.AgenticScanUUID != "" {
		row := &database.AgentSection{
			UUID:            st.UUID,
			AgenticScanUUID: c.AgenticScanUUID,
			ProjectUUID:     c.ProjectUUID,
			Seq:             st.Seq,
			Kind:            kind,
			Status:          database.SectionStatusRunning,
			Task:            task,
			StartedAt:       st.StartedAt,
		}
		if err := c.Repo.SaveAgentSection(ctx, row); err != nil {
			// Non-fatal: rotation still works from in-memory state.
			_ = err
		}
	}

	if c.Recorder != nil {
		c.Recorder.SectionStart(st.UUID, st.Seq, kind, task)
	}
	return st
}

// ShouldRotate decides whether the current section should close and rotate. It
// also maintains the stall counter: a turn that made progress (a new record /
// finding / candidate or a plan mutation) resets it, an unproductive turn
// increments it. Triggers, in priority order:
//   - turns this section >= MaxTurnsPerSection
//   - ContextTokenSoftCap > 0 && tokens this section >= cap
//   - stall counter >= StallTurns
//
// Call once per completed turn (at EventTurnDone).
func (c *SectionController) ShouldRotate(turnsThisSection int, tokensThisSection int64, progressed bool) (bool, string) {
	if progressed {
		c.stallCounter = 0
	} else {
		c.stallCounter++
	}
	if c.MaxTurnsPerSection > 0 && turnsThisSection >= c.MaxTurnsPerSection {
		return true, rotationReasonTurnCap
	}
	if c.ContextTokenSoftCap > 0 && tokensThisSection >= c.ContextTokenSoftCap {
		return true, rotationReasonTokenCap
	}
	if c.StallTurns > 0 && c.stallCounter >= c.StallTurns {
		return true, rotationReasonStall
	}
	return false, ""
}

// EndSection closes the current section: updates the row (status, rotation
// reason, closing summary, turn/token counts, ended_at) and emits section_end.
// Safe to call with no open section (no-op).
func (c *SectionController) EndSection(ctx context.Context, status, rotationReason, closingSummary string, turnCount int, in, out int64) {
	st := c.current
	if st == nil {
		return
	}
	endedAt := time.Now().UTC()

	if c.Repo != nil && c.AgenticScanUUID != "" {
		row := &database.AgentSection{
			UUID:           st.UUID,
			Status:         status,
			RotationReason: rotationReason,
			ClosingSummary: closingSummary,
			TurnCount:      turnCount,
			InputTokens:    in,
			OutputTokens:   out,
			EndedAt:        endedAt,
		}
		if err := c.Repo.UpdateAgentSection(ctx, row); err != nil {
			_ = err // non-fatal
		}
	}

	if c.Recorder != nil {
		durMs := endedAt.Sub(st.StartedAt).Milliseconds()
		if status == database.SectionStatusInterrupted {
			c.Recorder.SectionInterrupted(st.UUID)
		} else {
			c.Recorder.SectionEnd(st.UUID, status, rotationReason, closingSummary, durMs)
		}
	}
	c.current = nil
}

// StoreClosingSummary pins a section's closing summary into the durable
// scratchpad under the key section-<seq>-closing, so it survives context loss
// and can be surfaced in the next section's reconstructed brief. No-op when no
// scratchpad is wired.
func (c *SectionController) StoreClosingSummary(summary string, seq int) {
	if c.Scratch == nil || strings.TrimSpace(summary) == "" {
		return
	}
	c.Scratch.Remember(fmt.Sprintf("section-%d-closing", seq), summary, []string{"section-summary"})
}

// BuildReconstructedBrief assembles the user prompt that seeds a fresh section
// after eng.Reset(). It packs the durable state the operator must not lose:
// the mission, the working-memory render (plan + notes + stop criteria), the
// previous section's closing summary, a compact candidate ledger, the current
// task, a recent-actions window, and a pointer to the already-captured
// http_records. Best-effort DB reads (ledger, record count) degrade to an
// omitted section rather than failing.
func (c *SectionController) BuildReconstructedBrief(mission, recentActions string) string {
	var b strings.Builder

	if strings.TrimSpace(mission) != "" {
		b.WriteString(strings.TrimSpace(mission))
		b.WriteString("\n\n")
	}

	b.WriteString("This is a fresh operator section. Your earlier conversation history was rotated out to keep " +
		"context bounded, but nothing important is lost — everything you need is reconstructed below. " +
		"Re-read it, then continue from where the plan says you are.\n\n")

	if c.Scratch != nil {
		b.WriteString("## Working memory\n")
		b.WriteString(c.Scratch.Render())
		b.WriteString("\n")
	}

	// Previous section closing summary (the section just ended). c.seq is the
	// current section's seq once BeginSection has run; the prior one is seq-1.
	if c.Scratch != nil {
		if prev := c.Scratch.NoteByKey(fmt.Sprintf("section-%d-closing", c.seq-1)); prev != "" {
			b.WriteString("## Previous section summary\n")
			b.WriteString(prev)
			b.WriteString("\n\n")
		}
	}

	if ledger := c.candidateLedger(); ledger != "" {
		b.WriteString(ledger)
		b.WriteString("\n")
	}

	if c.current != nil && strings.TrimSpace(c.current.Task) != "" {
		b.WriteString("## Current task\n")
		b.WriteString(c.current.Task)
		b.WriteString("\n\n")
	}

	if strings.TrimSpace(recentActions) != "" {
		b.WriteString("## Recent actions (last steps of the previous section)\n")
		b.WriteString(strings.TrimSpace(recentActions))
		b.WriteString("\n\n")
	}

	if n := c.recordCount(); n > 0 {
		fmt.Fprintf(&b, "%d http_records already captured — use query_records to inspect them before sending new traffic.\n", n)
	}

	return b.String()
}

// candidateLedger renders a compact, bounded list of this run's candidates
// grouped by status, so a rotated operator can see what it has already proposed
// (and what the verifier has already ruled on) without re-proposing. Returns ""
// when no repo, no scan, or no candidates.
func (c *SectionController) candidateLedger() string {
	if c.Repo == nil || c.AgenticScanUUID == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cands, err := c.Repo.ListCandidates(ctx, c.AgenticScanUUID)
	if err != nil || len(cands) == 0 {
		return ""
	}
	const maxLedger = 30
	var b strings.Builder
	fmt.Fprintf(&b, "## Candidate ledger (%d proposed this run)\n", len(cands))
	b.WriteString("_Do not re-propose these. Confirmed/rejected verdicts are final._\n")
	shown := cands
	if len(shown) > maxLedger {
		shown = shown[:maxLedger]
	}
	for _, cd := range shown {
		fmt.Fprintf(&b, "- [%s] %s (%s/%s)", cd.Status, truncate(cd.Title, 70), cd.Severity, cd.Class)
		if cd.VerdictReason != "" {
			fmt.Fprintf(&b, " — %s", truncate(cd.VerdictReason, 80))
		}
		b.WriteString("\n")
	}
	if len(cands) > maxLedger {
		fmt.Fprintf(&b, "- … and %d more\n", len(cands)-maxLedger)
	}
	return b.String()
}

// recordCount returns the number of http_records visible to this run (project-
// scoped). Best-effort; a query error returns 0 so the brief just omits the
// pointer line.
func (c *SectionController) recordCount() int {
	if c.Repo == nil || c.ProjectUUID == "" {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	n, err := c.Repo.DB().NewSelect().
		Model((*database.HTTPRecord)(nil)).
		Where("project_uuid = ?", c.ProjectUUID).
		Count(ctx)
	if err != nil {
		return 0
	}
	return n
}
