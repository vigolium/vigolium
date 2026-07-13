package database

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// Durable-autopilot state persistence. These methods back the bounded-section
// controller (agent_sections) and the verify-before-promote pipeline
// (agent_finding_candidates). They are only exercised when
// agent.olium.autopilot_mode != legacy; legacy runs never call them, so the
// tables stay empty and the current behavior is unchanged.

// Candidate lifecycle status values.
const (
	CandidateStatusProposed      = "proposed"
	CandidateStatusVerifying     = "verifying"
	CandidateStatusConfirmed     = "confirmed"
	CandidateStatusRejected      = "rejected"
	CandidateStatusNeedsEvidence = "needs_evidence"
)

// Section lifecycle status values.
const (
	SectionStatusRunning     = "running"
	SectionStatusCompleted   = "completed"
	SectionStatusInterrupted = "interrupted"
)

// SaveAgentSection inserts a new bounded-section row. The uuid carries the
// section identity; a duplicate uuid is a no-op (idempotent on resume).
func (r *Repository) SaveAgentSection(ctx context.Context, section *AgentSection) error {
	if section == nil {
		return fmt.Errorf("SaveAgentSection: nil section")
	}
	if section.CreatedAt.IsZero() {
		section.CreatedAt = time.Now().UTC()
	}
	_, err := r.db.NewInsert().Model(section).
		On("CONFLICT (uuid) DO NOTHING").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("SaveAgentSection: %w", err)
	}
	return nil
}

// UpdateAgentSection updates a section row identified by uuid. OmitZero lets the
// caller pass a partial struct (e.g. only status + closing_summary + ended_at)
// without clobbering columns set at BeginSection time.
func (r *Repository) UpdateAgentSection(ctx context.Context, section *AgentSection) error {
	if section == nil || section.UUID == "" {
		return fmt.Errorf("UpdateAgentSection: section uuid required")
	}
	_, err := r.db.NewUpdate().Model(section).
		OmitZero().
		Where("uuid = ?", section.UUID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("UpdateAgentSection: %w", err)
	}
	return nil
}

// ListAgentSections returns all sections for an agentic scan ordered by seq
// (execution order). Empty agenticScanUUID returns an empty slice.
func (r *Repository) ListAgentSections(ctx context.Context, agenticScanUUID string) ([]*AgentSection, error) {
	if agenticScanUUID == "" {
		return nil, nil
	}
	var sections []*AgentSection
	err := r.db.NewSelect().Model(&sections).
		Where("agentic_scan_uuid = ?", agenticScanUUID).
		OrderExpr("seq ASC, id ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("ListAgentSections: %w", err)
	}
	return sections, nil
}

// SaveCandidate inserts a proposed finding candidate, deduping on
// (agentic_scan_uuid, dedup_hash) via ON CONFLICT DO NOTHING so a looping model
// that re-proposes the same bug produces exactly one row. Returns inserted=true
// only when a new row was written (false on a dedup hit), so callers can keep an
// accurate proposed-count.
func (r *Repository) SaveCandidate(ctx context.Context, cand *AgentFindingCandidate) (bool, error) {
	if cand == nil {
		return false, fmt.Errorf("SaveCandidate: nil candidate")
	}
	if cand.Status == "" {
		cand.Status = CandidateStatusProposed
	}
	if cand.CreatedAt.IsZero() {
		cand.CreatedAt = time.Now().UTC()
	}
	res, err := r.db.NewInsert().Model(cand).
		On("CONFLICT (agentic_scan_uuid, dedup_hash) DO NOTHING").
		Exec(ctx)
	if err != nil {
		return false, fmt.Errorf("SaveCandidate: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListCandidates returns candidates for an agentic scan, optionally filtered to
// the given statuses (empty statuses = all). Ordered by id so the verifier
// processes them in proposal order.
func (r *Repository) ListCandidates(ctx context.Context, agenticScanUUID string, statuses ...string) ([]*AgentFindingCandidate, error) {
	if agenticScanUUID == "" {
		return nil, nil
	}
	var cands []*AgentFindingCandidate
	q := r.db.NewSelect().Model(&cands).
		Where("agentic_scan_uuid = ?", agenticScanUUID)
	if len(statuses) > 0 {
		q = q.Where("status IN (?)", bun.In(statuses))
	}
	if err := q.OrderExpr("id ASC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("ListCandidates: %w", err)
	}
	return cands, nil
}

// UpdateCandidateStatus records a verifier verdict on a candidate by uuid,
// setting status, verdict_reason, promoted_finding_id (when > 0), and stamping
// verified_at. Used by the fresh-context verifier to mark confirmed / rejected /
// needs_evidence.
func (r *Repository) UpdateCandidateStatus(ctx context.Context, uuid, status, verdictReason string, promotedFindingID int64) error {
	if uuid == "" {
		return fmt.Errorf("UpdateCandidateStatus: uuid required")
	}
	q := r.db.NewUpdate().Model((*AgentFindingCandidate)(nil)).
		Set("status = ?", status).
		Set("verdict_reason = ?", verdictReason).
		Set("verified_at = ?", time.Now().UTC()).
		Where("uuid = ?", uuid)
	if promotedFindingID > 0 {
		q = q.Set("promoted_finding_id = ?", promotedFindingID)
	}
	if _, err := q.Exec(ctx); err != nil {
		return fmt.Errorf("UpdateCandidateStatus: %w", err)
	}
	return nil
}
