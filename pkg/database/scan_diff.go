package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/uptrace/bun"
)

// Scan diffs and "new since" reads over finding_observations.
//
// findings.scan_uuid only names the LAST scan that saw a finding (a
// re-detection overwrites it), so "what did scan B find that scan A did not"
// cannot be answered from the findings table. finding_observations records
// every (finding, scan) pair; everything here reads that.

// Diff classes, one per finding in a scan diff.
const (
	// DiffNew: observed by the head scan, not by the base scan.
	DiffNew = "new"
	// DiffUnchanged: observed by both.
	DiffUnchanged = "unchanged"
	// DiffFixed: observed by the base scan and not by a head scan that covered
	// at least what the base did, to completion (Comparable).
	DiffFixed = "fixed"
	// DiffNotReobserved: observed by the base scan and not by a head scan that
	// cannot vouch for its absence (not Comparable). Not evidence of a fix.
	DiffNotReobserved = "not_reobserved"
)

// DiffChanges lists the classes in report order.
var DiffChanges = []string{DiffNew, DiffFixed, DiffNotReobserved, DiffUnchanged}

// Reasons a head scan is not comparable to its base, so absence from it is
// reported as not_reobserved rather than fixed.
const (
	ComparabilityHeadNotFinished       = "head_not_finished"         // head is still running, paused, failed or cancelled
	ComparabilityHeadPartial           = "head_partial"              // head finished with completeness partial
	ComparabilityHeadCompletenessUnset = "head_completeness_unknown" // head row carries no completeness verdict
	ComparabilityTargetsUnknown        = "targets_unknown"           // a scan row has no target list to compare
	ComparabilityTargetsNotCovered     = "head_targets_not_superset" // head did not cover every base target
	ComparabilityPhasesUnknown         = "phases_unknown"            // a scan row has no phase outcomes to compare
	ComparabilityPhasesNotCovered      = "head_phases_not_superset"  // a phase that ran in base did not complete in head
)

// Diff history labels.
const (
	DiffHistoryComplete = "complete"
	// DiffHistoryPartial: a scan in the diff started before the store recorded
	// every observation (schema_meta.observation_history_since), so a finding
	// that scan re-observed may be missing from its set.
	DiffHistoryPartial = "partial"
)

// ErrScanNotFound is returned when a scan reference matches no scan in scope.
var ErrScanNotFound = errors.New("scan not found")

// ScanDiffOptions selects the two scans and what to include.
type ScanDiffOptions struct {
	// ProjectUUID scopes both scans and every finding; "" = scoping off.
	ProjectUUID string
	// Base is scan a (the earlier run), Head is scan b (the later run).
	Base, Head *Scan
	// IncludeDismissed keeps false_positive/accepted_risk findings.
	IncludeDismissed bool
}

// ScanDiffEntry is one finding in a diff, as it stands now.
type ScanDiffEntry struct {
	Finding *Finding
	Change  string
	// FirstSeenScan is the scan of the finding's earliest observation.
	FirstSeenScan string
}

// ScanDiff is the result of DiffScans.
type ScanDiff struct {
	Base, Head           *Scan
	Comparable           bool
	ComparabilityReasons []string
	History              string
	Entries              []ScanDiffEntry
	// Counts has one key per DiffChanges class, zero included.
	Counts map[string]int
}

// NewScanDiff returns an empty diff of head against base with every
// DiffChanges count present at zero.
func NewScanDiff(base, head *Scan, comparable bool, reasons []string, history string) *ScanDiff {
	d := &ScanDiff{
		Base: base, Head: head,
		Comparable: comparable, ComparabilityReasons: reasons,
		History: history,
		Counts:  make(map[string]int, len(DiffChanges)),
	}
	for _, c := range DiffChanges {
		d.Counts[c] = 0
	}
	return d
}

// Classify adds f under the class its observations give it: unchanged when
// both sides observed it, new when only the head did, and fixed (Comparable)
// or not_reobserved when only the base did. A finding neither side observed
// is not added.
func (d *ScanDiff) Classify(f *Finding, inBase, inHead bool, firstSeen string) {
	var change string
	switch {
	case inBase && inHead:
		change = DiffUnchanged
	case inHead:
		change = DiffNew
	case inBase && d.Comparable:
		change = DiffFixed
	case inBase:
		change = DiffNotReobserved
	default:
		return
	}
	d.Entries = append(d.Entries, ScanDiffEntry{Finding: f, Change: change, FirstSeenScan: firstSeen})
	d.Counts[change]++
}

// SortEntries orders entries by class (DiffChanges), then severity, then id.
func (d *ScanDiff) SortEntries() {
	sort.SliceStable(d.Entries, func(i, j int) bool {
		a, b := d.Entries[i], d.Entries[j]
		if ca, cb := slices.Index(DiffChanges, a.Change), slices.Index(DiffChanges, b.Change); ca != cb {
			return ca < cb
		}
		if sa, sb := severityWeight(a.Finding.Severity), severityWeight(b.Finding.Severity); sa != sb {
			return sa > sb
		}
		return a.Finding.ID < b.Finding.ID
	})
}

// DiffScans classifies every finding observed by either scan:
// new = head \ base, unchanged = base ∩ head, and for base \ head fixed when
// the head is comparable (ScanComparability), not_reobserved otherwise.
// Dismissed findings are left out unless IncludeDismissed. Entries are ordered
// by class (DiffChanges), then severity, then id.
func (r *Repository) DiffScans(ctx context.Context, opts ScanDiffOptions) (*ScanDiff, error) {
	if opts.Base == nil || opts.Head == nil {
		return nil, fmt.Errorf("DiffScans: both scans are required")
	}
	base, head := opts.Base.UUID, opts.Head.UUID

	filters := QueryFilters{
		ProjectUUID:     opts.ProjectUUID,
		ObservedInScans: []string{base, head},
	}
	if !opts.IncludeDismissed {
		filters.ExcludeStatuses = DismissedFindingStatuses
	}
	findings, err := NewFindingsQueryBuilder(r.db, filters).Execute(ctx)
	if err != nil {
		return nil, fmt.Errorf("DiffScans: load findings: %w", err)
	}

	// Which of the two scans observed each finding.
	var obs []FindingObservation
	q := r.db.NewSelect().Model(&obs).Column("finding_id", "scan_uuid").
		Where("scan_uuid IN (?)", bun.List([]string{base, head}))
	if opts.ProjectUUID != "" {
		q = q.Where("project_uuid = ?", opts.ProjectUUID)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("DiffScans: load observations: %w", err)
	}
	inBase, inHead := map[int64]bool{}, map[int64]bool{}
	for _, o := range obs {
		if o.ScanUUID == base {
			inBase[o.FindingID] = true
		}
		if o.ScanUUID == head {
			inHead[o.FindingID] = true
		}
	}

	ids := make([]int64, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.ID)
	}
	firstSeen, err := r.firstObservingScans(ctx, ids)
	if err != nil {
		return nil, err
	}

	comparable, reasons := ScanComparability(opts.Base, opts.Head)
	history, err := r.observationHistory(ctx, opts.Base, opts.Head)
	if err != nil {
		return nil, err
	}

	diff := NewScanDiff(opts.Base, opts.Head, comparable, reasons, history)
	for _, f := range findings {
		diff.Classify(f, inBase[f.ID], inHead[f.ID], firstSeen[f.ID])
	}
	diff.SortEntries()
	return diff, nil
}

// ScanComparability reports whether head can vouch for the absence of base's
// findings: it finished, to completion, over at least base's targets and every
// phase that ran in base. Unknown is never comparable — "fixed" is a claim, and
// a missing verdict cannot support it.
func ScanComparability(base, head *Scan) (bool, []string) {
	var reasons []string
	switch {
	case head.Status != "completed":
		reasons = append(reasons, ComparabilityHeadNotFinished)
	case head.Completeness == CompletenessPartial:
		reasons = append(reasons, ComparabilityHeadPartial)
	case head.Completeness == "":
		reasons = append(reasons, ComparabilityHeadCompletenessUnset)
	}

	baseTargets, headTargets := scanTargetSet(base.Target), scanTargetSet(head.Target)
	switch {
	case len(baseTargets) == 0 || len(headTargets) == 0:
		reasons = append(reasons, ComparabilityTargetsUnknown)
	default:
		for t := range baseTargets {
			if !headTargets[t] {
				reasons = append(reasons, ComparabilityTargetsNotCovered)
				break
			}
		}
	}

	if len(base.PhaseOutcomes) == 0 || len(head.PhaseOutcomes) == 0 {
		reasons = append(reasons, ComparabilityPhasesUnknown)
	} else {
		headDone := map[string]bool{}
		for _, p := range head.PhaseOutcomes {
			if p.State == PhaseCompleted {
				headDone[p.Phase] = true
			}
		}
		for _, p := range base.PhaseOutcomes {
			if p.State == PhaseSkipped {
				continue // did not run in base, so head owes nothing for it
			}
			if !headDone[p.Phase] {
				reasons = append(reasons, ComparabilityPhasesNotCovered)
				break
			}
		}
	}
	return len(reasons) == 0, reasons
}

// observationHistory labels a diff partial when either scan started before the
// store began recording every observation.
func (r *Repository) observationHistory(ctx context.Context, scans ...*Scan) (string, error) {
	since, err := r.ObservationHistorySince(ctx)
	if err != nil {
		return "", err
	}
	for _, s := range scans {
		if since.IsZero() || s.StartedAt.Before(since) {
			return DiffHistoryPartial, nil
		}
	}
	return DiffHistoryComplete, nil
}

// firstObservingScans maps each finding id to the scan of its earliest
// observation (ties by scan uuid). The pick happens in SQL: ROW_NUMBER is a
// window function both SQLite (3.25+) and PostgreSQL support, so only one row
// per finding crosses the driver.
func (r *Repository) firstObservingScans(ctx context.Context, ids []int64) (map[int64]string, error) {
	out := make(map[int64]string, len(ids))
	for chunk := range slices.Chunk(ids, SQLChunkSize) {
		ranked := r.db.NewSelect().Model((*FindingObservation)(nil)).
			Column("finding_id", "scan_uuid").
			ColumnExpr("ROW_NUMBER() OVER (PARTITION BY fo.finding_id ORDER BY fo.observed_at ASC, fo.scan_uuid ASC) AS rn").
			Where("finding_id IN (?)", bun.List(chunk))
		var first []struct {
			FindingID int64  `bun:"finding_id"`
			ScanUUID  string `bun:"scan_uuid"`
		}
		if err := r.db.NewSelect().TableExpr("(?) AS first_obs", ranked).
			Column("finding_id", "scan_uuid").
			Where("rn = 1").
			Scan(ctx, &first); err != nil {
			return nil, fmt.Errorf("load first observations: %w", err)
		}
		for _, o := range first {
			out[o.FindingID] = o.ScanUUID
		}
	}
	return out, nil
}

// NewSinceBaseline is the `finding --new-since <scan>` predicate: keep findings
// the baseline scan did not observe and whose earliest observation belongs to a
// scan that started after the baseline did. A finding with no observations at
// all (an import, an out-of-band agent finding) falls back to "stored after the
// baseline finished".
//
// PartialHistory is set when the baseline predates the store's observation
// history; the predicate then also requires the finding to have been stored
// after the baseline started, since a backfilled finding's only observation is
// its LATEST scan and would otherwise read as new.
type NewSinceBaseline struct {
	ScanUUID       string
	PartialHistory bool
}

// apply adds the predicate to a findings query (alias f). The baseline's times
// are read by subquery from its own row, so both sides of every comparison are
// stored values in the same format.
func (n *NewSinceBaseline) apply(query *bun.SelectQuery) {
	query.Where(`(
		(EXISTS (SELECT 1 FROM finding_observations o WHERE o.finding_id = f.id)
		 AND NOT EXISTS (
			SELECT 1 FROM finding_observations o
			LEFT JOIN scans s ON s.uuid = o.scan_uuid
			WHERE o.finding_id = f.id
			  AND (o.scan_uuid = ? OR COALESCE(s.started_at, o.observed_at) <= (SELECT bs.started_at FROM scans bs WHERE bs.uuid = ?))))
		OR (NOT EXISTS (SELECT 1 FROM finding_observations o WHERE o.finding_id = f.id)
		 AND f.created_at > (SELECT COALESCE(bs.finished_at, bs.started_at) FROM scans bs WHERE bs.uuid = ?)))`,
		n.ScanUUID, n.ScanUUID, n.ScanUUID)
	if n.PartialHistory {
		query.Where("f.created_at > (SELECT bs.started_at FROM scans bs WHERE bs.uuid = ?)", n.ScanUUID)
	}
}

// ResolveNewSince builds the --new-since predicate for a baseline scan already
// resolved in scope.
func (r *Repository) ResolveNewSince(ctx context.Context, baseline *Scan) (*NewSinceBaseline, error) {
	history, err := r.observationHistory(ctx, baseline)
	if err != nil {
		return nil, err
	}
	return &NewSinceBaseline{ScanUUID: baseline.UUID, PartialHistory: history == DiffHistoryPartial}, nil
}

// Scan reference keywords accepted by ResolveScanRef.
const (
	ScanRefLatest   = "latest"
	ScanRefPrevious = "previous"
)

// ResolveScanRef resolves a scan reference within the project: a full UUID, a
// UUID prefix of at least 8 characters, or the keyword "latest" (the most
// recently started scan that is not still running) / "previous" (the one
// before it). A miss — including a scan in another project — is
// ErrScanNotFound; an ambiguous prefix names its candidates.
func (r *Repository) ResolveScanRef(ctx context.Context, projectUUID, ref string) (*Scan, error) {
	ref = strings.TrimSpace(ref)
	switch strings.ToLower(ref) {
	case ScanRefLatest, ScanRefPrevious:
		scans, err := r.recentFinishedScans(ctx, projectUUID, "", 2)
		if err != nil {
			return nil, err
		}
		idx := 0
		if strings.EqualFold(ref, ScanRefPrevious) {
			idx = 1
		}
		if len(scans) <= idx {
			return nil, fmt.Errorf("%w: no %s scan in scope (found %d finished scan(s))", ErrScanNotFound, strings.ToLower(ref), len(scans))
		}
		return scans[idx], nil
	}

	scan := &Scan{}
	q := r.db.NewSelect().Model(scan).Where("uuid = ?", ref)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	err := q.Scan(ctx)
	if err == nil {
		return scan, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("look up scan %s: %w", ref, err)
	}
	if len(ref) < MinUUIDPrefix {
		return nil, fmt.Errorf("%w: %q (a prefix needs at least %d characters; keywords: latest, previous)", ErrScanNotFound, ref, MinUUIDPrefix)
	}
	full, cands, err := r.ResolveUUIDPrefix(ctx, "scans", projectUUID, ref)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, fmt.Errorf("%w: %q", ErrScanNotFound, ref)
	case err != nil:
		return nil, fmt.Errorf("look up scan prefix %s: %w", ref, err)
	case full == "":
		return nil, fmt.Errorf("scan prefix %q matches several scans (%s) - use more characters", ref, strings.Join(cands, ", "))
	}
	return r.GetScanByUUID(ctx, full)
}

// ScansForTarget returns the last n finished scans (newest first) whose target
// list includes target. Matching is on the normalized target (case, trailing
// slash); a target given without a scheme matches either scheme.
func (r *Repository) ScansForTarget(ctx context.Context, projectUUID, target string, n int) ([]*Scan, error) {
	want := normalizeScanTarget(target)
	if want == "" {
		return nil, fmt.Errorf("ScansForTarget: empty target")
	}
	// The LIKE pre-filter narrows to rows mentioning the host; the exact
	// membership test runs on the split list below.
	candidates, err := r.recentFinishedScans(ctx, projectUUID, stripScheme(want), 0)
	if err != nil {
		return nil, err
	}
	schemeless := stripScheme(want) == want
	var out []*Scan
	for _, s := range candidates {
		for t := range scanTargetSet(s.Target) {
			if t == want || (schemeless && stripScheme(t) == want) {
				out = append(out, s)
				break
			}
		}
		if n > 0 && len(out) == n {
			break
		}
	}
	return out, nil
}

// recentFinishedScans lists scans that are not still running, newest start
// first. contains, when set, narrows to targets containing it; limit 0 = all.
func (r *Repository) recentFinishedScans(ctx context.Context, projectUUID, contains string, limit int) ([]*Scan, error) {
	var scans []*Scan
	q := r.db.NewSelect().Model(&scans).
		Where("status NOT IN (?)", bun.List([]string{"running", "paused", "pending", "queued"})).
		OrderExpr("started_at DESC, created_at DESC")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if contains != "" {
		q = q.Where(WithLikeEscape("LOWER(target) LIKE ?"), LikeContains(contains))
	}
	if limit > 0 {
		q = q.Limit(int64(limit))
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	return scans, nil
}

// scanTargetSet splits a scan row's target column (the runner joins several
// with ", ") into a normalized set.
func scanTargetSet(target string) map[string]bool {
	set := map[string]bool{}
	for _, t := range strings.Split(target, ",") {
		if t = normalizeScanTarget(t); t != "" {
			set[t] = true
		}
	}
	return set
}

func normalizeScanTarget(t string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(t)), "/")
}

func stripScheme(t string) string {
	if _, rest, ok := strings.Cut(t, "://"); ok {
		return rest
	}
	return t
}

// severityWeight orders severities for display (critical highest).
func severityWeight(s string) int {
	switch strings.ToLower(s) {
	case SeverityCritical:
		return 6
	case SeverityHigh:
		return 5
	case SeverityMedium:
		return 4
	case SeverityLow:
		return 3
	case SeveritySuspect:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}
