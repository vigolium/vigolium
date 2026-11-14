package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"
)

// DismissedFindingStatuses are the verdicts that take a finding out of the
// answer to "what is still wrong": an operator or agent has ruled it not a bug
// (false_positive) or decided to live with it (accepted_risk). The --fail-on
// gate, `scan diff` and `finding --new-since` leave these out by default;
// reports keep them, labelled.
var DismissedFindingStatuses = []string{StatusFalsePositive, StatusAcceptedRisk}

// MinFindingHashPrefix is the shortest finding_hash prefix a status write
// accepts. finding_hash is a 40-char hex digest and is stable across databases
// (unlike the autoincrement id), so it is the identity an agent should carry;
// twelve characters keep a typo from matching by accident while staying short
// enough to copy reliably.
const MinFindingHashPrefix = 12

// FindingStatusUpdate names the findings to move and the verdict to give them.
// IDs and Hashes may both be set; a finding named twice is updated once.
// Hashes are full finding_hash values or prefixes of at least
// MinFindingHashPrefix hex characters.
type FindingStatusUpdate struct {
	IDs    []int64
	Hashes []string
	Status string
	// Note says why (stored as findings.status_note and on the event row). A
	// new verdict replaces the previous note, so an empty Note clears it.
	Note string
	// Actor names who decided: a person, "agent-triage", "api", ….
	Actor string
}

// FindingStatusChange is one finding a status write touched (or would have).
type FindingStatusChange struct {
	ID          int64  `json:"id"`
	FindingHash string `json:"finding_hash"`
	From        string `json:"from"`
	To          string `json:"to"`
}

// FindingStatusResult reports a status write. Changed findings moved to the new
// status (and got an event row); Unchanged already had it and were left alone,
// note included; NotFound lists the selectors (an id as its decimal string, a
// hash as given) that matched nothing in scope.
type FindingStatusResult struct {
	Changed   []FindingStatusChange
	Unchanged []FindingStatusChange
	NotFound  []string
}

// AmbiguousFindingHashError is returned when a hash prefix matches more than one
// finding. Nothing is written: a verdict meant for one finding must never land
// on several.
type AmbiguousFindingHashError struct {
	Prefix     string
	Candidates []string // finding_hash values, at most a handful
	More       bool     // more candidates exist than are listed
}

func (e *AmbiguousFindingHashError) Error() string {
	more := ""
	if e.More {
		more = ", …"
	}
	return fmt.Sprintf("finding hash prefix %q matches more than one finding (%s%s) - use more characters",
		e.Prefix, strings.Join(e.Candidates, ", "), more)
}

// ValidateFindingHashPrefix rejects a hash selector that is too short or not
// hex. Exported so the CLI can reject it as a usage error before opening the
// store.
func ValidateFindingHashPrefix(h string) error {
	if len(h) < MinFindingHashPrefix {
		return fmt.Errorf("finding hash %q is too short: use at least %d characters (or the numeric id)", h, MinFindingHashPrefix)
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return fmt.Errorf("finding hash %q is not hexadecimal", h)
		}
	}
	return nil
}

// findingStatusRow is the slice of a finding a status write needs.
type findingStatusRow struct {
	ID          int64  `bun:"id"`
	ProjectUUID string `bun:"project_uuid"`
	FindingHash string `bun:"finding_hash"`
	Status      string `bun:"status"`
}

// UpdateFindingStatusScoped sets the lifecycle status of the findings named by
// id and/or finding_hash (full or ≥MinFindingHashPrefix prefix), inside one
// project, in one transaction. Each finding whose status actually changes gets
// status_note/status_actor/status_updated_at set and one finding_status_events
// row; a finding already at the status is reported Unchanged and not touched.
//
// The project predicate is part of every lookup, so an id or hash from another
// project matches nothing and is reported in NotFound — indistinguishable from
// a missing finding, revealing nothing about other projects. projectUUID == ""
// drops the predicate; only callers with scoping deliberately off (a standalone
// `-S --db file` store) pass it.
//
// An ambiguous hash prefix fails the whole call with *AmbiguousFindingHashError
// before anything is written.
//
// This is the single status writer for the CLI (`finding mark`, `agent
// triage`), REST PATCH and the olium update_finding tool. The swarm triage
// writeback, which scopes by agentic scan rather than by finding, keeps
// UpdateFindingStatusByHash.
func (r *Repository) UpdateFindingStatusScoped(ctx context.Context, projectUUID string, req FindingStatusUpdate) (*FindingStatusResult, error) {
	if !IsValidFindingStatus(req.Status) {
		return nil, fmt.Errorf("UpdateFindingStatusScoped: invalid status %q", req.Status)
	}
	for _, h := range req.Hashes {
		if err := ValidateFindingHashPrefix(h); err != nil {
			return nil, fmt.Errorf("UpdateFindingStatusScoped: %w", err)
		}
	}

	res := &FindingStatusResult{}
	err := r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		*res = FindingStatusResult{}
		targets, notFound, err := resolveFindingSelectors(ctx, tx, projectUUID, req.IDs, req.Hashes)
		if err != nil {
			return err
		}
		res.NotFound = notFound

		now := time.Now().UTC()
		var changedIDs []int64
		var events []FindingStatusEvent
		for _, row := range targets {
			from := row.Status
			if from == "" {
				from = StatusTriaged // the column default; NULL reads as triaged
			}
			change := FindingStatusChange{ID: row.ID, FindingHash: row.FindingHash, From: from, To: req.Status}
			if from == req.Status {
				res.Unchanged = append(res.Unchanged, change)
				continue
			}
			changedIDs = append(changedIDs, row.ID)
			events = append(events, FindingStatusEvent{
				FindingID:   row.ID,
				ProjectUUID: defaultProjectUUID(row.ProjectUUID),
				FromStatus:  from,
				ToStatus:    req.Status,
				Note:        req.Note,
				Actor:       req.Actor,
				CreatedAt:   now,
			})
			res.Changed = append(res.Changed, change)
		}
		for chunk := range slices.Chunk(changedIDs, SQLChunkSize) {
			if _, err := tx.NewUpdate().Model((*Finding)(nil)).
				Set("status = ?", req.Status).
				Set("status_note = ?", nullIfEmpty(req.Note)).
				Set("status_actor = ?", nullIfEmpty(req.Actor)).
				Set("status_updated_at = ?", now).
				Where("id IN (?)", bun.List(chunk)).
				Exec(ctx); err != nil {
				return fmt.Errorf("update finding status: %w", err)
			}
		}
		// Events carry 8 columns each; keep every INSERT well under the
		// driver's bind-parameter limit.
		for chunk := range slices.Chunk(events, SQLChunkSize/8) {
			if _, err := tx.NewInsert().Model(&chunk).Exec(ctx); err != nil {
				return fmt.Errorf("record finding status events: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		var amb *AmbiguousFindingHashError
		if errors.As(err, &amb) {
			return nil, amb
		}
		return nil, fmt.Errorf("UpdateFindingStatusScoped: %w", err)
	}
	return res, nil
}

// SetFindingStatus is UpdateFindingStatusScoped for one finding by id: it
// returns sql.ErrNoRows when the id matches nothing in scope, and nil when the
// finding was updated or already had the status.
func (r *Repository) SetFindingStatus(ctx context.Context, projectUUID string, id int64, status, note, actor string) error {
	res, err := r.UpdateFindingStatusScoped(ctx, projectUUID, FindingStatusUpdate{
		IDs: []int64{id}, Status: status, Note: note, Actor: actor,
	})
	if err != nil {
		return err
	}
	if len(res.NotFound) > 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListFindingStatusEvents returns a finding's status history, oldest first.
// projectUUID == "" drops the project predicate (scoping off).
func (r *Repository) ListFindingStatusEvents(ctx context.Context, projectUUID string, findingID int64) ([]FindingStatusEvent, error) {
	var out []FindingStatusEvent
	q := r.db.NewSelect().Model(&out).Where("finding_id = ?", findingID).OrderExpr("created_at ASC, id ASC")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("list finding status events: %w", err)
	}
	return out, nil
}

// resolveFindingSelectors maps ids and hash prefixes to finding rows within the
// project, deduplicated and ordered by id. Selectors that match nothing come
// back in notFound, in the order given.
func resolveFindingSelectors(ctx context.Context, idb bun.IDB, projectUUID string, ids []int64, hashes []string) ([]findingStatusRow, []string, error) {
	byID := map[int64]findingStatusRow{}
	var notFound []string

	if len(ids) > 0 {
		var rows []findingStatusRow
		for chunk := range slices.Chunk(ids, SQLChunkSize) {
			var part []findingStatusRow
			q := idb.NewSelect().Model((*Finding)(nil)).
				Column("id", "project_uuid", "finding_hash", "status").
				Where("id IN (?)", bun.List(chunk))
			if projectUUID != "" {
				q = q.Where("project_uuid = ?", projectUUID)
			}
			if err := q.Scan(ctx, &part); err != nil {
				return nil, nil, fmt.Errorf("look up findings by id: %w", err)
			}
			rows = append(rows, part...)
		}
		for _, row := range rows {
			byID[row.ID] = row
		}
		seen := map[int64]bool{}
		for _, id := range ids {
			if _, ok := byID[id]; !ok && !seen[id] {
				notFound = append(notFound, strconv.FormatInt(id, 10))
			}
			seen[id] = true
		}
	}

	const maxCandidates = 5
	seenHash := map[string]bool{}
	for _, h := range hashes {
		prefix := strings.ToLower(h)
		if seenHash[prefix] {
			continue
		}
		seenHash[prefix] = true
		upper, ok := prefixUpperBound(prefix)
		if !ok {
			notFound = append(notFound, h)
			continue
		}
		// A range over the (project_uuid, finding_hash) unique index rather than
		// LIKE 'prefix%', which neither SQLite nor Postgres can seek with.
		var rows []findingStatusRow
		q := idb.NewSelect().Model((*Finding)(nil)).
			Column("id", "project_uuid", "finding_hash", "status").
			Where("finding_hash >= ? AND finding_hash < ?", prefix, upper).
			OrderExpr("finding_hash ASC").
			Limit(maxCandidates + 1)
		if projectUUID != "" {
			q = q.Where("project_uuid = ?", projectUUID)
		}
		if err := q.Scan(ctx, &rows); err != nil {
			return nil, nil, fmt.Errorf("look up findings by hash: %w", err)
		}
		if len(rows) == 0 {
			// A hash from before identity v2, or of a duplicate merged away,
			// resolves through finding_hash_aliases to the finding that
			// absorbed it.
			aliased, err := resolveAliasPrefix(ctx, idb, projectUUID, prefix, upper, maxCandidates)
			if err != nil {
				return nil, nil, err
			}
			rows = aliased
		}
		switch {
		case len(rows) == 0:
			notFound = append(notFound, h)
		case len(rows) > 1 && !allSameFinding(rows):
			cands := make([]string, 0, maxCandidates)
			for i, row := range rows {
				if i == maxCandidates {
					break
				}
				cands = append(cands, row.FindingHash)
			}
			return nil, nil, &AmbiguousFindingHashError{Prefix: h, Candidates: cands, More: len(rows) > maxCandidates}
		default:
			byID[rows[0].ID] = rows[0]
		}
	}

	out := make([]findingStatusRow, 0, len(byID))
	for _, row := range byID {
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, notFound, nil
}

// resolveAliasPrefix looks a hash prefix up in finding_hash_aliases and loads
// the findings it names (at most limit+1 distinct ones).
func resolveAliasPrefix(ctx context.Context, idb bun.IDB, projectUUID, prefix, upper string, limit int) ([]findingStatusRow, error) {
	var ids []int64
	q := idb.NewSelect().Model((*FindingHashAlias)(nil)).ColumnExpr("DISTINCT finding_id").
		Where("alias_hash >= ? AND alias_hash < ?", prefix, upper).
		Limit(int64(limit + 1))
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if err := q.Scan(ctx, &ids); err != nil {
		return nil, fmt.Errorf("look up finding hash aliases: %w", err)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	var rows []findingStatusRow
	fq := idb.NewSelect().Model((*Finding)(nil)).
		Column("id", "project_uuid", "finding_hash", "status").
		Where("id IN (?)", bun.List(ids)).
		OrderExpr("finding_hash ASC")
	if projectUUID != "" {
		fq = fq.Where("project_uuid = ?", projectUUID)
	}
	if err := fq.Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("load aliased findings: %w", err)
	}
	return rows, nil
}

// allSameFinding reports whether every row is the same finding (the hash
// lookup cannot return duplicates today, but a match is only ambiguous when it
// names two different findings).
func allSameFinding(rows []findingStatusRow) bool {
	for _, row := range rows[1:] {
		if row.ID != rows[0].ID {
			return false
		}
	}
	return true
}

// nullIfEmpty binds "" as NULL so a cleared note reads back as absent rather
// than as an empty string.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
