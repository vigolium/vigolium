package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

// Finding identity v2 (schema v6).
//
// output.ResultEvent.IdentityKey describes what identifies a finding. This
// file is the store side: the alias table that keeps a finding's pre-v6 hashes
// resolvable, the re-detection update, and the one-time re-key of stored rows.

// identityV2Version is the schema version that re-keyed stored findings to the
// v2 location identity. A store below it gets RekeyFindingIdentities once.
const identityV2Version = 6

// Actors written on status events this file records.
const (
	// StatusActorRescan reopens a `fixed` finding a later scan detected again.
	StatusActorRescan = "rescan"
	// StatusActorIdentityMigration carries a merged group's triage onto its
	// survivor during the v6 re-key.
	StatusActorIdentityMigration = "migration:identity-v2"
)

// FindingHashAlias maps a finding hash that no longer names a row (a pre-v6
// content hash, or a duplicate folded into a survivor) to the finding that
// absorbed it, so `finding mark <old-hash>`, curl/verify and the --fail-on
// dismissal lookup keep resolving.
type FindingHashAlias struct {
	bun.BaseModel `bun:"table:finding_hash_aliases,alias:fha" json:"-"`

	ProjectUUID string    `bun:"project_uuid,notnull" json:"project_uuid"`
	AliasHash   string    `bun:"alias_hash,notnull" json:"alias_hash"`
	FindingID   int64     `bun:"finding_id,notnull" json:"finding_id"`
	CreatedAt   time.Time `bun:"created_at,notnull,default:current_timestamp" json:"created_at"`
}

// insertHashAliasesTx records old hashes as aliases of findingID. A hash
// already aliased (or still a live finding_hash) is left alone.
func insertHashAliasesTx(ctx context.Context, idb bun.IDB, projectUUID string, findingID int64, hashes []string) error {
	for _, h := range hashes {
		if h == "" {
			continue
		}
		if _, err := idb.NewRaw(
			`INSERT INTO finding_hash_aliases (project_uuid, alias_hash, finding_id, created_at)
			 SELECT ?, ?, ?, CURRENT_TIMESTAMP
			 WHERE NOT EXISTS (SELECT 1 FROM finding_hash_aliases WHERE project_uuid = ? AND alias_hash = ?)
			   AND NOT EXISTS (SELECT 1 FROM findings WHERE project_uuid = ? AND finding_hash = ?)`,
			projectUUID, h, findingID, projectUUID, h, projectUUID, h,
		).Exec(ctx); err != nil {
			return fmt.Errorf("record finding hash alias: %w", err)
		}
	}
	return nil
}

// resolveHashAliases maps exact hashes to the finding ids they alias within the
// project ("" = every project). Hashes with no alias are absent from the map.
func resolveHashAliases(ctx context.Context, idb bun.IDB, projectUUID string, hashes []string) (map[string]int64, error) {
	out := map[string]int64{}
	for chunk := range slices.Chunk(hashes, SQLChunkSize) {
		var rows []FindingHashAlias
		q := idb.NewSelect().Model(&rows).Column("alias_hash", "finding_id").
			Where("alias_hash IN (?)", bun.List(chunk))
		if projectUUID != "" {
			q = q.Where("project_uuid = ?", projectUUID)
		}
		if err := q.Scan(ctx); err != nil {
			return nil, fmt.Errorf("resolve finding hash aliases: %w", err)
		}
		for _, row := range rows {
			out[row.AliasHash] = row.FindingID
		}
	}
	return out, nil
}

// DismissedFindingHashes returns which of the given hashes name a finding
// carrying a dismissed verdict (DismissedFindingStatuses), by live hash or by
// alias. The result maps each input hash that is dismissed to true.
func (r *Repository) DismissedFindingHashes(ctx context.Context, projectUUID string, hashes []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(hashes) == 0 {
		return out, nil
	}
	for chunk := range slices.Chunk(hashes, SQLChunkSize) {
		var dismissed []string
		q := r.db.NewSelect().Model((*Finding)(nil)).Column("finding_hash").
			Where("finding_hash IN (?)", bun.List(chunk)).
			Where("status IN (?)", bun.List(DismissedFindingStatuses))
		if projectUUID != "" {
			q = q.Where("project_uuid = ?", projectUUID)
		}
		if err := q.Scan(ctx, &dismissed); err != nil {
			return nil, err
		}
		for _, h := range dismissed {
			out[h] = true
		}
	}
	var rest []string
	for _, h := range hashes {
		if !out[h] {
			rest = append(rest, h)
		}
	}
	if len(rest) == 0 {
		return out, nil
	}
	aliases, err := resolveHashAliases(ctx, r.db, projectUUID, rest)
	if err != nil || len(aliases) == 0 {
		return out, err
	}
	ids := make([]int64, 0, len(aliases))
	for _, id := range aliases {
		ids = append(ids, id)
	}
	var dismissedIDs []int64
	q := r.db.NewSelect().Model((*Finding)(nil)).Column("id").
		Where("id IN (?)", bun.List(ids)).
		Where("status IN (?)", bun.List(DismissedFindingStatuses))
	if err := q.Scan(ctx, &dismissedIDs); err != nil {
		return out, err
	}
	isDismissed := make(map[int64]bool, len(dismissedIDs))
	for _, id := range dismissedIDs {
		isDismissed[id] = true
	}
	for h, id := range aliases {
		if isDismissed[id] {
			out[h] = true
		}
	}
	return out, nil
}

// recordRedetectionTx applies what a re-detection says about an existing
// finding: it was seen now (last_seen_at), the latest severity, confidence and
// description stand, and a finding marked `fixed` is open again (status
// triaged, with a status event by StatusActorRescan).
func recordRedetectionTx(idb bun.IDB, existingID int64, existingStatus string, latest *Finding) (*bun.UpdateQuery, *FindingStatusEvent) {
	now := time.Now().UTC()
	q := idb.NewUpdate().Model((*Finding)(nil)).Where("id = ?", existingID).
		Set("last_seen_at = ?", now)
	if latest != nil {
		if latest.Severity != "" {
			q = q.Set("severity = ?", latest.Severity)
		}
		if latest.Confidence != "" {
			q = q.Set("confidence = ?", latest.Confidence)
		}
		if latest.Description != "" {
			q = q.Set("description = ?", latest.Description)
		}
	}
	if existingStatus != StatusFixed {
		return q, nil
	}
	q = q.Set("status = ?", StatusTriaged).
		Set("status_actor = ?", StatusActorRescan).
		Set("status_note = ?", nil).
		Set("status_updated_at = ?", now)
	projectUUID := ""
	if latest != nil {
		projectUUID = latest.ProjectUUID
	}
	return q, &FindingStatusEvent{
		FindingID:   existingID,
		ProjectUUID: defaultProjectUUID(projectUUID),
		FromStatus:  StatusFixed,
		ToStatus:    StatusTriaged,
		Note:        "detected again by a later scan",
		Actor:       StatusActorRescan,
		CreatedAt:   now,
	}
}

// RekeyStats summarises a RekeyFindingIdentities pass.
type RekeyStats struct {
	Rekeyed int64 // rows whose finding_hash moved to the v2 identity
	Merged  int64 // rows folded into a survivor (deleted)
	Aliases int64 // old hashes recorded as aliases
}

// rekeyRow is what the re-key reads of one finding.
type rekeyRow struct {
	ID               int64      `bun:"id"`
	ProjectUUID      string     `bun:"project_uuid"`
	ScanUUID         string     `bun:"scan_uuid"`
	ModuleID         string     `bun:"module_id"`
	ModuleName       string     `bun:"module_name"`
	RecordKind       string     `bun:"record_kind"`
	Description      string     `bun:"description"`
	Severity         string     `bun:"severity"`
	MatchedAt        []string   `bun:"matched_at,type:jsonb"`
	RequestHead      string     `bun:"request_head"`
	URL              string     `bun:"url"`
	OriginRecordUUID string     `bun:"origin_record_uuid"`
	InsertionPoint   string     `bun:"insertion_point"`
	FindingHash      string     `bun:"finding_hash"`
	Status           string     `bun:"status"`
	StatusNote       string     `bun:"status_note"`
	StatusActor      string     `bun:"status_actor"`
	StatusUpdatedAt  *time.Time `bun:"status_updated_at"`
	CreatedAt        time.Time  `bun:"created_at"`

	v2 string
}

// RekeyFindingIdentities moves stored findings onto the v2 location identity
// (output.IdentityKeyV2), merging rows that share a v2 key. projectUUID ""
// re-keys every project. Idempotent: rows already on their v2 hash and alone
// in their group are left as they are.
//
// Only rows that recorded an insertion point AND whose stored hash is their v1
// content hash (or already their v2 hash) are re-keyed. A row whose hash is
// neither came from a producer DedupKey and keeps it, the same rule ID() uses
// at emission, so a re-detection after the migration lands on the migrated row.
//
// Within a group the oldest row survives (its id, so links and history stay
// valid); it absorbs the others' evidence links, records, observations and
// status events; its triage becomes the most recently set verdict in the group;
// its scan_uuid is the latest observer's; every old hash becomes an alias.
func (db *DB) RekeyFindingIdentities(ctx context.Context, projectUUID string) (RekeyStats, error) {
	var stats RekeyStats
	var rows []rekeyRow
	q := db.NewSelect().TableExpr("findings AS f").
		ColumnExpr("f.id, f.project_uuid, COALESCE(f.scan_uuid, '') AS scan_uuid, f.module_id, f.module_name").
		ColumnExpr("COALESCE(NULLIF(f.record_kind, ''), 'finding') AS record_kind, COALESCE(f.description, '') AS description, f.severity").
		ColumnExpr("f.matched_at, COALESCE(substr(f.request, 1, 32), '') AS request_head, COALESCE(f.url, '') AS url").
		ColumnExpr("COALESCE(f.origin_record_uuid, '') AS origin_record_uuid, CAST(f.insertion_point AS TEXT) AS insertion_point").
		ColumnExpr("f.finding_hash, COALESCE(f.status, '') AS status, COALESCE(f.status_note, '') AS status_note, COALESCE(f.status_actor, '') AS status_actor").
		ColumnExpr("f.status_updated_at, f.created_at").
		Where("f.insertion_point IS NOT NULL")
	if projectUUID != "" {
		q = q.Where("f.project_uuid = ?", projectUUID)
	}
	if err := q.Scan(ctx, &rows); err != nil {
		return stats, fmt.Errorf("rekey findings: load: %w", err)
	}
	if len(rows) == 0 {
		return stats, nil
	}

	originURL, err := db.originRecordURLs(ctx, rows)
	if err != nil {
		return stats, err
	}

	type groupKey struct{ project, v2 string }
	groups := map[groupKey][]*rekeyRow{}
	var order []groupKey
	for i := range rows {
		row := &rows[i]
		var ip FindingInsertionPoint
		if row.InsertionPoint == "" || json.Unmarshal([]byte(row.InsertionPoint), &ip) != nil || ip.Type == "" {
			continue
		}
		matched := ""
		if len(row.MatchedAt) > 0 {
			matched = row.MatchedAt[0]
		}
		kind := output.RecordKind(row.RecordKind)
		v1 := output.HashContentV1(kind, row.ModuleID, row.Description, row.Severity, matched)
		loc := originURL[row.ProjectUUID+"\x00"+row.OriginRecordUUID]
		if loc == "" {
			loc = row.URL
		}
		if loc == "" {
			loc = matched
		}
		row.v2 = output.HashIdentityV2(output.IdentityFields{
			Kind: kind, ModuleID: row.ModuleID, Rule: row.ModuleName,
			Method: output.RequestMethod(row.RequestHead), URL: loc,
			IPType: ip.Type, Param: ip.Name,
		})
		if row.FindingHash != v1 && row.FindingHash != row.v2 {
			continue // a DedupKey identity: keep it
		}
		k := groupKey{row.ProjectUUID, row.v2}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], row)
	}

	// Work groups in bounded transactions so a large store neither holds one
	// enormous write transaction nor loads every body at once.
	const groupsPerTx = 200
	var pending [][]*rekeyRow
	for _, k := range order {
		g := groups[k]
		if len(g) == 1 && g[0].FindingHash == g[0].v2 {
			continue
		}
		pending = append(pending, g)
	}
	for batch := range slices.Chunk(pending, groupsPerTx) {
		if err := db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
			for _, g := range batch {
				if err := rekeyGroupTx(ctx, tx, g, &stats); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return stats, fmt.Errorf("rekey findings: %w", err)
		}
	}
	if stats.Rekeyed > 0 || stats.Merged > 0 {
		zap.L().Info("Re-keyed stored findings to identity v2",
			zap.Int64("rekeyed", stats.Rekeyed), zap.Int64("merged", stats.Merged), zap.Int64("aliases", stats.Aliases))
	}
	return stats, nil
}

// originRecordURLs resolves the scanned item's URL for rows that link one,
// keyed project + "\x00" + record uuid.
func (db *DB) originRecordURLs(ctx context.Context, rows []rekeyRow) (map[string]string, error) {
	byProject := map[string][]string{}
	for i := range rows {
		if u := rows[i].OriginRecordUUID; u != "" {
			byProject[rows[i].ProjectUUID] = append(byProject[rows[i].ProjectUUID], u)
		}
	}
	out := map[string]string{}
	for project, uuids := range byProject {
		slices.Sort(uuids)
		uuids = slices.Compact(uuids)
		for chunk := range slices.Chunk(uuids, SQLChunkSize) {
			var recs []struct {
				UUID string `bun:"uuid"`
				URL  string `bun:"url"`
			}
			if err := db.NewSelect().TableExpr("http_records").Column("uuid", "url").
				Where("project_uuid = ?", project).
				Where("uuid IN (?)", bun.List(chunk)).
				Scan(ctx, &recs); err != nil {
				return nil, fmt.Errorf("rekey findings: origin records: %w", err)
			}
			for _, rec := range recs {
				out[project+"\x00"+rec.UUID] = rec.URL
			}
		}
	}
	return out, nil
}

// rekeyGroupTx folds one v2 group into its oldest row and moves it to the v2
// hash.
func rekeyGroupTx(ctx context.Context, tx bun.Tx, g []*rekeyRow, stats *RekeyStats) error {
	sort.Slice(g, func(i, j int) bool {
		if !g[i].CreatedAt.Equal(g[j].CreatedAt) {
			return g[i].CreatedAt.Before(g[j].CreatedAt)
		}
		return g[i].ID < g[j].ID
	})
	survivor := g[0]
	dups := g[1:]
	dupIDs := make([]int64, len(dups))
	oldHashes := make([]string, 0, len(g))
	for i, d := range dups {
		dupIDs[i] = d.ID
	}
	for _, m := range g {
		if m.FindingHash != survivor.v2 {
			oldHashes = append(oldHashes, m.FindingHash)
		}
	}

	upd := tx.NewUpdate().Model((*Finding)(nil)).Where("id = ?", survivor.ID)
	if len(dups) > 0 {
		if err := migrateFindingRecordsTx(ctx, tx, survivor.ID, dupIDs); err != nil {
			return err
		}
		if err := migrateFindingHistoryTx(ctx, tx, survivor.ID, dupIDs); err != nil {
			return err
		}
		if err := mergeGroupEvidenceTx(ctx, tx, survivor.ID, dupIDs, upd); err != nil {
			return err
		}
		if ev := groupTriage(survivor, dups, upd); ev != nil {
			if _, err := tx.NewInsert().Model(ev).Exec(ctx); err != nil {
				return fmt.Errorf("record migration status event: %w", err)
			}
		}
		if err := deleteFindingsByIDsTx(ctx, tx, dupIDs); err != nil {
			return err
		}
		stats.Merged += int64(len(dups))
	}

	// The latest observation names the scan that last saw the issue.
	var latest []struct {
		ScanUUID   string    `bun:"scan_uuid"`
		ObservedAt time.Time `bun:"observed_at"`
	}
	if err := tx.NewSelect().TableExpr("finding_observations").Column("scan_uuid", "observed_at").
		Where("finding_id = ?", survivor.ID).OrderExpr("observed_at DESC").Limit(1).
		Scan(ctx, &latest); err != nil {
		return fmt.Errorf("read latest observation: %w", err)
	}
	if len(latest) > 0 {
		upd = upd.Set("scan_uuid = ?", latest[0].ScanUUID).Set("last_seen_at = ?", latest[0].ObservedAt)
	} else if newest := g[len(g)-1].ScanUUID; newest != "" {
		upd = upd.Set("scan_uuid = ?", newest)
	}
	upd = upd.Set("finding_hash = ?", survivor.v2)
	if _, err := upd.Exec(ctx); err != nil {
		return fmt.Errorf("update re-keyed finding: %w", err)
	}
	if survivor.FindingHash != survivor.v2 {
		stats.Rekeyed++
	}
	if _, err := tx.NewRaw("UPDATE finding_observations SET finding_hash = ? WHERE finding_id = ?", survivor.v2, survivor.ID).Exec(ctx); err != nil {
		return fmt.Errorf("re-key finding observations: %w", err)
	}
	if err := insertHashAliasesTx(ctx, tx, survivor.ProjectUUID, survivor.ID, oldHashes); err != nil {
		return err
	}
	stats.Aliases += int64(len(oldHashes))
	return nil
}

// mergeGroupEvidenceTx folds the duplicates' request/response pairs and their
// own evidence into the survivor's additional_evidence (set on upd).
func mergeGroupEvidenceTx(ctx context.Context, tx bun.Tx, survivorID int64, dupIDs []int64, upd *bun.UpdateQuery) error {
	type bodyRow struct {
		ID                 int64    `bun:"id"`
		Request            string   `bun:"request"`
		Response           string   `bun:"response"`
		AdditionalEvidence []string `bun:"additional_evidence,type:jsonb"`
	}
	ids := append([]int64{survivorID}, dupIDs...)
	var bodies []bodyRow
	if err := tx.NewSelect().TableExpr("findings").
		ColumnExpr("id, COALESCE(request, '') AS request, COALESCE(response, '') AS response, additional_evidence").
		Where("id IN (?)", bun.List(ids)).Scan(ctx, &bodies); err != nil {
		return fmt.Errorf("load bodies for re-key merge: %w", err)
	}
	var survivor bodyRow
	var extra []string
	for _, b := range bodies {
		if b.ID == survivorID {
			survivor = b
			continue
		}
		if ev := buildEvidence(b.Request, b.Response); ev != "" {
			extra = append(extra, ev)
		}
		extra = append(extra, b.AdditionalEvidence...)
	}
	if len(extra) == 0 {
		return nil
	}
	merged := appendUniqueEvidence(survivor.AdditionalEvidence, buildEvidence(survivor.Request, survivor.Response), extra...)
	if len(merged) > len(survivor.AdditionalEvidence) {
		upd.Set("additional_evidence = ?", merged)
	}
	return nil
}

// groupTriage carries the group's most recently set verdict onto the survivor
// (set on upd) and returns the status event recording it, or nil when the
// survivor's own verdict stands.
func groupTriage(survivor *rekeyRow, dups []*rekeyRow, upd *bun.UpdateQuery) *FindingStatusEvent {
	best := survivor
	for _, d := range dups {
		if d.StatusUpdatedAt == nil {
			continue
		}
		if best.StatusUpdatedAt == nil || d.StatusUpdatedAt.After(*best.StatusUpdatedAt) {
			best = d
		}
	}
	if best == survivor || best.Status == "" || strings.EqualFold(best.Status, survivor.Status) {
		return nil
	}
	from := survivor.Status
	if from == "" {
		from = StatusTriaged
	}
	upd.Set("status = ?", best.Status).
		Set("status_note = ?", nullIfEmpty(best.StatusNote)).
		Set("status_actor = ?", nullIfEmpty(best.StatusActor)).
		Set("status_updated_at = ?", best.StatusUpdatedAt)
	return &FindingStatusEvent{
		FindingID:   survivor.ID,
		ProjectUUID: defaultProjectUUID(survivor.ProjectUUID),
		FromStatus:  from,
		ToStatus:    best.Status,
		Note:        "merged by finding identity v2; verdict from finding " + best.FindingHash,
		Actor:       StatusActorIdentityMigration,
		CreatedAt:   time.Now().UTC(),
	}
}
