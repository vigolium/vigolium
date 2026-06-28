package database

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"

	"github.com/uptrace/bun"

	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

// secretDetectModuleID mirrors secret_detect.ModuleID. The URL-keyed finding
// dedup (DeduplicateFindings) collapses findings that share (module, severity,
// URL) — correct for a module like input-behavior-probe that fires many times on
// one endpoint with incidental per-payload values, but WRONG for the secret
// detector, whose extracted value IS the finding's identity: a client_id,
// client_secret, and access_token leaked in the same response are three distinct
// secrets on one URL, not duplicates. URL-merging them keeps only one value and
// buries the rest as redundant Additional Evidence. So secret-detect is excluded
// from the URL pass and deduped instead by the value-keyed pass
// (GroupFindingsByValue), which collapses identical secrets across URLs.
// Hardcoded (not imported) to avoid a modules→database import cycle, mirroring
// the existing 'deparos' source literals in this file.
const secretDetectModuleID = "secret-detect"

// dedupDeleteChunk bounds each IN-list delete/select so a dedup pass over a very
// large duplicate set stays within the driver's bound-parameter limit (SQLite's
// SQLITE_MAX_VARIABLE_NUMBER is 32766). A deparos discovery phase whose error/echo
// pages mirror the requested URI can produce tens of thousands of duplicate
// records — exactly what the deparos dedup passes target — so a single unbounded
// "uuid IN (?)" would error the whole transaction once the set crossed the limit.
const dedupDeleteChunk = 10000

// deleteRecordsByUUIDsTx deletes the http_records identified by uuids and their
// finding_records junction rows inside tx, chunking the IN lists so a large set
// never exceeds the bound-parameter limit. Shared by the record-dedup passes.
func deleteRecordsByUUIDsTx(ctx context.Context, tx bun.Tx, uuids []string) error {
	for chunk := range slices.Chunk(uuids, dedupDeleteChunk) {
		if _, err := tx.NewRaw("DELETE FROM finding_records WHERE record_uuid IN (?)", bun.List(chunk)).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding_records: %w", err)
		}
		if _, err := tx.NewDelete().Model((*HTTPRecord)(nil)).Where("uuid IN (?)", bun.List(chunk)).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete records: %w", err)
		}
	}
	return nil
}

// deleteFindingsByIDsTx deletes the findings identified by ids and their
// finding_records junction rows inside tx, chunking the IN lists. Shared by the
// finding-dedup passes.
func deleteFindingsByIDsTx(ctx context.Context, tx bun.Tx, ids []int64) error {
	for chunk := range slices.Chunk(ids, dedupDeleteChunk) {
		if _, err := tx.NewRaw("DELETE FROM finding_records WHERE finding_id IN (?)", bun.List(chunk)).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding_records: %w", err)
		}
		if _, err := tx.NewDelete().Model((*Finding)(nil)).Where("id IN (?)", bun.List(chunk)).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete findings: %w", err)
		}
	}
	return nil
}

// DeduplicateRecordsBySource removes duplicate HTTP records for a given source that share
// identical (hostname, method, status_code, response_content_length, response_hash).
// Within each group, the record with the shortest path is kept.
// Returns the number of deleted records.
func (r *Repository) DeduplicateRecordsBySource(ctx context.Context, projectUUID, source string) (int64, error) {
	projectUUID = defaultProjectUUID(projectUUID)

	// Use ROW_NUMBER window function to identify duplicates, keeping the
	// record with shortest path (then oldest created_at as tiebreaker).
	dupQuery := `
		SELECT uuid FROM (
			SELECT uuid, ROW_NUMBER() OVER (
				PARTITION BY hostname, method, status_code, response_content_length, response_hash
				ORDER BY LENGTH(path) ASC, created_at ASC
			) AS rn
			FROM http_records
			WHERE source = ?
			  AND project_uuid = ?
			  AND has_response = true
			  AND response_hash != ''
		) sub WHERE rn > 1`

	var uuids []string
	if err := r.db.NewRaw(dupQuery, source, projectUUID).Scan(ctx, &uuids); err != nil {
		return 0, fmt.Errorf("failed to identify duplicate %s records: %w", source, err)
	}

	if len(uuids) == 0 {
		return 0, nil
	}

	// Delete junction rows and records in a transaction (chunked IN lists).
	err := r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		return deleteRecordsByUUIDsTx(ctx, tx, uuids)
	})
	if err != nil {
		return 0, err
	}

	return int64(len(uuids)), nil
}

// DeduplicateDeparosRecords removes duplicate deparos HTTP records.
// Delegates to DeduplicateRecordsBySource with source "deparos".
func (r *Repository) DeduplicateDeparosRecords(ctx context.Context, projectUUID string) (int64, error) {
	return r.DeduplicateRecordsBySource(ctx, projectUUID, "deparos")
}

// DeduplicateSoftDeparosRecords removes deparos HTTP records that are "soft duplicates":
// same response characteristics (status, word count, content type) under the same
// 2-segment path prefix. This catches cases where the server echoes part of the URL in the
// response body, causing different response_hash values for functionally identical pages.
// Exact response_content_length is deliberately NOT part of the key: a reflected URL/path
// shifts the body length by a handful of bytes per probe, which would otherwise split an
// otherwise-identical family into singletons (the very case this pass exists to collapse) —
// word count + content type + status + path prefix is the stable shape signal.
// Only groups with 3+ members are collapsed. The shortest path per group is kept.
func (r *Repository) DeduplicateSoftDeparosRecords(ctx context.Context, projectUUID string) (int64, map[int]int64, error) {
	projectUUID = defaultProjectUUID(projectUUID)

	// Path prefix extraction: first 2 segments (SQLite/PG compatible).
	pathPrefix := `CASE
		WHEN INSTR(SUBSTR(path, 2), '/') = 0 THEN path
		WHEN INSTR(SUBSTR(path, INSTR(SUBSTR(path, 2), '/') + 2), '/') = 0 THEN path
		ELSE SUBSTR(path, 1, INSTR(SUBSTR(path, 2), '/') + INSTR(SUBSTR(path, INSTR(SUBSTR(path, 2), '/') + 2), '/'))
	END`

	dupQuery := fmt.Sprintf(`
		SELECT uuid FROM (
			SELECT uuid,
				ROW_NUMBER() OVER (
					PARTITION BY hostname, method, status_code,
						response_words, response_content_type, %s
					ORDER BY LENGTH(path) ASC, created_at ASC
				) AS rn,
				COUNT(*) OVER (
					PARTITION BY hostname, method, status_code,
						response_words, response_content_type, %s
				) AS group_size
			FROM http_records
			WHERE source = 'deparos'
			  AND project_uuid = ?
			  AND has_response = true
		) sub WHERE rn > 1 AND group_size >= 3`, pathPrefix, pathPrefix)

	var uuids []string
	if err := r.db.NewRaw(dupQuery, projectUUID).Scan(ctx, &uuids); err != nil {
		return 0, nil, fmt.Errorf("failed to identify soft-duplicate deparos records: %w", err)
	}

	if len(uuids) == 0 {
		return 0, nil, nil
	}
	statusCodes, err := r.deleteRecordsWithStatusBreakdown(ctx, uuids)
	if err != nil {
		return 0, nil, err
	}
	return int64(len(uuids)), statusCodes, nil
}

// ApplyDeparosStatusPolicy enforces the discovery status-retention policy on
// stored deparos records. A fuzzed path the server answers with a 4xx is not a
// discovered resource — it's a rejection (malformed/ambiguous path → 400,
// not-found → 404, forbidden → 403). Keeping one record per probed variant is
// pure noise, made worse when the error page echoes the requested URI: every
// variant then carries a distinct body, length, and hash, so they all survive
// the exact-hash dedup as separate records.
//
// It deletes every deparos record whose status is a client error (4xx) EXCEPT
// statuses in keepOnePerHost, which are instead collapsed to a single
// representative per (hostname, status_code) — the shortest path. keepOnePerHost
// is typically {401}: "an authenticated area exists here" is worth keeping, but
// one record per host is enough. Returns the number of deleted records and a
// status-code breakdown of them.
func (r *Repository) ApplyDeparosStatusPolicy(ctx context.Context, projectUUID string, keepOnePerHost []int) (int64, map[int]int64, error) {
	projectUUID = defaultProjectUUID(projectUUID)

	// De-dup the keep list so the IN clauses stay tidy.
	keepSeen := make(map[int]struct{}, len(keepOnePerHost))
	keepList := make([]int, 0, len(keepOnePerHost))
	for _, c := range keepOnePerHost {
		if _, ok := keepSeen[c]; ok {
			continue
		}
		keepSeen[c] = struct{}{}
		keepList = append(keepList, c)
	}

	uuidSet := make(map[string]struct{})

	// (1) Drop all 4xx that are not kept-one-per-host.
	dropQuery := `
		SELECT uuid FROM http_records
		WHERE source = 'deparos' AND project_uuid = ?
		  AND status_code >= 400 AND status_code < 500`
	dropArgs := []any{projectUUID}
	if len(keepList) > 0 {
		dropQuery += ` AND status_code NOT IN (?)`
		dropArgs = append(dropArgs, bun.List(keepList))
	}
	var dropUUIDs []string
	if err := r.db.NewRaw(dropQuery, dropArgs...).Scan(ctx, &dropUUIDs); err != nil {
		return 0, nil, fmt.Errorf("failed to identify client-error deparos records: %w", err)
	}
	for _, u := range dropUUIDs {
		uuidSet[u] = struct{}{}
	}

	// (2) Collapse kept statuses to a single representative per (host, status).
	if len(keepList) > 0 {
		collapseQuery := `
			SELECT uuid FROM (
				SELECT uuid, ROW_NUMBER() OVER (
					PARTITION BY hostname, status_code
					ORDER BY LENGTH(path) ASC, created_at ASC
				) AS rn
				FROM http_records
				WHERE source = 'deparos' AND project_uuid = ?
				  AND status_code IN (?)
			) sub WHERE rn > 1`
		var collapseUUIDs []string
		if err := r.db.NewRaw(collapseQuery, projectUUID, bun.List(keepList)).Scan(ctx, &collapseUUIDs); err != nil {
			return 0, nil, fmt.Errorf("failed to identify collapsible deparos records: %w", err)
		}
		for _, u := range collapseUUIDs {
			uuidSet[u] = struct{}{}
		}
	}

	if len(uuidSet) == 0 {
		return 0, nil, nil
	}
	uuids := make([]string, 0, len(uuidSet))
	for u := range uuidSet {
		uuids = append(uuids, u)
	}
	statusCodes, err := r.deleteRecordsWithStatusBreakdown(ctx, uuids)
	if err != nil {
		return 0, nil, err
	}
	return int64(len(uuids)), statusCodes, nil
}

// DeduplicateDeparosByNormHash collapses deparos records whose NORMALIZED
// response body is identical — records that differ only by a reflected request
// URL/path or per-request dynamic tokens (timestamps, ids). This is the case the
// exact (hostname, status, content_length, response_hash) dedup misses: an error
// or echo page that mirrors the requested URI gives every probed path a distinct
// body, length, and hash, so they all survive as separate records even though
// they are the same page. response_norm_hash (computed at storage time with the
// reflected URL/path stripped and dynamic runs collapsed) makes them identical.
//
// Grouping is on (hostname, method, status_code, response_content_type,
// response_norm_hash); the shortest path per group survives. Records with no
// normalized hash (empty bodies) are left to exact-hash dedup. Returns the number
// of deleted records and a status-code breakdown.
func (r *Repository) DeduplicateDeparosByNormHash(ctx context.Context, projectUUID string) (int64, map[int]int64, error) {
	projectUUID = defaultProjectUUID(projectUUID)

	dupQuery := `
		SELECT uuid FROM (
			SELECT uuid, ROW_NUMBER() OVER (
				PARTITION BY hostname, method, status_code, response_content_type, response_norm_hash
				ORDER BY LENGTH(path) ASC, created_at ASC
			) AS rn
			FROM http_records
			WHERE source = 'deparos'
			  AND project_uuid = ?
			  AND has_response = true
			  AND response_norm_hash IS NOT NULL
			  AND response_norm_hash != ''
		) sub WHERE rn > 1`

	var uuids []string
	if err := r.db.NewRaw(dupQuery, projectUUID).Scan(ctx, &uuids); err != nil {
		return 0, nil, fmt.Errorf("failed to identify reflected-URL-duplicate deparos records: %w", err)
	}
	if len(uuids) == 0 {
		return 0, nil, nil
	}
	statusCodes, err := r.deleteRecordsWithStatusBreakdown(ctx, uuids)
	if err != nil {
		return 0, nil, err
	}
	return int64(len(uuids)), statusCodes, nil
}

// deleteRecordsWithStatusBreakdown counts the to-be-deleted records by status
// code (for operator feedback), then deletes them and their finding_records
// junction rows in one transaction. Shared by the deparos record-dedup passes.
func (r *Repository) deleteRecordsWithStatusBreakdown(ctx context.Context, uuids []string) (map[int]int64, error) {
	if len(uuids) == 0 {
		return nil, nil
	}
	type statusCount struct {
		StatusCode int   `bun:"status_code"`
		Count      int64 `bun:"cnt"`
	}
	statusCodes := make(map[int]int64)
	for chunk := range slices.Chunk(uuids, dedupDeleteChunk) {
		var counts []statusCount
		if err := r.db.NewRaw(
			"SELECT status_code, COUNT(*) AS cnt FROM http_records WHERE uuid IN (?) GROUP BY status_code",
			bun.List(chunk),
		).Scan(ctx, &counts); err != nil {
			zap.L().Debug("Failed to collect status code stats for dedup", zap.Error(err))
		}
		for _, c := range counts {
			statusCodes[c.StatusCode] += c.Count
		}
	}

	err := r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		return deleteRecordsByUUIDsTx(ctx, tx, uuids)
	})
	if err != nil {
		return nil, err
	}
	return statusCodes, nil
}

// findingHostnameFilter builds an optional "AND hostname IN (?)" SQL fragment and
// its bind argument(s) for scoping a findings query to a set of hostnames. The
// fragment is empty (project-wide) for an empty/all-blank list, so callers can
// always concatenate it immediately after the project_uuid predicate. Scoping the
// per-round dynamic-assessment dedup to the hosts being scanned keeps it from
// re-scanning the whole project's findings table every feedback round — which is
// what makes a long scan with a big findings table O(rounds × table) instead of
// O(rounds × this-scan's-hosts).
func findingHostnameFilter(hostnames []string) (string, []any) {
	seen := make(map[string]struct{}, len(hostnames))
	clean := make([]string, 0, len(hostnames))
	for _, h := range hostnames {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		clean = append(clean, h)
	}
	if len(clean) == 0 {
		return "", nil
	}
	return " AND hostname IN (?)", []any{bun.List(clean)}
}

// findingBody holds a finding's heavy request/response body text, loaded in the
// two-pass dedup passes' second pass.
type findingBody struct {
	ID       int64  `bun:"id"`
	Request  string `bun:"request"`
	Response string `bun:"response"`
}

// loadFindingBodies fetches the request/response body text for the given finding
// IDs, keyed by ID. It is the shared "pass 2" of the two-pass dedup passes
// (DeduplicateFindings / GroupFindingsByValue), which defer body loads to the
// few findings in groups that actually have duplicates.
func (r *Repository) loadFindingBodies(ctx context.Context, ids []int64) (map[int64]findingBody, error) {
	m := make(map[int64]findingBody, len(ids))
	// Chunk the IN list: ids here is the survivor + every duplicate id (a
	// superset of the delete set), so it can exceed the bound-parameter limit on
	// the same large dedups the delete legs chunk for.
	for chunk := range slices.Chunk(ids, dedupDeleteChunk) {
		var rows []findingBody
		if err := r.db.NewSelect().Model((*Finding)(nil)).
			Column("id", "request", "response").
			Where("id IN (?)", bun.List(chunk)).
			Scan(ctx, &rows); err != nil {
			return nil, err
		}
		for _, br := range rows {
			m[br.ID] = br
		}
	}
	return m, nil
}

// DeduplicateFindings merges duplicate findings that share the same
// (module_id, severity, matched_at URL) within a project. This collapses
// findings where the same module fires many times on the same URL with different
// payloads (e.g., input-behavior-probe producing dozens of results per endpoint).
// Within each group, the earliest finding is kept and the request/response pairs
// from duplicates are collected into its AdditionalEvidence field.
//
// When one or more hostnames are passed, the pass is scoped to findings on those
// hosts (an empty/omitted list dedupes the whole project). The dynamic-assessment
// feedback loop scopes each round to the hosts being scanned — coverage-equivalent
// there, since every finding produced during DA is on an in-scope host — so a
// growing findings table isn't full-scanned once per round.
// Returns the count of deleted findings and the number of groups that were merged.
func (r *Repository) DeduplicateFindings(ctx context.Context, projectUUID string, hostnames ...string) (deleted int64, grouped int64, err error) {
	projectUUID = defaultProjectUUID(projectUUID)
	hostFilter, hostArgs := findingHostnameFilter(hostnames)

	// Pass 1 — identify duplicate groups WITHOUT loading the heavy request/response
	// body columns. Most findings are singletons (no duplicate), so loading their
	// bodies here would be pure waste, repeated every feedback round. We fetch only
	// id, rn, group_key, and the (small) additional_evidence jsonb.
	//
	// The matched URL is extracted once in a CTE rather than evaluating
	// json_extract(matched_at, '$[0]') twice (PARTITION BY + group_key) per row —
	// SQLite does not common-subexpression-eliminate across a query.
	groupQuery := `
		WITH base AS (
			SELECT id, additional_evidence, module_id, severity, created_at,
			       json_extract(matched_at, '$[0]') AS matched_url
			FROM findings
			WHERE project_uuid = ?` + hostFilter + `
			  AND matched_at IS NOT NULL
			  AND matched_at != '[]'
			  AND matched_at != ''
			  AND module_id != '` + secretDetectModuleID + `'
		)
		SELECT id, additional_evidence, ROW_NUMBER() OVER (
			PARTITION BY module_id, severity, matched_url
			ORDER BY created_at ASC
		) AS rn,
		-- Stable group key for matching survivors to duplicates
		module_id || '|' || severity || '|' || COALESCE(matched_url, '') AS group_key
		FROM base`

	type findingRow struct {
		ID                 int64    `bun:"id"`
		AdditionalEvidence []string `bun:"additional_evidence,type:jsonb"`
		RN                 int64    `bun:"rn"`
		GroupKey           string   `bun:"group_key"`
	}

	queryArgs := append([]any{projectUUID}, hostArgs...)
	var rows []findingRow
	if err := r.db.NewRaw(groupQuery, queryArgs...).Scan(ctx, &rows); err != nil {
		return 0, 0, fmt.Errorf("failed to identify duplicate findings: %w", err)
	}

	type dupRow struct {
		id       int64
		evidence []string
	}
	type groupData struct {
		survivorID       int64
		survivorRequest  string
		survivorResponse string
		existingEvidence []string
		newEvidence      []string
		dups             []dupRow
	}
	// Group count is bounded by row count; sizing up front avoids rehashing.
	groups := make(map[string]*groupData, len(rows))
	for _, row := range rows {
		g, ok := groups[row.GroupKey]
		if !ok {
			g = &groupData{}
			groups[row.GroupKey] = g
		}
		if row.RN == 1 {
			g.survivorID = row.ID
			g.existingEvidence = row.AdditionalEvidence
		} else {
			g.dups = append(g.dups, dupRow{id: row.ID, evidence: row.AdditionalEvidence})
		}
	}

	// Collect the groups that actually have duplicates, plus the finding IDs whose
	// bodies we must load (each dup group's survivor + its duplicates).
	var allDupIDs []int64
	var bodyIDs []int64
	var groupCount int64
	dupGroups := make([]*groupData, 0)
	for _, g := range groups {
		if len(g.dups) == 0 {
			continue
		}
		groupCount++
		dupGroups = append(dupGroups, g)
		bodyIDs = append(bodyIDs, g.survivorID)
		for _, d := range g.dups {
			allDupIDs = append(allDupIDs, d.id)
			bodyIDs = append(bodyIDs, d.id)
		}
	}

	if len(allDupIDs) == 0 {
		return 0, 0, nil
	}

	// Pass 2 — load request/response bodies only for findings in groups that have
	// duplicates, then build the merged evidence.
	bodyByID, err := r.loadFindingBodies(ctx, bodyIDs)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to load finding bodies for dedup: %w", err)
	}
	for _, g := range dupGroups {
		sb := bodyByID[g.survivorID]
		g.survivorRequest = sb.Request
		g.survivorResponse = sb.Response
		// Pre-size: each dup contributes at most its own buildEvidence string
		// plus any evidence it already carried.
		evCap := 0
		for _, d := range g.dups {
			evCap += 1 + len(d.evidence)
		}
		g.newEvidence = make([]string, 0, evCap)
		for _, d := range g.dups {
			db := bodyByID[d.id]
			if ev := buildEvidence(db.Request, db.Response); ev != "" {
				g.newEvidence = append(g.newEvidence, ev)
			}
			// Carry forward any evidence the duplicate already had.
			g.newEvidence = append(g.newEvidence, d.evidence...)
		}
	}

	// Update survivors with merged evidence, then delete duplicates.
	err = r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		for _, g := range dupGroups {
			if len(g.newEvidence) == 0 {
				continue
			}
			primary := buildEvidence(g.survivorRequest, g.survivorResponse)
			merged := appendUniqueEvidence(g.existingEvidence, primary, g.newEvidence...)
			if len(merged) == len(g.existingEvidence) {
				continue // nothing new after dropping duplicates of the primary pair
			}
			if len(merged) > maxAdditionalEvidence {
				merged = merged[:maxAdditionalEvidence]
			}
			if _, err := tx.NewUpdate().Model((*Finding)(nil)).
				Set("additional_evidence = ?", merged).
				Where("id = ?", g.survivorID).
				Exec(ctx); err != nil {
				return fmt.Errorf("failed to update survivor evidence: %w", err)
			}
		}
		return deleteFindingsByIDsTx(ctx, tx, allDupIDs)
	})
	if err != nil {
		return 0, 0, err
	}

	return int64(len(allDupIDs)), groupCount, nil
}

// GroupFindingOptions configures value-based finding grouping (see
// GroupFindingsByValue).
type GroupFindingOptions struct {
	// PerHost groups within each hostname — a value seen on two hosts stays two
	// findings. When false, grouping is project-wide regardless of host.
	PerHost bool
	// Tags, when non-empty, restricts grouping to findings carrying at least one
	// matching tag (case-insensitive).
	Tags []string
	// ByModule lists module IDs whose findings collapse to a single finding per
	// (module, severity[, host]) regardless of the per-URL extracted value — for
	// modules that fire once per asset (e.g. sourcemap-detect, one .map filename
	// per JS bundle). These bypass the value-identity requirement and the Tags
	// gate; module + severity is the guardrail.
	ByModule []string
	// ByRule lists module IDs whose findings collapse per (module, rule_name,
	// severity[, host]) regardless of value — like ByModule, but the rule
	// (module_name) stays part of the key, so DISTINCT rules remain distinct
	// findings while repeats of the SAME rule fold together. This is for
	// secret-detect, whose one module_id carries many rule_names (Kingfisher
	// rules): a "Looker Client ID" rule matching every chunk hash in a minified
	// bundle's content-hash map yields dozens of identical findings differing only
	// by value, which collapse to one finding (all values unioned on), while a
	// genuinely different secret — an AWS key, a Slack token — keeps its own row.
	ByRule []string
	// MaxURLs caps the merged matched-URL list on the survivor (0 = unlimited).
	MaxURLs int
	// Hostnames, when non-empty, scopes the pass to findings on those hosts. The
	// dynamic-assessment feedback loop sets it to the hosts being scanned so a
	// growing findings table isn't loaded in full each round. Empty = project-wide.
	Hostnames []string
}

// GroupFindingsByValue collapses findings that share an identical extracted value
// (e.g. the same leaked secret reported once per URL) into a single finding. The
// survivor (earliest by created_at) absorbs every duplicate's matched URLs into
// MatchedAt and a sample of their request/response pairs into AdditionalEvidence;
// the duplicates are then deleted. Grouping is keyed on
// (module_id, severity[, hostname], normalized extracted_results) — the value
// must match byte-for-byte, so findings with distinct or empty extracted values
// are never merged.
//
// Modules listed in opts.ByModule are an exception: their findings collapse on
// (module_id, severity[, hostname]) alone, regardless of (or absent) an extracted
// value, and skip the Tags gate. This is for modules that fire once per asset
// where the per-URL value is noise (e.g. sourcemap-detect, a distinct .map
// filename per JS bundle).
//
// Modules listed in opts.ByRule collapse on (module_id, rule_name, severity[,
// hostname]) — the same as ByModule but with the rule (module_name) kept in the
// key, so a module whose single id fronts many rules (secret-detect) folds
// repeats of one rule while keeping different rules apart. Their distinct values
// are unioned onto the survivor just like ByModule.
//
// Returns the count of deleted findings and the number of groups that were
// collapsed.
func (r *Repository) GroupFindingsByValue(ctx context.Context, projectUUID string, opts GroupFindingOptions) (deleted int64, grouped int64, err error) {
	projectUUID = defaultProjectUUID(projectUUID)

	// Pass 1 loads grouping inputs WITHOUT the heavy request/response body columns;
	// they are fetched in pass 2 only for groups that actually have duplicates.
	type findingRow struct {
		ID                 int64    `bun:"id"`
		Hostname           string   `bun:"hostname"`
		ModuleID           string   `bun:"module_id"`
		ModuleName         string   `bun:"module_name"`
		Severity           string   `bun:"severity"`
		Description        string   `bun:"description"`
		MatchedAt          []string `bun:"matched_at,type:jsonb"`
		ExtractedResults   []string `bun:"extracted_results,type:jsonb"`
		Tags               []string `bun:"tags,type:jsonb"`
		AdditionalEvidence []string `bun:"additional_evidence,type:jsonb"`
	}

	// Only findings with a non-empty extracted value can be value-grouped — except
	// by-module and by-rule modules, which group regardless of value (so they are
	// pulled in even with an empty extracted_results). Order by created_at so the
	// earliest finding in each group becomes the survivor.
	byModule := output.NormalizeStringSet(opts.ByModule)
	byRule := output.NormalizeStringSet(opts.ByRule)
	const valueCond = "(extracted_results IS NOT NULL AND extracted_results != '[]' AND extracted_results != '')"
	where := valueCond
	queryArgs := []any{projectUUID}
	// Host scope binds right after project_uuid so its placeholder precedes the
	// optional module_id IN (?) below — keep the arg order matching the SQL text.
	hostFilter, hostArgs := findingHostnameFilter(opts.Hostnames)
	queryArgs = append(queryArgs, hostArgs...)
	// By-module and by-rule modules both bypass the value condition (their value is
	// noise or merely a sub-key), so pull them in even with an empty value. A
	// module listed under both lands in the IN clause twice, which is harmless.
	moduleList := make([]string, 0, len(byModule)+len(byRule))
	for id := range byModule {
		moduleList = append(moduleList, id)
	}
	for id := range byRule {
		moduleList = append(moduleList, id)
	}
	if len(moduleList) > 0 {
		where = "(" + valueCond + " OR module_id IN (?))"
		queryArgs = append(queryArgs, bun.List(moduleList))
	}
	loadQuery := `
		SELECT id, hostname, module_id, module_name, severity, description, matched_at, extracted_results, tags,
		       additional_evidence
		FROM findings
		WHERE project_uuid = ?` + hostFilter + ` AND ` + where + `
		ORDER BY created_at ASC, id ASC`

	var rows []findingRow
	if err := r.db.NewRaw(loadQuery, queryArgs...).Scan(ctx, &rows); err != nil {
		return 0, 0, fmt.Errorf("failed to load findings for value grouping: %w", err)
	}

	tagFilter := output.NormalizeTagSet(opts.Tags)

	type dupRow struct {
		id       int64
		evidence []string
	}
	type groupData struct {
		survivorID          int64
		survivorRequest     string // filled in pass 2
		survivorResponse    string // filled in pass 2
		survivorDescription string
		survivorMatched     []string
		survivorExtracted   []string
		existingEvidence    []string
		dupEvidence         []string // filled in pass 2
		extraMatched        []string
		extraExtracted      []string
		dups                []dupRow
		// mergeValues marks a group collapsed regardless of value — a by-module
		// group (keyed on module+severity) or a by-rule group (keyed on
		// module+rule+severity). Only these merge the differing per-URL extracted
		// values onto the survivor; plain value groups share an identical value, so
		// there is nothing to merge.
		mergeValues bool
	}
	groups := make(map[string]*groupData)
	var order []string

	for i := range rows {
		row := &rows[i]
		moduleKey, valueKey, groupable := output.GroupingBranch(
			row.ModuleID, row.ModuleName, output.NormalizedValueKey(row.ExtractedResults), row.Tags, byModule, byRule, tagFilter)
		if !groupable {
			continue
		}
		// An emptied value key marks a by-module/by-rule group — every value folds
		// into one finding, so the distinct values are unioned onto the survivor.
		mergeValues := valueKey == ""
		key := output.GroupingKey(moduleKey, row.Severity, valueKey, row.Hostname, opts.PerHost)
		g, ok := groups[key]
		if !ok {
			groups[key] = &groupData{
				survivorID:          row.ID,
				survivorDescription: row.Description,
				survivorMatched:     row.MatchedAt,
				survivorExtracted:   row.ExtractedResults,
				existingEvidence:    row.AdditionalEvidence,
				mergeValues:         mergeValues,
			}
			order = append(order, key)
			continue
		}
		// Duplicate: fold its URLs and evidence into the survivor (body-derived
		// evidence is built in pass 2).
		g.dups = append(g.dups, dupRow{id: row.ID, evidence: row.AdditionalEvidence})
		g.extraMatched = append(g.extraMatched, row.MatchedAt...)
		// For by-module/by-rule groups the differing values are signal the operator
		// wants to keep — union them onto the survivor so the collapsed finding lists
		// every matched value, not just the first occurrence's.
		if g.mergeValues {
			g.extraExtracted = append(g.extraExtracted, row.ExtractedResults...)
		}
	}

	// Collect duplicates and the finding IDs whose bodies pass 2 must load.
	var allDupIDs []int64
	var bodyIDs []int64
	for _, key := range order {
		g := groups[key]
		if len(g.dups) == 0 {
			continue
		}
		grouped++
		bodyIDs = append(bodyIDs, g.survivorID)
		for _, d := range g.dups {
			allDupIDs = append(allDupIDs, d.id)
			bodyIDs = append(bodyIDs, d.id)
		}
	}
	if len(allDupIDs) == 0 {
		return 0, 0, nil
	}

	// Pass 2 — load request/response bodies only for dup-group members and build
	// the survivor's body-derived evidence.
	bodyByID, err := r.loadFindingBodies(ctx, bodyIDs)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to load finding bodies for value grouping: %w", err)
	}
	for _, key := range order {
		g := groups[key]
		if len(g.dups) == 0 {
			continue
		}
		sb := bodyByID[g.survivorID]
		g.survivorRequest = sb.Request
		g.survivorResponse = sb.Response
		for _, d := range g.dups {
			db := bodyByID[d.id]
			if ev := buildEvidence(db.Request, db.Response); ev != "" {
				g.dupEvidence = append(g.dupEvidence, ev)
			}
			g.dupEvidence = append(g.dupEvidence, d.evidence...)
		}
	}

	err = r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		for _, key := range order {
			g := groups[key]
			if len(g.dups) == 0 {
				continue
			}
			mergedMatched := mergeUniqueStrings(g.survivorMatched, g.extraMatched)
			if opts.MaxURLs > 0 && len(mergedMatched) > opts.MaxURLs {
				mergedMatched = mergedMatched[:opts.MaxURLs]
			}
			primary := buildEvidence(g.survivorRequest, g.survivorResponse)
			mergedEvidence := appendUniqueEvidence(g.existingEvidence, primary, g.dupEvidence...)
			if len(mergedEvidence) > maxAdditionalEvidence {
				mergedEvidence = mergedEvidence[:maxAdditionalEvidence]
			}
			upd := tx.NewUpdate().Model((*Finding)(nil)).Where("id = ?", g.survivorID)
			if len(mergedMatched) > 0 {
				upd = upd.Set("matched_at = ?", mergedMatched)
			}
			if len(mergedEvidence) > 0 {
				upd = upd.Set("additional_evidence = ?", mergedEvidence)
			}
			// By-module/by-rule groups: merge the distinct extracted values onto the
			// survivor (bounded by MaxURLs) and note the rollup in the description so
			// the collapsed finding reflects every occurrence, not just the first.
			if g.mergeValues {
				mergedExtracted := filterEmpty(mergeUniqueStrings(g.survivorExtracted, g.extraExtracted))
				if opts.MaxURLs > 0 && len(mergedExtracted) > opts.MaxURLs {
					mergedExtracted = mergedExtracted[:opts.MaxURLs]
				}
				if len(mergedExtracted) > 0 {
					upd = upd.Set("extracted_results = ?", mergedExtracted)
				}
				if desc := withGroupRollup(g.survivorDescription, len(mergedMatched), len(mergedExtracted)); desc != "" {
					upd = upd.Set("description = ?", desc)
				}
			}
			if _, err := upd.Exec(ctx); err != nil {
				return fmt.Errorf("failed to update grouped survivor: %w", err)
			}
		}
		return deleteFindingsByIDsTx(ctx, tx, allDupIDs)
	})
	if err != nil {
		return 0, 0, err
	}

	return int64(len(allDupIDs)), grouped, nil
}

// groupRollupMarker delimits the appended rollup note on a by-module grouped
// survivor's description. It is a stable sentinel so re-running the grouping pass
// (each phase calls it) rewrites the note in place rather than stacking it.
const groupRollupMarker = "· grouped:"

// withGroupRollup returns desc with a trailing note summarising how far a by-module
// survivor was collapsed (distinct URLs and values it now represents). Any prior
// note from an earlier pass is stripped first so the result stays idempotent.
func withGroupRollup(desc string, urlCount, valueCount int) string {
	base := desc
	if i := strings.Index(base, groupRollupMarker); i >= 0 {
		base = base[:i]
	}
	base = strings.TrimRight(base, " ")
	if urlCount <= 0 && valueCount <= 0 {
		return base
	}
	note := fmt.Sprintf("collapsed across %d URL(s)", urlCount)
	if valueCount > 1 {
		note += fmt.Sprintf(", %d distinct value(s)", valueCount)
	}
	prefix := ""
	if base != "" {
		prefix = base + " "
	}
	return prefix + groupRollupMarker + " " + note
}

// filterEmpty drops empty/whitespace-only strings, preserving order.
func filterEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}
