package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/uptrace/bun"

	"go.uber.org/zap"
)

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

	// Delete junction rows and records in a transaction
	err := r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		// Clean up finding_records junction rows
		if _, err := tx.NewRaw("DELETE FROM finding_records WHERE record_uuid IN (?)", bun.In(uuids)).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding_records: %w", err)
		}
		// Delete the duplicate records
		if _, err := tx.NewDelete().Model((*HTTPRecord)(nil)).Where("uuid IN (?)", bun.In(uuids)).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete duplicate records: %w", err)
		}
		return nil
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
// same response characteristics (status, size, word count, content type) under the same
// 2-segment path prefix. This catches cases where the server echoes part of the URL in the
// response body, causing different response_hash values for functionally identical pages.
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
					PARTITION BY hostname, method, status_code, response_content_length,
						response_words, response_content_type, %s
					ORDER BY LENGTH(path) ASC, created_at ASC
				) AS rn,
				COUNT(*) OVER (
					PARTITION BY hostname, method, status_code, response_content_length,
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

	// Collect status code breakdown before deleting
	type statusCount struct {
		StatusCode int   `bun:"status_code"`
		Count      int64 `bun:"cnt"`
	}
	var counts []statusCount
	if err := r.db.NewRaw(
		"SELECT status_code, COUNT(*) AS cnt FROM http_records WHERE uuid IN (?) GROUP BY status_code",
		bun.In(uuids),
	).Scan(ctx, &counts); err != nil {
		zap.L().Debug("Failed to collect status code stats for soft-dedup", zap.Error(err))
	}
	statusCodes := make(map[int]int64, len(counts))
	for _, c := range counts {
		statusCodes[c.StatusCode] = c.Count
	}

	err := r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		if _, err := tx.NewRaw("DELETE FROM finding_records WHERE record_uuid IN (?)", bun.In(uuids)).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding_records: %w", err)
		}
		if _, err := tx.NewDelete().Model((*HTTPRecord)(nil)).Where("uuid IN (?)", bun.In(uuids)).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete soft-duplicate records: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}

	return int64(len(uuids)), statusCodes, nil
}

// DeduplicateFindings merges duplicate findings that share the same
// (module_id, severity, matched_at URL) within a project. This collapses
// findings where the same module fires many times on the same URL with different
// payloads (e.g., input-behavior-probe producing dozens of results per endpoint).
// Within each group, the earliest finding is kept and the request/response pairs
// from duplicates are collected into its AdditionalEvidence field.
// Returns the count of deleted findings and the number of groups that were merged.
func (r *Repository) DeduplicateFindings(ctx context.Context, projectUUID string) (deleted int64, grouped int64, err error) {
	projectUUID = defaultProjectUUID(projectUUID)

	// Identify duplicate groups: for each group, get the survivor (rn=1) and duplicates (rn>1).
	groupQuery := `
		SELECT id, request, response, additional_evidence, ROW_NUMBER() OVER (
			PARTITION BY module_id, severity, json_extract(matched_at, '$[0]')
			ORDER BY created_at ASC
		) AS rn,
		-- Stable group key for matching survivors to duplicates
		module_id || '|' || severity || '|' || COALESCE(json_extract(matched_at, '$[0]'), '') AS group_key
		FROM findings
		WHERE project_uuid = ?
		  AND matched_at IS NOT NULL
		  AND matched_at != '[]'
		  AND matched_at != ''`

	type findingRow struct {
		ID                 int64    `bun:"id"`
		Request            string   `bun:"request"`
		Response           string   `bun:"response"`
		AdditionalEvidence []string `bun:"additional_evidence,type:jsonb"`
		RN                 int64    `bun:"rn"`
		GroupKey           string   `bun:"group_key"`
	}

	var rows []findingRow
	if err := r.db.NewRaw(groupQuery, projectUUID).Scan(ctx, &rows); err != nil {
		return 0, 0, fmt.Errorf("failed to identify duplicate findings: %w", err)
	}

	// Build survivor map and collect evidence from duplicates per group.
	type groupData struct {
		survivorID       int64
		existingEvidence []string
		newEvidence      []string
		dupIDs           []int64
	}
	groups := make(map[string]*groupData)
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
			g.dupIDs = append(g.dupIDs, row.ID)
			ev := buildEvidence(row.Request, row.Response)
			if ev != "" {
				g.newEvidence = append(g.newEvidence, ev)
			}
			// Carry forward any evidence the duplicate already had.
			g.newEvidence = append(g.newEvidence, row.AdditionalEvidence...)
		}
	}

	// Collect all duplicate IDs and count groups that actually had duplicates.
	var allDupIDs []int64
	var groupCount int64
	for _, g := range groups {
		if len(g.dupIDs) == 0 {
			continue
		}
		groupCount++
		allDupIDs = append(allDupIDs, g.dupIDs...)
	}

	if len(allDupIDs) == 0 {
		return 0, 0, nil
	}

	// Update survivors with merged evidence, then delete duplicates.
	err = r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		for _, g := range groups {
			if len(g.newEvidence) == 0 {
				continue
			}
			merged := append(g.existingEvidence, g.newEvidence...)
			const maxAdditionalEvidence = 10
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
		if _, err := tx.NewRaw("DELETE FROM finding_records WHERE finding_id IN (?)", bun.In(allDupIDs)).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding_records: %w", err)
		}
		if _, err := tx.NewDelete().Model((*Finding)(nil)).Where("id IN (?)", bun.In(allDupIDs)).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete duplicate findings: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}

	return int64(len(allDupIDs)), groupCount, nil
}
