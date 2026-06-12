package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/uptrace/bun"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// SaveRecord stores a denormalized HTTP record (request + response + host + parameters).
// The source identifies the origin of the record (e.g. "scanner", "ingest-cli", "ingest-server", "ingest-proxy").
// Returns the UUID of the saved record. If a matching record already exists (same method,
// hostname, path, URL, and request body), the existing UUID is returned without inserting.
func (r *Repository) SaveRecord(ctx context.Context, httpRR *httpmsg.HttpRequestResponse, source string, projectUUID string) (string, error) {
	if httpRR == nil || httpRR.Request() == nil {
		return "", fmt.Errorf("invalid HttpRequestResponse")
	}

	record := &HTTPRecord{}
	if err := record.FromHttpRequestResponse(httpRR); err != nil {
		return "", fmt.Errorf("failed to convert request: %w", err)
	}
	record.Source = source
	record.ProjectUUID = defaultProjectUUID(projectUUID)

	if existingUUID, err := r.findDuplicateRecord(ctx, record); err == nil && existingUUID != "" {
		return existingUUID, nil
	}

	if _, err := r.db.NewInsert().Model(record).Exec(ctx); err != nil {
		return "", fmt.Errorf("failed to insert record: %w", err)
	}

	return record.UUID, nil
}

// findDuplicateRecord checks whether a record with the same method, hostname,
// path, and URL already exists. For requests with a body, the request_hash is
// also compared to distinguish different payloads to the same endpoint.
func (r *Repository) findDuplicateRecord(ctx context.Context, record *HTTPRecord) (string, error) {
	var existingUUID string
	q := r.db.NewSelect().
		Model((*HTTPRecord)(nil)).
		Column("uuid").
		Where("project_uuid = ?", record.ProjectUUID).
		Where("method = ?", record.Method).
		Where("hostname = ?", record.Hostname).
		Where("path = ?", record.Path).
		Where("url = ?", record.URL).
		Limit(1)

	if record.RequestContentLength > 0 {
		q = q.Where("request_hash = ?", record.RequestHash)
	}

	err := q.Scan(ctx, &existingUUID)
	return existingUUID, err
}

// SaveRecordBatch converts httpmsg.HttpRequestResponse objects to HTTPRecord models and
// batch-inserts them. This is the high-level batch equivalent of SaveRecord.
func (r *Repository) SaveRecordBatch(ctx context.Context, records []*httpmsg.HttpRequestResponse, source string, projectUUID string) ([]string, error) {
	if len(records) == 0 {
		return nil, nil
	}

	projectUUID = defaultProjectUUID(projectUUID)
	dbRecords := make([]*HTTPRecord, 0, len(records))

	for _, rr := range records {
		rec := &HTTPRecord{}
		if err := rec.FromHttpRequestResponse(rr); err != nil {
			zap.L().Debug("SaveRecordBatch: skipping record", zap.Error(err))
			continue
		}
		rec.Source = source
		rec.ProjectUUID = projectUUID
		dbRecords = append(dbRecords, rec)
	}

	return r.SaveRecordsBatch(ctx, dbRecords)
}

// SaveRecordsBatch inserts multiple HTTP records in a single transaction.
// Returns the UUIDs of all successfully inserted records.
func (r *Repository) SaveRecordsBatch(ctx context.Context, records []*HTTPRecord) ([]string, error) {
	if len(records) == 0 {
		return nil, nil
	}

	for _, rec := range records {
		rec.ProjectUUID = defaultProjectUUID(rec.ProjectUUID)
	}

	err := r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		_, err := tx.NewInsert().Model(&records).Exec(ctx)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("failed to batch insert %d records: %w", len(records), err)
	}

	uuids := make([]string, len(records))
	for i, rec := range records {
		uuids[i] = rec.UUID
	}
	return uuids, nil
}

// GetRecordByUUID retrieves a single HTTP record by UUID
func (r *Repository) GetRecordByUUID(ctx context.Context, uuid string) (*HTTPRecord, error) {
	record := &HTTPRecord{}
	err := r.db.NewSelect().
		Model(record).
		Where("uuid = ?", uuid).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return record, nil
}

// GetRecordByRequestHash retrieves the most recent HTTP record whose raw request
// hashes to requestHash (the SHA-256 over the raw request bytes, matching
// httpmsg.HttpRequest.ID). It recovers the originating request for an
// out-of-band (OAST) finding when the in-memory hash→UUID resolver is no longer
// available — e.g. a callback that lands after the executor that planted the
// payload has been torn down. projectUUID may be empty to search across projects.
func (r *Repository) GetRecordByRequestHash(ctx context.Context, projectUUID, requestHash string) (*HTTPRecord, error) {
	if requestHash == "" {
		return nil, sql.ErrNoRows
	}
	record := &HTTPRecord{}
	q := r.db.NewSelect().
		Model(record).
		Where("request_hash = ?", requestHash).
		Order("created_at DESC").
		Limit(1)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, err
	}
	return record, nil
}

// GetRecordsByHostname retrieves HTTP records for a hostname within a project.
func (r *Repository) GetRecordsByHostname(ctx context.Context, projectUUID, hostname string, limit int) ([]*HTTPRecord, error) {
	var records []*HTTPRecord
	q := r.db.NewSelect().
		Model(&records).
		Where("hostname = ?", hostname).
		Order("sent_at DESC").
		Limit(limit)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	err := q.Scan(ctx)
	if err != nil {
		return nil, err
	}
	return records, nil
}

// GetUnprobedRecordsBySource returns records with has_response=false for the given source and hostname.
func (r *Repository) GetUnprobedRecordsBySource(ctx context.Context, projectUUID, source, hostname string, limit int) ([]*HTTPRecord, error) {
	var records []*HTTPRecord
	q := r.db.NewSelect().
		Model(&records).
		Where("source = ?", source).
		Where("hostname = ?", hostname).
		Where("has_response = ?", false).
		Order("created_at ASC").
		Limit(limit)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	err := q.Scan(ctx)
	if err != nil {
		return nil, err
	}
	return records, nil
}

// GetRecordsByUUIDs retrieves HTTP records matching the given UUIDs.
func (r *Repository) GetRecordsByUUIDs(ctx context.Context, uuids []string) ([]*HTTPRecord, error) {
	if len(uuids) == 0 {
		return nil, nil
	}
	var records []*HTTPRecord
	err := r.db.NewSelect().
		Model(&records).
		Where("uuid IN (?)", bun.List(uuids)).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get records by UUIDs: %w", err)
	}
	return records, nil
}

// GetRelatedRecords finds HTTP records with the same hostname and a path
// matching the path-template of the given UUID's record.
// Default limit 10; excludes the source record itself.
// Results are filtered to the same path depth as the source record.
func (r *Repository) GetRelatedRecords(ctx context.Context, uuid string, limit int) ([]*HTTPRecord, error) {
	source, err := r.GetRecordByUUID(ctx, uuid)
	if err != nil {
		return nil, fmt.Errorf("GetRelatedRecords: failed to get source record: %w", err)
	}

	if limit <= 0 {
		limit = 10
	}

	template := PathToTemplate(source.Path)
	likePattern := strings.ReplaceAll(template, "*", "%")

	// Fetch more than the limit to allow post-filter by path depth
	fetchLimit := limit * 3
	if fetchLimit < 30 {
		fetchLimit = 30
	}

	var candidates []*HTTPRecord
	err = r.db.NewSelect().
		Model(&candidates).
		Where("hostname = ?", source.Hostname).
		Where("path LIKE ?", likePattern).
		Where("uuid != ?", uuid).
		Order("created_at DESC").
		Limit(fetchLimit).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetRelatedRecords: query failed: %w", err)
	}

	// Filter to same path depth to avoid matching sub-resources
	sourceDepth := strings.Count(source.Path, "/")
	records := make([]*HTTPRecord, 0, limit)
	for _, rec := range candidates {
		if strings.Count(rec.Path, "/") == sourceDepth {
			records = append(records, rec)
			if len(records) >= limit {
				break
			}
		}
	}
	return records, nil
}

// UpdateRecordAnnotations updates the risk_score and/or remarks of an HTTP record.
// Only non-nil fields are updated. Returns an error if no record matches the UUID.
func (r *Repository) UpdateRecordAnnotations(ctx context.Context, uuid string, riskScore *int, remarks []string) error {
	q := r.db.NewUpdate().
		Model((*HTTPRecord)(nil)).
		Where("uuid = ?", uuid)

	setCount := 0
	if riskScore != nil {
		q = q.Set("risk_score = ?", *riskScore)
		setCount++
	}
	if remarks != nil {
		remarksJSON, err := json.Marshal(remarks)
		if err != nil {
			return fmt.Errorf("UpdateRecordAnnotations: failed to marshal remarks: %w", err)
		}
		q = q.Set("remarks = ?", string(remarksJSON))
		setCount++
	}

	if setCount == 0 {
		return nil
	}

	result, err := q.Exec(ctx)
	if err != nil {
		return fmt.Errorf("UpdateRecordAnnotations: failed: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("UpdateRecordAnnotations: no record found with uuid %s", uuid)
	}
	return nil
}

// GetRecordsWithResponseBody returns HTTP records that have a non-empty response body,
// using UUID-based cursor pagination. Only columns needed for batch secret scanning are selected.
func (r *Repository) GetRecordsWithResponseBody(ctx context.Context, projectUUID, afterUUID string, limit int) ([]*HTTPRecord, error) {
	var records []*HTTPRecord
	q := r.db.NewSelect().
		Model(&records).
		Column("uuid", "hostname", "url", "has_response", "raw_response", "response_content_type").
		Where("has_response = ?", true).
		Where("raw_response IS NOT NULL").
		Where("length(raw_response) > 0")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if afterUUID != "" {
		q = q.Where("uuid > ?", afterUUID)
	}
	err := q.OrderExpr("uuid ASC").Limit(limit).Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query records with response body: %w", err)
	}
	return records, nil
}

// ReSpiderCandidate is a lightweight projection of an HTTP record used by the
// targeted re-spider phase. It carries just enough to evaluate rich/SPA content
// and dedup app shells (source + raw_response) without materializing every column.
type ReSpiderCandidate struct {
	UUID                string `bun:"uuid"`
	URL                 string `bun:"url"`
	Scheme              string `bun:"scheme"`
	Hostname            string `bun:"hostname"`
	Port                int    `bun:"port"`
	Source              string `bun:"source"`
	ResponseContentType string `bun:"response_content_type"`
	RawResponse         []byte `bun:"raw_response"`
}

// GetReSpiderCandidates returns records that carry a response body, for the
// targeted re-spider phase. It deliberately includes spidering-sourced records
// too, so the caller can pre-seed its shell-dedup set with pages the browser
// already crawled. Ordered by uuid for deterministic per-host capping.
func (r *Repository) GetReSpiderCandidates(ctx context.Context, projectUUID string, limit int) ([]ReSpiderCandidate, error) {
	var rows []ReSpiderCandidate
	q := r.db.NewSelect().
		TableExpr("http_records").
		ColumnExpr("uuid, url, scheme, hostname, port, source, response_content_type, raw_response").
		Where("has_response = ?", true).
		Where("raw_response IS NOT NULL").
		Where("length(raw_response) > 0")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if limit > 0 {
		q = q.Limit(limit)
	}
	if err := q.OrderExpr("uuid ASC").Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("failed to query re-spider candidates: %w", err)
	}
	return rows, nil
}

// DeleteRecord deletes an HTTP record by UUID, including any finding_records junction rows.
func (r *Repository) DeleteRecord(ctx context.Context, uuid string) error {
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		if _, err := tx.NewDelete().TableExpr("finding_records").Where("record_uuid = ?", uuid).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding_records: %w", err)
		}
		if _, err := tx.NewDelete().Model((*HTTPRecord)(nil)).Where("uuid = ?", uuid).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete record: %w", err)
		}
		return nil
	})
}

// HostTarget represents a distinct scheme+hostname+port combination from HTTP records.
type HostTarget struct {
	Scheme   string `bun:"scheme"`
	Hostname string `bun:"hostname"`
	Port     int    `bun:"port"`
}

// GetDistinctHosts returns distinct scheme+hostname+port combinations from HTTP records, filtered by project.
func (r *Repository) GetDistinctHosts(ctx context.Context, projectUUID string) ([]HostTarget, error) {
	var hosts []HostTarget
	q := r.db.NewSelect().
		TableExpr("http_records").
		ColumnExpr("DISTINCT scheme, hostname, port")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	err := q.Scan(ctx, &hosts)
	if err != nil {
		return nil, fmt.Errorf("failed to get distinct hosts: %w", err)
	}
	return hosts, nil
}

// PathTarget represents a distinct scheme+hostname+port+path combination from HTTP records.
type PathTarget struct {
	Scheme   string `bun:"scheme"`
	Hostname string `bun:"hostname"`
	Port     int    `bun:"port"`
	Path     string `bun:"path"`
}

// GetDistinctPaths returns distinct scheme+hostname+port+path combinations from HTTP records, filtered by project.
func (r *Repository) GetDistinctPaths(ctx context.Context, projectUUID string) ([]PathTarget, error) {
	var paths []PathTarget
	q := r.db.NewSelect().
		TableExpr("http_records").
		ColumnExpr("DISTINCT scheme, hostname, port, path")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	err := q.Scan(ctx, &paths)
	if err != nil {
		return nil, fmt.Errorf("failed to get distinct paths: %w", err)
	}
	return paths, nil
}

// AppendRemarks batch-appends remarks to HTTPRecords identified by UUID.
// Existing remarks are preserved and duplicates within each record are deduplicated.
func (r *Repository) AppendRemarks(ctx context.Context, annotations map[string][]string) error {
	if len(annotations) == 0 {
		return nil
	}

	// Track the first update failure so a systemic problem surfaces to the
	// caller (every caller logs the returned error) while a single bad record
	// doesn't abort annotation of the rest.
	var firstErr error
	for uuid, newRemarks := range annotations {
		if len(newRemarks) == 0 {
			continue
		}

		// Fetch current remarks
		record := &HTTPRecord{}
		err := r.db.NewSelect().Model(record).Column("remarks").Where("uuid = ?", uuid).Scan(ctx)
		if err != nil {
			continue // skip missing records
		}

		// Merge and deduplicate
		seen := make(map[string]struct{}, len(record.Remarks)+len(newRemarks))
		merged := make([]string, 0, len(record.Remarks)+len(newRemarks))
		for _, r := range record.Remarks {
			if _, ok := seen[r]; !ok {
				seen[r] = struct{}{}
				merged = append(merged, r)
			}
		}
		for _, r := range newRemarks {
			if _, ok := seen[r]; !ok {
				seen[r] = struct{}{}
				merged = append(merged, r)
			}
		}

		remarksJSON, err := json.Marshal(merged)
		if err != nil {
			continue
		}

		if _, err := r.db.NewUpdate().
			Model((*HTTPRecord)(nil)).
			Set("remarks = ?", string(remarksJSON)).
			Where("uuid = ?", uuid).
			Exec(ctx); err != nil {
			zap.L().Warn("failed to append remarks to record", zap.String("uuid", uuid), zap.Error(err))
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	return firstErr
}

// UpdateRiskScores batch-updates risk_score on HTTPRecords identified by UUID.
// Uses CASE/WHEN SQL to update up to 500 records per statement, minimizing roundtrips.
func (r *Repository) UpdateRiskScores(ctx context.Context, scores map[string]int) error {
	if len(scores) == 0 {
		return nil
	}

	// Collect UUIDs into ordered slice for deterministic batching
	uuids := make([]string, 0, len(scores))
	for uuid := range scores {
		uuids = append(uuids, uuid)
	}

	const batchSize = 500
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		for i := 0; i < len(uuids); i += batchSize {
			end := i + batchSize
			if end > len(uuids) {
				end = len(uuids)
			}
			if err := updateRiskScoreBatch(ctx, tx, scores, uuids[i:end]); err != nil {
				return err
			}
		}
		return nil
	})
}

// updateRiskScoreBatch executes a single CASE/WHEN UPDATE for a batch of UUIDs.
func updateRiskScoreBatch(ctx context.Context, tx bun.Tx, scores map[string]int, uuids []string) error {
	// Build: UPDATE http_records SET risk_score = CASE uuid WHEN ? THEN ? ... END WHERE uuid IN (?,...)
	// Each UUID contributes 2 args to CASE + 1 arg to IN = 3 args per UUID.
	// Batch of 500 = 1500 args, well within SQLITE_MAX_VARIABLE_NUMBER (999 default raised in modern builds).
	args := make([]interface{}, 0, len(uuids)*3)
	var caseSQL strings.Builder
	caseSQL.WriteString("UPDATE http_records SET risk_score = CASE uuid ")
	for _, uuid := range uuids {
		caseSQL.WriteString("WHEN ? THEN ? ")
		args = append(args, uuid, scores[uuid])
	}
	caseSQL.WriteString("END WHERE uuid IN (")
	for i, uuid := range uuids {
		if i > 0 {
			caseSQL.WriteByte(',')
		}
		caseSQL.WriteByte('?')
		args = append(args, uuid)
	}
	caseSQL.WriteByte(')')

	_, err := tx.ExecContext(ctx, caseSQL.String(), args...)
	if err != nil {
		return fmt.Errorf("failed to batch update risk_scores: %w", err)
	}
	return nil
}
