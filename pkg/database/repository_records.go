package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	neturl "net/url"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
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

	r.emitRecordSaved(record)
	return record.UUID, nil
}

// UpsertSnapshotRecord stores a Burp snapshot record idempotently. When an
// existing request later gains a response, or its response changes, the
// response-derived columns are refreshed in place while the stable UUID and
// finding links are preserved. outcome is inserted, updated, or unchanged.
func (r *Repository) UpsertSnapshotRecord(ctx context.Context, httpRR *httpmsg.HttpRequestResponse, source string, projectUUID string) (uuid, outcome string, err error) {
	if httpRR == nil || httpRR.Request() == nil {
		return "", "", fmt.Errorf("invalid HttpRequestResponse")
	}
	record := &HTTPRecord{}
	if err := record.FromHttpRequestResponse(httpRR); err != nil {
		return "", "", fmt.Errorf("failed to convert request: %w", err)
	}
	record.Source = source
	record.ProjectUUID = defaultProjectUUID(projectUUID)

	existingUUID, lookupErr := r.findDuplicateRecord(ctx, record)
	if lookupErr != nil {
		return "", "", lookupErr
	}
	if existingUUID == "" {
		if _, err := r.db.NewInsert().Model(record).Exec(ctx); err != nil {
			return "", "", fmt.Errorf("failed to insert snapshot record: %w", err)
		}
		r.emitRecordSaved(record)
		return record.UUID, "inserted", nil
	}
	if !record.HasResponse {
		return existingUUID, "unchanged", nil
	}

	existing, err := r.GetRecordByUUID(ctx, existingUUID)
	if err != nil {
		return "", "", err
	}
	if existing.HasResponse && existing.ResponseHash == record.ResponseHash {
		return existingUUID, "unchanged", nil
	}
	_, err = r.db.NewUpdate().
		Model((*HTTPRecord)(nil)).
		Set("status_code = ?", record.StatusCode).
		Set("status_phrase = ?", record.StatusPhrase).
		Set("response_http_version = ?", record.ResponseHTTPVersion).
		Set("response_content_type = ?", record.ResponseContentType).
		Set("response_content_length = ?", record.ResponseContentLength).
		Set("raw_response = ?", record.RawResponse).
		Set("response_hash = ?", record.ResponseHash).
		Set("response_norm_hash = ?", record.ResponseNormHash).
		Set("response_words = ?", record.ResponseWords).
		Set("response_title = ?", record.ResponseTitle).
		Set("content_hash = ?", record.ContentHash).
		Set("has_response = ?", true).
		Set("received_at = ?", time.Now()).
		Where("uuid = ?", existingUUID).
		Exec(ctx)
	if err != nil {
		return "", "", fmt.Errorf("failed to refresh snapshot response: %w", err)
	}
	return existingUUID, "updated", nil
}

// findDuplicateRecord checks whether a record with the same method, hostname,
// path, and URL already exists. For requests with a body, the request_hash is
// also compared to distinguish different payloads to the same endpoint. It is a
// thin wrapper over the batched findDuplicateRecordUUIDs so the duplicate rule
// lives in exactly one place.
func (r *Repository) findDuplicateRecord(ctx context.Context, record *HTTPRecord) (string, error) {
	uuids, err := r.findDuplicateRecordUUIDs(ctx, []*HTTPRecord{record})
	if err != nil {
		return "", err
	}
	return uuids[0], nil
}

// recordDedupTuple is the (method, hostname, path, url) identity shared by the
// duplicate lookup for grouping and matching. request_hash is compared
// separately because it only narrows records that carry a body.
func recordDedupTuple(method, host, path, url string) string {
	return method + "\x00" + host + "\x00" + path + "\x00" + url
}

// recordSourceRequiresExactIdentity reports whether records saved under this
// source must dedup on the EXACT raw request (its request_hash) even when the
// request carries no body. Finding-evidence records — saved with the record kind
// as their source (finding / candidate / observation) — carry the precise
// exchange a module used to prove a vulnerability. A header-only probe (Origin,
// Authorization, Cookie, X-Forwarded-*, a method-override or cache/conditional
// header) leaves method/host/path/url unchanged and carries no body, so the coarse
// no-body dedup would collapse it onto an unrelated baseline record and mislink the
// finding to traffic that never carried the attacker header (and to the baseline
// response). Requiring the request_hash keeps each proving exchange distinct.
//
// Crawler/ingest sources (scanner, spidering, discovery, ingest-*) intentionally
// keep the coarse no-body key so repeated identical fetches still collapse and the
// record store isn't inflated by every header-varied crawl request.
func recordSourceRequiresExactIdentity(source string) bool {
	switch source {
	case RecordKindFinding, RecordKindCandidate, RecordKindObservation:
		return true
	default:
		return false
	}
}

// dedupCandidate is the narrow projection findDuplicateRecordUUIDs scans — only
// the columns the duplicate rule needs, so candidate rows don't allocate full
// HTTPRecord structs.
type dedupCandidate struct {
	Method      string `bun:"method"`
	Hostname    string `bun:"hostname"`
	Path        string `bun:"path"`
	URL         string `bun:"url"`
	RequestHash string `bun:"request_hash"`
	UUID        string `bun:"uuid"`
}

// findDuplicateRecordUUIDs is the batched duplicate lookup: for each input
// record it returns the UUID of a pre-existing duplicate (same project, method,
// hostname, path, url — plus request_hash when the request carries a body) or ""
// when none exists; the result slice is parallel to records.
//
// It runs one SELECT per distinct project (instead of one per record), letting
// the batched record writer keep the dedup check off the scan worker's hot path.
// The lookup columns line up with the idx_records_dedup covering index
// (project_uuid, method, hostname, path, url, request_hash, uuid), so the
// row-value IN list resolves via the index instead of a table scan.
func (r *Repository) findDuplicateRecordUUIDs(ctx context.Context, records []*HTTPRecord) ([]string, error) {
	out := make([]string, len(records))
	if len(records) == 0 {
		return out, nil
	}

	// Per-record tuple key, computed once and reused for grouping and matching.
	// Records are grouped by project so each query can pin project_uuid, the
	// leading column of idx_records_dedup.
	keys := make([]string, len(records))
	byProject := make(map[string][]int)
	for i, rec := range records {
		keys[i] = recordDedupTuple(rec.Method, rec.Hostname, rec.Path, rec.URL)
		byProject[rec.ProjectUUID] = append(byProject[rec.ProjectUUID], i)
	}

	for project, idxs := range byProject {
		// Distinct (method, hostname, path, url) tuples for the IN list.
		seen := make(map[string]struct{}, len(idxs))
		clause := strings.Builder{}
		clause.WriteString("(method, hostname, path, url) IN (")
		args := make([]interface{}, 0, len(idxs)*4)
		for _, i := range idxs {
			if _, ok := seen[keys[i]]; ok {
				continue
			}
			seen[keys[i]] = struct{}{}
			if len(args) > 0 {
				clause.WriteByte(',')
			}
			clause.WriteString("(?,?,?,?)")
			rec := records[i]
			args = append(args, rec.Method, rec.Hostname, rec.Path, rec.URL)
		}
		clause.WriteByte(')')
		if len(args) == 0 {
			continue
		}

		var rows []dedupCandidate
		err := r.db.NewSelect().
			Model((*HTTPRecord)(nil)).
			Column("method", "hostname", "path", "url", "request_hash", "uuid").
			Where("project_uuid = ?", project).
			Where(clause.String(), args...).
			Scan(ctx, &rows)
		if err != nil {
			return nil, err
		}

		// A body record matches the candidate with the same request_hash; a
		// no-body record matches any candidate (mirroring findDuplicateRecord,
		// which omits the request_hash filter when there is no body) — UNLESS its
		// source requires exact identity (finding-evidence records), in which case
		// it too must match on request_hash so a header-only probe never collapses
		// onto an unrelated baseline record.
		byTuple := make(map[string][]dedupCandidate, len(rows))
		for _, row := range rows {
			k := recordDedupTuple(row.Method, row.Hostname, row.Path, row.URL)
			byTuple[k] = append(byTuple[k], row)
		}

		for _, i := range idxs {
			cands := byTuple[keys[i]]
			if len(cands) == 0 {
				continue
			}
			rec := records[i]
			if rec.RequestContentLength == 0 && !recordSourceRequiresExactIdentity(rec.Source) {
				out[i] = cands[0].UUID
				continue
			}
			for _, c := range cands {
				if c.RequestHash == rec.RequestHash {
					out[i] = c.UUID
					break
				}
			}
		}
	}

	return out, nil
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
		r.emitRecordSaved(rec)
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

// GetRecordMetadataByHostname is GetRecordsByHostname without the raw_request /
// raw_response BLOB columns, for callers that only need request-line metadata
// (method, URL, path, status). It avoids pulling multi-KB bodies for every row
// when they're immediately discarded — notably the autopilot coverage probe,
// which scans up to 5000 rows just to build (method, URL) signatures. Use the
// full GetRecordsByHostname when the bodies are needed.
func (r *Repository) GetRecordMetadataByHostname(ctx context.Context, projectUUID, hostname string, limit int) ([]*HTTPRecord, error) {
	var records []*HTTPRecord
	q := r.db.NewSelect().
		Model(&records).
		ExcludeColumn("raw_request", "raw_response").
		Where("hostname = ?", hostname).
		Order("sent_at DESC").
		Limit(limit)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if err := q.Scan(ctx); err != nil {
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

// scanRecordColumns is the minimal column projection the dynamic-assessment scan
// feed needs to reconstruct an HttpRequestResponse (via
// recordToHttpRequestResponse): the UUID, the cursor key (created_at), the
// stored URL, the raw request/response bytes, and the has_response gate that
// ParsedResponse() checks. Shared by GetScanRecordsByUUIDs and
// DBInputSource.fetchNextBatch so the two scan-feed fetches can't drift.
var scanRecordColumns = []string{"uuid", "created_at", "url", "raw_request", "raw_response", "has_response"}

// getRecordsByUUIDs fetches HTTP records matching uuids. With no columns it loads
// the full model; passing columns projects the SELECT to just those.
func (r *Repository) getRecordsByUUIDs(ctx context.Context, uuids []string, columns ...string) ([]*HTTPRecord, error) {
	if len(uuids) == 0 {
		return nil, nil
	}
	var records []*HTTPRecord
	q := r.db.NewSelect().Model(&records).Where("uuid IN (?)", bun.List(uuids))
	if len(columns) > 0 {
		q = q.Column(columns...)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, fmt.Errorf("failed to get records by UUIDs: %w", err)
	}
	return records, nil
}

// GetRecordsByUUIDs retrieves HTTP records matching the given UUIDs.
func (r *Repository) GetRecordsByUUIDs(ctx context.Context, uuids []string) ([]*HTTPRecord, error) {
	return r.getRecordsByUUIDs(ctx, uuids)
}

// GetScanRecordsByUUIDs retrieves HTTP records matching the given UUIDs,
// projecting only scanRecordColumns — what the dynamic-assessment scan feed
// consumes. This avoids loading (and JSON-deserializing) the
// parameters/technology/remarks jsonb columns plus ~25 unused scalar columns per
// record. Modules receive the reconstructed HttpRequestResponse (via
// recordToHttpRequestResponse), never the HTTPRecord, so no downstream consumer
// reads the dropped fields.
func (r *Repository) GetScanRecordsByUUIDs(ctx context.Context, uuids []string) ([]*HTTPRecord, error) {
	return r.getRecordsByUUIDs(ctx, uuids, scanRecordColumns...)
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

// OverwriteRecordResponseBody replaces the stored raw response of the record
// with the given UUID and recomputes its derived fields (response_hash,
// response_norm_hash, response_words, response_content_length), keeping them
// consistent with dedup/resume/fingerprinting that key off those columns.
//
// rawResponse must be a complete HTTP response (status line + headers + body).
// Used by the passive js-beautify module to overwrite a minified JS body with
// its beautified form in place. The derivation mirrors Record.FromRequestResponse
// so a rewritten record hashes identically to one ingested with the new body.
// (Distinct from UpdateRecordResponse, which is the replay feature's full
// response-field swap.)
func (r *Repository) OverwriteRecordResponseBody(ctx context.Context, uuid string, rawResponse []byte) error {
	if uuid == "" || len(rawResponse) == 0 {
		return fmt.Errorf("OverwriteRecordResponseBody: empty uuid or response")
	}

	// Path + URL are needed for the reflected-URL-robust normalized body hash.
	recs, err := r.getRecordsByUUIDs(ctx, []string{uuid}, "uuid", "path", "url")
	if err != nil {
		return fmt.Errorf("OverwriteRecordResponseBody: load record: %w", err)
	}
	if len(recs) == 0 {
		return fmt.Errorf("OverwriteRecordResponseBody: no record found with uuid %s", uuid)
	}
	rec := recs[0]

	resp := httpmsg.NewHttpResponse(rawResponse)
	body := resp.Body()

	respHash := sha256.Sum256(rawResponse)
	normHash := modkit.NormalizedBodyHash(string(body), rec.Path, rec.URL)
	words := countResponseWords(body, resp.Headers())

	result, err := r.db.NewUpdate().
		Model((*HTTPRecord)(nil)).
		Where("uuid = ?", uuid).
		Set("raw_response = ?", rawResponse).
		Set("response_hash = ?", hex.EncodeToString(respHash[:])).
		Set("response_norm_hash = ?", normHash).
		Set("response_words = ?", words).
		Set("response_content_length = ?", int64(len(body))).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("OverwriteRecordResponseBody: update failed: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("OverwriteRecordResponseBody: no record found with uuid %s", uuid)
	}
	return nil
}

// GetRecordsWithResponseBody returns HTTP records that have a non-empty response body,
// using UUID-based cursor pagination. Only columns needed for batch secret scanning are selected.
func (r *Repository) GetRecordsWithResponseBody(ctx context.Context, projectUUID, afterUUID string, limit int, hosts ...HostTarget) ([]*HTTPRecord, error) {
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
	// Optional in-scope origin filter — empty means all project records.
	q = applyHostScopeFilter(q, hosts)
	if afterUUID != "" {
		q = q.Where("uuid > ?", afterUUID)
	}
	err := q.OrderExpr("uuid ASC").Limit(limit).Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query records with response body: %w", err)
	}
	return records, nil
}

// WalkJavaScriptRecords streams JavaScript responses already stored for a host by
// earlier phases (spidering, proxy/Burp ingestion) so the discovery engine can
// feed browser-collected bundles through JSTangle even though they live in the
// main DB rather than the ephemeral discovery sitemap. Each callback receives the
// record URL, its response content-type, and the decoded (gzip-inflated) response
// body. JavaScript is matched by content-type or a .js/.mjs URL suffix; the walk
// is bounded by limit and ordered by uuid for determinism. A callback error stops
// the walk and is returned. This satisfies the source.spideredJSProvider optional
// interface structurally (primitive-typed) so neither package imports the other.
func (r *Repository) WalkJavaScriptRecords(ctx context.Context, projectUUID, hostname string, limit int, fn func(recordURL, contentType string, body []byte) error) error {
	if hostname == "" || fn == nil {
		return nil
	}
	var rows []struct {
		URL                 string `bun:"url"`
		ResponseContentType string `bun:"response_content_type"`
		RawResponse         []byte `bun:"raw_response"`
	}
	q := r.db.NewSelect().
		TableExpr("http_records").
		ColumnExpr("url, response_content_type, raw_response").
		Where("has_response = ?", true).
		Where("raw_response IS NOT NULL").
		Where("length(raw_response) > 0").
		Where("hostname = ?", hostname).
		Where("(response_content_type LIKE '%javascript%' OR response_content_type LIKE '%ecmascript%' OR url LIKE '%.js' OR url LIKE '%.mjs')")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if limit > 0 {
		q = q.Limit(limit)
	}
	if err := q.OrderExpr("uuid ASC").Scan(ctx, &rows); err != nil {
		return fmt.Errorf("failed to query stored JavaScript records: %w", err)
	}
	for i := range rows {
		body := httpmsg.NewHttpResponse(rows[i].RawResponse).Body()
		// Stored bodies may still carry their on-wire gzip encoding; inflate when
		// the gzip magic is present so JSTangle/linkfinder see readable source.
		if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
			if dec := httpmsg.DecompressBytes(body); len(dec) > 0 {
				body = dec
			}
		}
		if len(body) == 0 {
			continue
		}
		if err := fn(rows[i].URL, rows[i].ResponseContentType, body); err != nil {
			return err
		}
	}
	return nil
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
// targeted re-spider phase, using UUID-based cursor pagination (afterUUID="" for
// the first page). It deliberately includes spidering-sourced records too, so
// the caller can pre-seed its shell-dedup set with pages the browser already
// crawled. Ordered by uuid so paging is stable and per-host capping
// deterministic. Each returned row carries a full raw_response body, so the
// caller pages with a modest limit and reduces each page before reading the
// next rather than materializing every body at once.
func (r *Repository) GetReSpiderCandidates(ctx context.Context, projectUUID, afterUUID string, limit int, hosts ...HostTarget) ([]ReSpiderCandidate, error) {
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
	q = applyHostScopeFilter(q, hosts)
	if afterUUID != "" {
		q = q.Where("uuid > ?", afterUUID)
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

// dbTimestampString formats t to the DB's second-precision UTC timestamp string, matching
// how created_at/cursor timestamps are stored and compared (so the comparison works on
// SQLite text columns as well as Postgres).
func dbTimestampString(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05")
}

// GetDistinctHosts returns distinct scheme+hostname+port combinations from HTTP records,
// filtered by project. When a non-zero `since` is supplied, only records created at/after
// that time are considered (used to find origins discovered during a specific scan).
func (r *Repository) GetDistinctHosts(ctx context.Context, projectUUID string, since ...time.Time) ([]HostTarget, error) {
	var hosts []HostTarget
	q := r.db.NewSelect().
		TableExpr("http_records").
		ColumnExpr("DISTINCT scheme, hostname, port")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if len(since) > 0 && !since[0].IsZero() {
		q = q.Where("created_at >= ?", dbTimestampString(since[0]))
	}
	err := q.Scan(ctx, &hosts)
	if err != nil {
		return nil, fmt.Errorf("failed to get distinct hosts: %w", err)
	}
	return hosts, nil
}

// InScopeHosts returns the distinct (scheme, hostname, port) origins in the project that
// are in scope for the supplied CLI targets. An origin is in scope when its hostname passes
// the scope matcher AND EITHER its (scheme, port) matches one of the targets' origins
// (default ports normalized like stored records: https→443, http→80) OR it was discovered
// during the current scan (records created at/after the scan's start). Returns nil when
// there are no targets (no filter — a project-wide pass). This is the single source of
// truth for the origin scoping the executor applies via WithHostScopes, so
// DynamicAssessment, KnownIssueScan, spidering/discovery seeds, and the scan-completion
// record count all derive the same set.
//
// The full-origin match keeps e.g. localhost:3000 separate from localhost:8080 left in the
// project by a prior scan, while the current-scan provenance carve-out still lets THIS
// scan's own discoveries on a different port (e.g. the --intensity deep port sweep, or a
// followed cross-port link) be scanned. Records carry no scan_uuid, so provenance is keyed
// on the scan's start time. If no target yields a determinable scheme/port (e.g. all bare
// hosts), the scheme/port constraint is dropped — a safe fallback that never over-excludes.
func (r *Repository) InScopeHosts(ctx context.Context, scopeCfg config.ScopeConfig, targets []string, projectUUID, scanUUID string) []HostTarget {
	if len(targets) == 0 {
		return nil
	}
	matcher := config.NewScopeMatcher(scopeCfg, targets...)
	allowedOrigins := parseTargetOrigins(targets)
	hosts, err := r.GetDistinctHosts(ctx, projectUUID)
	if err != nil {
		return nil
	}
	currentScanOrigins := r.originsDiscoveredByScan(ctx, projectUUID, scanUUID)
	var out []HostTarget
	for _, h := range hosts {
		if !matcher.InScopeRequest(h.Hostname, "/", "", "") {
			continue
		}
		if len(allowedOrigins) > 0 {
			_, originMatch := allowedOrigins[originKey(h.Scheme, h.Port)]
			_, fromScan := currentScanOrigins[fullOriginKey(h)]
			if !originMatch && !fromScan {
				continue
			}
		}
		out = append(out, h)
	}
	return out
}

// HostnamesOf returns the distinct hostnames of the given origins, order-preserving.
// Used to derive a hostname-only filter (e.g. for findings, which carry no port column)
// from a set of in-scope origins.
func HostnamesOf(hosts []HostTarget) []string {
	if len(hosts) == 0 {
		return nil
	}
	var hostnames []string
	seen := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		if _, ok := seen[h.Hostname]; ok {
			continue
		}
		seen[h.Hostname] = struct{}{}
		hostnames = append(hostnames, h.Hostname)
	}
	return hostnames
}

// originKey is the map key for a (scheme, port) origin pair.
func originKey(scheme string, port int) string {
	return strings.ToLower(scheme) + ":" + strconv.Itoa(port)
}

// fullOriginKey is the map key for a complete (scheme, hostname, port) origin.
func fullOriginKey(h HostTarget) string {
	return strings.ToLower(h.Scheme) + "://" + strings.ToLower(h.Hostname) + ":" + strconv.Itoa(h.Port)
}

// originsDiscoveredByScan returns the full origin keys (scheme://host:port) of hosts with
// records created during the given scan. http_records carry no scan_uuid, so the scan's
// start time is used as the provenance boundary: records created at/after it belong to this
// scan. (A precise alternative would populate http_records.scan_uuid at save time; the
// time boundary avoids that wider change at the cost of fragility under concurrent
// same-project scans.) Empty scanUUID (or an unknown scan) yields nil, so callers fall
// back to pure origin matching.
func (r *Repository) originsDiscoveredByScan(ctx context.Context, projectUUID, scanUUID string) map[string]struct{} {
	if scanUUID == "" {
		return nil
	}
	scan, err := r.GetScanByUUID(ctx, scanUUID)
	if err != nil || scan == nil || scan.StartedAt.IsZero() {
		return nil
	}
	hosts, err := r.GetDistinctHosts(ctx, projectUUID, scan.StartedAt)
	if err != nil {
		return nil
	}
	keys := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		keys[fullOriginKey(h)] = struct{}{}
	}
	return keys
}

// parseTargetOrigins extracts the set of (scheme, port) origins from CLI target URLs,
// normalizing default ports the same way stored records do (via httpmsg.GetDefaultPort).
// Targets without a determinable scheme are skipped; an empty result means "no scheme/port
// constraint" to the caller. The set is across all targets, not per-target: in the rare
// multi-target scan with the same host on different ports, a record may match a sibling
// target's port — an accepted trade-off vs per-target matching complexity.
func parseTargetOrigins(targets []string) map[string]struct{} {
	origins := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		u, err := neturl.Parse(strings.TrimSpace(t))
		if err != nil || u.Hostname() == "" || u.Scheme == "" {
			continue
		}
		scheme := strings.ToLower(u.Scheme)
		port := httpmsg.GetDefaultPort(scheme)
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		}
		origins[originKey(scheme, port)] = struct{}{}
	}
	return origins
}

// applyHostScopeFilter restricts q to the given in-scope origins when the list is
// non-empty; an empty list is a no-op. Each HostTarget is a flexible predicate: an empty
// Scheme or zero Port is left unconstrained, so {Hostname} matches any origin on that host
// while {Scheme,Hostname,Port} matches the exact origin. Origins are OR-ed together.
func applyHostScopeFilter(q *bun.SelectQuery, hosts []HostTarget) *bun.SelectQuery {
	if len(hosts) == 0 {
		return q
	}
	var conds []string
	var args []interface{}
	for _, h := range hosts {
		parts := []string{"hostname = ?"}
		args = append(args, h.Hostname)
		if h.Scheme != "" {
			parts = append(parts, "scheme = ?")
			args = append(args, h.Scheme)
		}
		if h.Port != 0 {
			parts = append(parts, "port = ?")
			args = append(args, h.Port)
		}
		conds = append(conds, "("+strings.Join(parts, " AND ")+")")
	}
	return q.Where("("+strings.Join(conds, " OR ")+")", args...)
}

// PathTarget represents a distinct scheme+hostname+port+path combination from HTTP records.
type PathTarget struct {
	Scheme   string `bun:"scheme"`
	Hostname string `bun:"hostname"`
	Port     int    `bun:"port"`
	Path     string `bun:"path"`
}

// GetDistinctPaths returns distinct scheme+hostname+port+path combinations from HTTP records,
// filtered by project and, when hosts is non-empty, restricted to those in-scope origins
// (matching the executor's WithHostScopes convention). Empty hosts means no origin filter.
func (r *Repository) GetDistinctPaths(ctx context.Context, projectUUID string, hosts ...HostTarget) ([]PathTarget, error) {
	var paths []PathTarget
	q := r.db.NewSelect().
		TableExpr("http_records").
		ColumnExpr("DISTINCT scheme, hostname, port, path")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	q = applyHostScopeFilter(q, hosts)
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

	// Batch-load the current remarks for every target UUID in one query rather
	// than issuing one SELECT per record (the old N+1). The updates still carry
	// per-record merged values, so they run individually — but inside a single
	// transaction to collapse N commits into one.
	uuids := make([]string, 0, len(annotations))
	for uuid, newRemarks := range annotations {
		if len(newRemarks) > 0 {
			uuids = append(uuids, uuid)
		}
	}
	if len(uuids) == 0 {
		return nil
	}

	var existing []HTTPRecord
	if err := r.db.NewSelect().
		Model(&existing).
		Column("uuid", "remarks").
		Where("uuid IN (?)", bun.List(uuids)).
		Scan(ctx); err != nil {
		return fmt.Errorf("failed to load existing remarks: %w", err)
	}
	existingByUUID := make(map[string][]string, len(existing))
	for i := range existing {
		existingByUUID[existing[i].UUID] = existing[i].Remarks
	}

	// Track the first update failure so a systemic problem surfaces to the
	// caller (every caller logs the returned error) while a single bad record
	// doesn't abort annotation of the rest.
	var firstErr error
	err := r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		for _, uuid := range uuids {
			current, ok := existingByUUID[uuid]
			if !ok {
				continue // record not found — skip
			}
			// Merge existing + new remarks, preserving order and dropping dups.
			merged := mergeUniqueStrings(current, annotations[uuid])

			remarksJSON, err := json.Marshal(merged)
			if err != nil {
				continue
			}

			if _, err := tx.NewUpdate().
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
		return nil
	})
	if err != nil {
		return err
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
