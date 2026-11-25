package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	neturl "net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// SaveRecord stores a denormalized HTTP record (request + response + host + parameters).
// The source identifies the origin of the record (e.g. "scanner", "ingest-cli", "ingest-server", "ingest-proxy").
// Returns the UUID of the saved record. If a matching record already exists (same method,
// hostname, path, URL, and request body), the existing UUID is returned without inserting.
func (r *Repository) SaveRecord(ctx context.Context, httpRR *httpmsg.HttpRequestResponse, source string, projectUUID string) (string, error) {
	return r.SaveRecordWithLineage(ctx, httpRR, source, projectUUID, RecordLineage{})
}

// RecordLineage is the chain metadata one record carries: where it sits in a
// redirect chain, and which submitted target the chain started from.
//
// Grouped into a struct rather than added to the parameter lists because the
// four fields are one fact about one row and are always decided together — a
// hop's parent, root and target all come from the same walk, and splitting them
// across positional arguments is how a caller ends up passing a root from one
// chain with a parent from another.
type RecordLineage struct {
	// ParentUUID is the record this one redirected from. Empty for a root.
	ParentUUID string
	// RootUUID is the first record of the chain. Empty means "this row is the
	// root", which applyTo resolves to the row's own UUID.
	RootUUID string
	// Target is the submitted input line the chain started from, verbatim.
	Target string
	// ChainTruncated marks a row whose destination is not the row after it.
	ChainTruncated bool
	// ScanUUID is the scan that fetched this exchange. Stamped on a NEW row
	// only, never on a dedup hit (AdoptRecord ignores it): records are shared
	// across scans, so http_records.scan_uuid means "the first scan to store this
	// exchange". That is what lets a scan-scoped export and records_written count
	// what a run produced instead of the whole project.
	ScanUUID string
	// Remarks are appended to a NEW row's remarks; a dedup hit keeps its own.
	Remarks []string
}

// applyTo stamps the lineage onto a record.
//
// An empty RootUUID is left ALONE rather than written, because the two callers
// run it at opposite ends of conversion: the batched writer applies lineage
// during PrepareIdentity, before the UUID exists, while the repository applies
// it after a full conversion that has already self-rooted the row. Writing the
// empty value would undo that second one, leaving a root row with no root.
// EnrichFromHttpRequestResponse fills whichever is still empty.
func (l RecordLineage) applyTo(rec *HTTPRecord) {
	if rec == nil {
		return
	}
	rec.ParentUUID = l.ParentUUID
	rec.Target = l.Target
	rec.ChainTruncated = l.ChainTruncated
	if l.RootUUID != "" {
		rec.RootUUID = l.RootUUID
	}
	// Left alone when empty, like RootUUID: a writer-level stamp (RecordWriter's
	// config) may already have set it, and an empty lineage says nothing.
	if l.ScanUUID != "" {
		rec.ScanUUID = l.ScanUUID
	}
	for _, r := range l.Remarks {
		if !slices.Contains(rec.Remarks, r) {
			rec.Remarks = append(rec.Remarks, r)
		}
	}
}

// SaveRecordWithLineage is SaveRecord carrying the record's full chain
// metadata.
//
// On a duplicate hit the existing row is ADOPTED rather than replaced: see
// AdoptRecord for which columns that repairs and why the row it repairs is so
// often the one that matters.
func (r *Repository) SaveRecordWithLineage(ctx context.Context, httpRR *httpmsg.HttpRequestResponse, source string, projectUUID string, lineage RecordLineage) (string, error) {
	if httpRR == nil || httpRR.Request() == nil {
		return "", fmt.Errorf("invalid HttpRequestResponse")
	}

	record := &HTTPRecord{}
	if err := record.FromHttpRequestResponse(httpRR); err != nil {
		return "", fmt.Errorf("failed to convert request: %w", err)
	}
	record.Source = source
	record.ProjectUUID = defaultProjectUUID(projectUUID)
	lineage.applyTo(record)

	if existingUUID, err := r.findDuplicateRecord(ctx, record); err == nil && existingUUID != "" {
		r.AdoptRecord(ctx, existingUUID, lineage, source)
		return existingUUID, nil
	}

	if _, err := r.db.NewInsert().Model(record).Exec(ctx); err != nil {
		return "", fmt.Errorf("failed to insert record: %w", err)
	}

	r.emitRecordSaved(record)
	return record.UUID, nil
}

// AdoptRecordParent links an existing record to a parent, but ONLY when it has
// none. A no-op for an empty uuid or parent.
//
// Backfill-never-overwrite is the whole contract. Filling an empty parent adds
// information and cannot contradict anything. Overwriting a set one would let
// the most recent scan to traverse a shared redirect target silently re-parent
// it out of the chain it was first recorded in, rewriting history for every
// earlier chain that ran through the same URL.
//
// Best-effort: a failure to link leaves a shorter chain, which reads correctly
// as less lineage rather than as wrong lineage, and must not fail the save that
// prompted it.
//
// A thin wrapper on AdoptRecord, which applies every column in one statement;
// kept because "link this orphan to its parent" is a question callers ask on
// its own.
func (r *Repository) AdoptRecordParent(ctx context.Context, uuid, parentUUID string) {
	r.AdoptRecord(ctx, uuid, RecordLineage{ParentUUID: parentUUID}, "")
}

// evidenceRecordKinds are the sources that mean "this row reached the database
// as a finding's evidence" rather than "a phase fetched it". One list, read by
// recordSourceRequiresExactIdentity on the way in and by AdoptRecord's promote
// clause on the way out — spelled twice, a fourth kind would be treated as
// non-promotable in one direction and non-displaceable in the other, leaving
// rows that can never be relabelled.
var evidenceRecordKinds = []string{RecordKindFinding, RecordKindCandidate, RecordKindObservation}

// AdoptRecord repairs a row that lost a dedup race, in ONE statement: it
// backfills the chain metadata the winning row never had, and promotes a
// finding-evidence source to the crawl source of the phase that just fetched it.
//
// Why any of this is needed. A passive module persists the response it reports
// on BEFORE the item's own save runs (processItem runs the passive stage
// first), so on a passive-heavy phase the evidence row routinely wins the
// dedup and the phase's own row — its lineage and its source label — is
// discarded. The visible symptom was that `vigolium traffic --source probe`
// returned a sweep's redirect hops and hid every page it actually fetched.
//
// The deeper fix is to save before the passive stage rather than repair
// afterwards; that is a behavioural change to processItem and belongs in its
// own commit. Until then this is the repair, and it must stay cheap: it runs
// once per deduped record, which on a sweep is most of them.
//
// One statement, not five. Every column here is conditional in SQL rather than
// in Go, so a no-op costs nothing beyond the row lock and the caller pays one
// round trip instead of one per column. Each condition encodes the same
// promote-only contract:
//
//   - parent_uuid, root_uuid, target: backfilled when empty, NEVER overwritten.
//     A shared redirect destination already belongs to the chain it was first
//     recorded in; re-rooting it to the most recent traversal would rewrite
//     history for every earlier chain through the same URL. A root_uuid equal
//     to the row's own uuid counts as empty — that is the "no chain" default.
//   - chain_truncated: only ever raised. A row once known to be cut short does
//     not become whole because a later, shorter walk reached it.
//   - source: a finding-evidence source is displaced because it describes HOW
//     the row first reached the database, not what the row IS. A crawl source
//     is never displaced by another crawl source, or "which phase found this"
//     would degrade into "which phase saw it last".
//
// Best-effort: a failure leaves the row readable under its old lineage, which
// reads as less information rather than wrong information, and must not fail
// the save that prompted it.
func (r *Repository) AdoptRecord(ctx context.Context, uuid string, lineage RecordLineage, source string) {
	if err := adoptRecordOn(ctx, r.db, uuid, lineage, source); err != nil {
		zap.L().Debug("failed to adopt record lineage",
			zap.String("uuid", uuid), zap.String("source", source), zap.Error(err))
	}
}

// RecordAdoption is one AdoptRecord call, for AdoptRecords.
type RecordAdoption struct {
	UUID    string
	Lineage RecordLineage
	Source  string
}

// AdoptRecords applies a batch of adoptions in ONE transaction: the
// record writer used to issue one autocommit UPDATE per deduplicated record,
// so a duplicate-heavy batch paid a commit (and on SQLite an fsync) per row.
// Best-effort like AdoptRecord: a failed batch is logged, never returned.
func (r *Repository) AdoptRecords(ctx context.Context, batch []RecordAdoption) {
	if len(batch) == 0 {
		return
	}
	err := r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		for _, a := range batch {
			if err := adoptRecordOn(ctx, tx, a.UUID, a.Lineage, a.Source); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		zap.L().Debug("failed to adopt record lineage batch", zap.Int("records", len(batch)), zap.Error(err))
	}
}

func adoptRecordOn(ctx context.Context, db bun.IDB, uuid string, lineage RecordLineage, source string) error {
	if uuid == "" {
		return nil
	}
	q := db.NewUpdate().Model((*HTTPRecord)(nil)).Where("uuid = ?", uuid)
	set := false
	if lineage.ParentUUID != "" && lineage.ParentUUID != uuid {
		q = q.Set("parent_uuid = CASE WHEN parent_uuid IS NULL OR parent_uuid = '' THEN ? ELSE parent_uuid END", lineage.ParentUUID)
		set = true
	}
	if lineage.RootUUID != "" && lineage.RootUUID != uuid {
		q = q.Set("root_uuid = CASE WHEN root_uuid IS NULL OR root_uuid IN ('', uuid) THEN ? ELSE root_uuid END", lineage.RootUUID)
		set = true
	}
	if lineage.Target != "" {
		q = q.Set("target = CASE WHEN target IS NULL OR target = '' THEN ? ELSE target END", lineage.Target)
		set = true
	}
	if lineage.ChainTruncated {
		q = q.Set("chain_truncated = ?", true)
		set = true
	}
	if source != "" && !recordSourceRequiresExactIdentity(source) {
		q = q.Set("source = CASE WHEN source IN (?) THEN ? ELSE source END", bun.List(evidenceRecordKinds), source)
		set = true
	}
	if !set {
		return nil
	}
	_, err := q.Exec(ctx)
	return err
}

// UpsertSnapshotRecord stores a Burp snapshot record idempotently. When an
// existing request later gains a response, or its response changes, the
// response-derived columns are refreshed in place while the stable UUID and
// finding links are preserved. outcome is inserted, updated, or unchanged.
func (r *Repository) UpsertSnapshotRecord(ctx context.Context, httpRR *httpmsg.HttpRequestResponse, source string, projectUUID string) (uuid, outcome string, err error) {
	return r.UpsertCapturedRecord(ctx, httpRR, source, projectUUID, Capture{})
}

// Capture is what an importer knows about a snapshot record beyond its bytes.
type Capture struct {
	// SentAt is when the capturing tool saw the exchange (a bridge summary's
	// time). It becomes sent_at — on insert, and on an update that replaces
	// the response with that capture's. Zero means unknown: sent_at is the
	// time of this write. created_at is always the time of the insert.
	SentAt time.Time
	// ScanUUID is stamped on a new row (the importing invocation's scans
	// row); an existing row keeps its own.
	ScanUUID string
}

// UpsertCapturedRecord is UpsertSnapshotRecord carrying the capture's own
// time and the importing invocation's scan row.
func (r *Repository) UpsertCapturedRecord(ctx context.Context, httpRR *httpmsg.HttpRequestResponse, source string, projectUUID string, capture Capture) (uuid, outcome string, err error) {
	if httpRR == nil || httpRR.Request() == nil {
		return "", "", fmt.Errorf("invalid HttpRequestResponse")
	}
	record := &HTTPRecord{}
	if err := record.FromHttpRequestResponse(httpRR); err != nil {
		return "", "", fmt.Errorf("failed to convert request: %w", err)
	}
	record.Source = source
	record.ProjectUUID = defaultProjectUUID(projectUUID)
	if !capture.SentAt.IsZero() {
		record.SentAt = capture.SentAt
	}
	if capture.ScanUUID != "" {
		record.ScanUUID = capture.ScanUUID
	}

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
		// The row now holds this capture's response, so it carries this
		// capture's time.
		Set("sent_at = ?", record.SentAt).
		Set("status_code = ?", record.StatusCode).
		Set("status_phrase = ?", record.StatusPhrase).
		Set("response_http_version = ?", record.ResponseHTTPVersion).
		Set("response_content_type = ?", record.ResponseContentType).
		Set("response_content_length = ?", record.ResponseContentLength).
		Set("raw_response = ?", record.RawResponse).
		Set("response_decoded_from = NULLIF(?, '')", record.ResponseDecodedFrom).
		Set("response_hash = ?", record.ResponseHash).
		Set("response_norm_hash = ?", record.ResponseNormHash).
		Set("response_words = ?", record.ResponseWords).
		Set("response_title = ?", record.ResponseTitle).
		Set("response_location = ?", record.ResponseLocation).
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
// Hand-sent and mined exchanges (replay, fuzz, param-mining) are the same
// kind of proof: a replay's whole point is the headers it carried, and a mined
// parameter or header is confirmed by exactly one request's bytes.
//
// Crawler/ingest sources (scanner, spidering, discovery, ingest-*) intentionally
// keep the coarse no-body key so repeated identical fetches still collapse and the
// record store isn't inflated by every header-varied crawl request. The coarse
// key still carries the principal (request_identity_hash): only headers that do
// not say WHO sent the request are ignored.
func recordSourceRequiresExactIdentity(source string) bool {
	return slices.Contains(evidenceRecordKinds, source) || slices.Contains(exactIdentitySentSources, source)
}

// exactIdentitySentSources are the non-evidence-kind sources whose records
// dedup on the exact request bytes (recordSourceRequiresExactIdentity).
var exactIdentitySentSources = []string{RecordSourceReplay, RecordSourceFuzz, RecordSourceParamMining}

// dedupCandidate is the narrow projection findDuplicateRecordUUIDs scans — only
// the columns the duplicate rule needs, so candidate rows don't allocate full
// HTTPRecord structs.
type dedupCandidate struct {
	Method      string `bun:"method"`
	Hostname    string `bun:"hostname"`
	Path        string `bun:"path"`
	URL         string `bun:"url"`
	RequestHash string `bun:"request_hash"`
	// IdentityHash is request_identity_hash, "" for a row that sent no
	// Authorization or Cookie (and for rows written before the column).
	IdentityHash string `bun:"identity_hash"`
	UUID         string `bun:"uuid"`
}

// findDuplicateRecordUUIDs is the batched duplicate lookup: for each input
// record it returns the UUID of a pre-existing duplicate (same project, method,
// hostname, path, url — plus request_hash when the request carries a body, and
// request_identity_hash when it does not) or "" when none exists; the result
// slice is parallel to records.
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
			ColumnExpr("COALESCE(request_identity_hash, '') AS identity_hash").
			Where("project_uuid = ?", project).
			Where(clause.String(), args...).
			Scan(ctx, &rows)
		if err != nil {
			return nil, err
		}

		// A body record matches the candidate with the same request_hash; a
		// no-body record matches a candidate sent by the same principal (the
		// same request_identity_hash: Authorization and Cookie), whatever its
		// other headers — UNLESS its source requires exact identity
		// (finding-evidence and hand-sent records), in which case it too must
		// match on request_hash so a header-only probe never collapses onto an
		// unrelated baseline record.
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
				for _, c := range cands {
					if c.IdentityHash == rec.RequestIdentityHash {
						out[i] = c.UUID
						break
					}
				}
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
	// converted[i] is the model for input record i, or nil when it failed
	// conversion and was never sent to the database. SaveRecordsBatch stamps each
	// model's UUID in place, so this doubles as the index back onto the input.
	converted := make([]*HTTPRecord, len(records))

	for i, rr := range records {
		rec := &HTTPRecord{}
		if err := rec.FromHttpRequestResponse(rr); err != nil {
			zap.L().Debug("SaveRecordBatch: skipping record", zap.Error(err))
			continue
		}
		rec.Source = source
		rec.ProjectUUID = projectUUID
		converted[i] = rec
		dbRecords = append(dbRecords, rec)
	}

	if _, err := r.SaveRecordsBatch(ctx, dbRecords); err != nil {
		return nil, err
	}

	// The returned slice MUST stay positionally aligned with records, with "" for
	// a record that was skipped. Callers zip the result back onto their input by
	// index (discovery's saveAndEmitWithUUIDs assigns uuids[i] to records[i]), so
	// returning the compacted slice shifted every UUID after a conversion failure
	// onto the PRECEDING request — silently linking that record's findings to the
	// wrong HTTP exchange in finding_records, the fs/HTML/SARIF evidence and the
	// live mirror. A malformed discovered URL is enough to trigger it, and the
	// conversion failure itself is only logged at Debug. This also matches the
	// alignment RecordWriter.SaveRecordBatch already promises for the same
	// interface, so the two implementations no longer disagree.
	out := make([]string, len(records))
	for i, rec := range converted {
		if rec != nil {
			out[i] = rec.UUID
		}
	}
	return out, nil
}

// CountSaved reports how many records in a SaveRecordBatch result were actually
// persisted. The result is index-aligned with the input and carries "" for a
// record that was skipped, so len() over-reports — this is the only correct way
// to turn that slice into a count.
func CountSaved(uuids []string) int {
	n := 0
	for _, u := range uuids {
		if u != "" {
			n++
		}
	}
	return n
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

// SaveRecordsBatchSkipExisting inserts multiple HTTP records in one transaction,
// skipping any whose uuid is already stored, and returns the uuids it actually
// inserted. len(records)-len(inserted) is the number skipped as duplicates.
//
// SaveRecordsBatch aborts the whole batch on a duplicate uuid, which is right for
// a scanner writing records it has just generated and wrong for an import: a
// JSONL export re-imported, or two overlapping exports imported together, share
// record uuids by design. That used to fail the run with a UNIQUE constraint
// error after an arbitrary number of earlier batches had already committed —
// neither idempotent nor atomic. Here the overlap is simply not inserted.
//
// Only the inserted uuids fire emitRecordSaved: a row that was already there is
// not a new record, and a mirror that saw it would duplicate on every re-import.
func (r *Repository) SaveRecordsBatchSkipExisting(ctx context.Context, records []*HTTPRecord) ([]string, error) {
	if len(records) == 0 {
		return nil, nil
	}

	for _, rec := range records {
		rec.ProjectUUID = defaultProjectUUID(rec.ProjectUUID)
	}

	var inserted []string
	err := r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		// RETURNING is the only way to learn WHICH rows survived the conflict
		// clause — RowsAffected gives a count with no identity, and a pre-SELECT of
		// existing uuids is a second round trip that another writer can invalidate
		// between the two statements. Supported by the bundled modernc SQLite
		// (3.35+) and by Postgres.
		return tx.NewInsert().Model(&records).
			On("CONFLICT (uuid) DO NOTHING").
			Returning("uuid").
			Scan(ctx, &inserted)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to batch insert %d records: %w", len(records), err)
	}

	if len(inserted) > 0 {
		byUUID := make(map[string]*HTTPRecord, len(records))
		for _, rec := range records {
			byUUID[rec.UUID] = rec
		}
		for _, u := range inserted {
			if rec := byUUID[u]; rec != nil {
				r.emitRecordSaved(rec)
			}
		}
	}
	return inserted, nil
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

// GetRecordByUUIDOrPrefix retrieves a record by full UUID, falling back to
// expanding an unambiguous prefix. Returns sql.ErrNoRows when nothing
// matches, and an error naming the candidates when a prefix is ambiguous.
//
// Agents read record UUIDs out of a JSON tool result and re-type them into
// the next call; transcribing 36 hex characters is something models get
// wrong regularly (an observed run produced one UUID with an invented head
// and another that spliced two records together). A prefix is short enough
// to copy reliably.
//
// The full-UUID path costs exactly one primary-key lookup, same as before -
// the prefix scan only runs once that has missed.
func (r *Repository) GetRecordByUUIDOrPrefix(ctx context.Context, idOrPrefix string) (*HTTPRecord, error) {
	rec, err := r.GetRecordByUUID(ctx, idOrPrefix)
	if err == nil || !errors.Is(err, sql.ErrNoRows) || len(idOrPrefix) < MinUUIDPrefix {
		return rec, err
	}
	full, resolveErr := r.ResolveRecordUUID(ctx, idOrPrefix)
	if resolveErr != nil {
		return nil, resolveErr
	}
	return r.GetRecordByUUID(ctx, full)
}

// ResolveRecordUUID expands a UUID prefix to the full UUID of the one record
// it matches. Returns sql.ErrNoRows when nothing matches, and an error
// naming the candidates when the prefix is ambiguous.
//
// Implemented as a range scan over the primary key rather than LIKE
// 'prefix%': the btree is ordered by uuid, so a range is index-seekable
// under any collation, while LIKE falls back to a full table scan on both
// SQLite (BINARY collation, no case_sensitive_like pragma) and Postgres (no
// text_pattern_ops index). http_records is the largest table in the schema
// and its rows carry request/response bodies, so that scan is not cheap. A
// range also sidesteps LIKE metacharacters entirely - a prefix containing %
// or _ is just a prefix here, which matters when the input is a string a
// model may have mangled.
func (r *Repository) ResolveRecordUUID(ctx context.Context, prefix string) (string, error) {
	full, candidates, err := r.ResolveRecordUUIDInProject(ctx, prefix, "")
	if err != nil || len(candidates) == 0 {
		return full, err
	}
	uuids := make([]string, len(candidates))
	for i, c := range candidates {
		uuids[i] = c.UUID
	}
	return "", fmt.Errorf("uuid prefix %q matches %d records (%s) - use more characters",
		prefix, len(uuids), strings.Join(uuids, ", "))
}

// RecordRefCandidate is one record a UUID prefix matched, as an ambiguity
// names it.
type RecordRefCandidate struct {
	UUID   string `json:"uuid"`
	Method string `json:"method"`
	URL    string `json:"url"`
}

// ResolveRecordUUIDInProject is ResolveRecordUUID limited to one project
// (projectUUID empty means every project, the unscoped -S read). It returns the
// full UUID of the one match, sql.ErrNoRows for none, and the candidates
// (at most 5) when the prefix is ambiguous. Scoping the scan is what keeps an
// ambiguity from naming another project's records — the same reason a scoped
// read reports another project's UUID as not found.
func (r *Repository) ResolveRecordUUIDInProject(ctx context.Context, prefix, projectUUID string) (string, []RecordRefCandidate, error) {
	const maxCandidates = 5
	upper, ok := prefixUpperBound(prefix)
	if !ok {
		return "", nil, sql.ErrNoRows
	}
	var rows []RecordRefCandidate
	q := r.db.NewSelect().
		Model((*HTTPRecord)(nil)).
		Column("uuid", "method", "url").
		Where("uuid >= ? AND uuid < ?", prefix, upper)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if err := q.OrderExpr("uuid").Limit(maxCandidates).Scan(ctx, &rows); err != nil {
		return "", nil, err
	}
	switch {
	case len(rows) == 0:
		return "", nil, sql.ErrNoRows
	case len(rows) == 1, rows[0].UUID == prefix:
		// An exact id sorts first among the ids it prefixes, and wins.
		return rows[0].UUID, nil, nil
	}
	return "", rows, nil
}

// prefixUpperBound returns the exclusive upper bound of the range of strings
// starting with prefix, by incrementing its last byte. ok is false when no
// such bound exists (empty prefix, or all-0xff), in which case the caller
// has nothing to scan.
func prefixUpperBound(prefix string) (string, bool) {
	b := []byte(prefix)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] < 0xff {
			b[i]++
			return string(b[:i+1]), true
		}
	}
	return "", false
}

// RecordProjectUUID returns just the project a record belongs to, for the
// existence-plus-scope check the mutating handlers perform before acting on it.
// Returns sql.ErrNoRows when the record does not exist, like GetRecordByUUID.
//
// Projected on purpose: the callers read only this one field, and a record's
// raw_response alone can be megabytes.
func (r *Repository) RecordProjectUUID(ctx context.Context, uuid string) (string, error) {
	record := &HTTPRecord{}
	err := r.db.NewSelect().
		Model(record).
		Column("project_uuid").
		Where("uuid = ?", uuid).
		Scan(ctx)
	if err != nil {
		return "", err
	}
	return record.ProjectUUID, nil
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
		Limit(int64(limit))
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
		ExcludeColumn(recordBodyColumns...).
		Where("hostname = ?", hostname).
		Order("sent_at DESC").
		Limit(int64(limit))
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
		Limit(int64(limit))
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
//
// The lookup is chunked because callers pass whatever list they hold — a whole
// scan feed's batch, an export's finding references — and bun renders an IN()
// list as SQL literals, so an unchunked call builds one statement carrying every
// uuid as text. Order across chunks is not guaranteed, which matches the
// unchunked behavior: this has always been a set lookup with no ORDER BY.
func (r *Repository) getRecordsByUUIDs(ctx context.Context, uuids []string, columns ...string) ([]*HTTPRecord, error) {
	if len(uuids) == 0 {
		return nil, nil
	}
	records := make([]*HTTPRecord, 0, len(uuids))
	for chunk := range slices.Chunk(uuids, SQLChunkSize) {
		var page []*HTTPRecord
		q := r.db.NewSelect().Model(&page).Where("uuid IN (?)", bun.List(chunk))
		if len(columns) > 0 {
			q = q.Column(columns...)
		}
		if err := q.Scan(ctx); err != nil {
			return nil, fmt.Errorf("failed to get records by UUIDs: %w", err)
		}
		records = append(records, page...)
	}
	return records, nil
}

// GetRecordsByUUIDs retrieves HTTP records matching the given UUIDs.
func (r *Repository) GetRecordsByUUIDs(ctx context.Context, uuids []string) ([]*HTTPRecord, error) {
	return r.getRecordsByUUIDs(ctx, uuids)
}

// ExistingRecordUUIDs returns the subset of uuids that exist. It selects the
// uuid column straight into a []string, so validating a caller-supplied list
// costs neither the raw_request/raw_response blobs nor an HTTPRecord struct per
// row.
//
// The answer is always scoped to a project, blank meaning the default one as
// everywhere else in this package. The scoping is not optional because
// enforcing ownership is this method's whole purpose: record UUIDs are
// globally unique, so an unscoped check answers "does this row exist anywhere"
// when the question is "does the caller own it", and a caller who learns one
// UUID from another engagement could pull its traffic into their own scan. An
// opt-out parameter would make the safe and unsafe calls look identical.
func (r *Repository) ExistingRecordUUIDs(ctx context.Context, projectUUID string, uuids []string) ([]string, error) {
	if len(uuids) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(uuids))
	for chunk := range slices.Chunk(uuids, SQLChunkSize) {
		var page []string
		err := r.db.NewSelect().
			Model((*HTTPRecord)(nil)).
			Column("uuid").
			Where("uuid IN (?)", bun.List(chunk)).
			Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
			Scan(ctx, &page)
		if err != nil {
			return nil, fmt.Errorf("failed to get record UUIDs: %w", err)
		}
		out = append(out, page...)
	}
	return out, nil
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

	// The template's `*` segments are the wildcards; a `%` or `_` in the stored
	// path itself is data and must not widen the match.
	likePattern := LikeGlob(PathToTemplate(source.Path))

	// Fetch more than the limit to allow post-filter by path depth
	fetchLimit := limit * 3
	if fetchLimit < 30 {
		fetchLimit = 30
	}

	var candidates []*HTTPRecord
	err = r.db.NewSelect().
		Model(&candidates).
		Where("hostname = ?", source.Hostname).
		Where(WithLikeEscape("path LIKE ?"), likePattern).
		Where("uuid != ?", uuid).
		Order("created_at DESC").
		Limit(int64(fetchLimit)).
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
// its beautified form in place. The derivation is deriveResponseColumns, as at
// ingest, so a rewritten record hashes identically to one ingested with the new body.
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

	// No content type: response_title is not one of the columns this rewrites.
	cols := deriveResponseColumns(httpmsg.NewHttpResponse(rawResponse), "", rec.Path, rec.URL)

	result, err := r.db.NewUpdate().
		Model((*HTTPRecord)(nil)).
		Where("uuid = ?", uuid).
		Set("raw_response = ?", rawResponse).
		Set("response_hash = ?", cols.Hash).
		Set("response_norm_hash = ?", cols.NormHash).
		Set("response_words = ?", cols.Words).
		Set("response_content_length = ?", cols.ContentLength).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("OverwriteRecordResponseBody: update failed: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("OverwriteRecordResponseBody: no record found with uuid %s", uuid)
	}
	return nil
}

// HasRecordsFromSources reports whether projectUUID holds any record whose
// source is one of sources (an index probe on (project_uuid, source)).
func (r *Repository) HasRecordsFromSources(ctx context.Context, projectUUID string, sources []string) (bool, error) {
	if len(sources) == 0 {
		return false, nil
	}
	return r.db.NewSelect().Model((*HTTPRecord)(nil)).
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Where("source IN (?)", bun.List(sources)).
		Exists(ctx)
}

// GetRecordsWithResponseBody returns HTTP records that have a non-empty response body,
// using UUID-based cursor pagination. Only columns needed for batch secret scanning are selected.
func (r *Repository) GetRecordsWithResponseBody(ctx context.Context, projectUUID, afterUUID string, limit int, hosts ...HostTarget) ([]*HTTPRecord, error) {
	records, _, _, err := r.GetRecordsWithResponseBodyPage(ctx, projectUUID, afterUUID, limit, nil, hosts...)
	return records, err
}

// GetRecordsWithResponseBodyPage is GetRecordsWithResponseBody with a filter
// applied before any body is read: it pages the matching uuids (after
// afterUUID, at most limit), then fetches the secret-scan columns only for the
// uuids keep accepts (all of them when keep is nil, in one query). It returns
// the kept records in uuid order, the page's last uuid (the next cursor) and
// the page size before filtering; a page shorter than limit is the last.
func (r *Repository) GetRecordsWithResponseBodyPage(ctx context.Context, projectUUID, afterUUID string, limit int, keep func(uuid string) bool, hosts ...HostTarget) (records []*HTTPRecord, last string, pageLen int, err error) {
	page := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.Where("has_response = ?", true).
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
		return q.OrderExpr("uuid ASC").Limit(int64(limit))
	}
	columns := []string{"uuid", "hostname", "url", "has_response", "raw_response", "response_content_type"}
	if keep == nil {
		if err := page(r.db.NewSelect().Model(&records).Column(columns...)).Scan(ctx); err != nil {
			return nil, "", 0, fmt.Errorf("failed to query records with response body: %w", err)
		}
		if len(records) > 0 {
			last = records[len(records)-1].UUID
		}
		return records, last, len(records), nil
	}
	var uuids []string
	if err := page(r.db.NewSelect().Model((*HTTPRecord)(nil)).Column("uuid")).Scan(ctx, &uuids); err != nil {
		return nil, "", 0, fmt.Errorf("failed to query records with response body: %w", err)
	}
	if len(uuids) == 0 {
		return nil, "", 0, nil
	}
	kept := uuids[:0:0]
	for _, id := range uuids {
		if keep(id) {
			kept = append(kept, id)
		}
	}
	last, pageLen = uuids[len(uuids)-1], len(uuids)
	if len(kept) == 0 {
		return nil, last, pageLen, nil
	}
	if err := r.db.NewSelect().Model(&records).Column(columns...).
		Where("uuid IN (?)", bun.List(kept)).
		OrderExpr("uuid ASC").Scan(ctx); err != nil {
		return nil, "", 0, fmt.Errorf("failed to query records with response body: %w", err)
	}
	return records, last, pageLen, nil
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
		q = q.Limit(int64(limit))
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
		q = q.Limit(int64(limit))
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

// dbTimestampString renders t the way `driver` stores created_at/cursor_at, so a
// keyset comparison matches the very row the value was read back from.
//
// The two drivers need different precision and neither tolerates the other's:
//
// SQLite holds these columns as TEXT written by CURRENT_TIMESTAMP — second
// precision, "2006-01-02 15:04:05" — and compares them lexically. A fractional
// part appended there sorts after every stored value, so `created_at = ?` would
// match nothing.
//
// PostgreSQL holds a real `timestamp` with microsecond precision and compares
// numerically. Truncating to seconds moves a bound read out of the database to
// *before* every row written in that same second, making both `created_at < ?`
// and `created_at = ?` false. That is not a narrower window, it is a total one:
// the dynamic-assessment phase reports "0 items" against a database full of
// records, and the scan finishes clean because it never looked at anything.
//
// Callers all hold a *DB; take the driver from it rather than defaulting, so a
// new driver has to make this decision explicitly instead of inheriting SQLite's.
func dbTimestampString(driver string, t time.Time) string {
	if driver == driverPostgres {
		return t.UTC().Format("2006-01-02 15:04:05.000000")
	}
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
		q = q.Where("created_at >= ?", dbTimestampString(r.db.Driver(), since[0]))
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
// while {Scheme,Hostname,Port} matches the exact origin.
//
// The origins are grouped by which fields they constrain into at most four
// row-value IN terms under one hostname IN prefilter. One OR term
// per origin nested the expression past SQLite's depth limit (1000) on a
// large host list, and assessment paging failed outright.
func applyHostScopeFilter(q *bun.SelectQuery, hosts []HostTarget) *bun.SelectQuery {
	if len(hosts) == 0 {
		return q
	}
	type shp struct {
		scheme, host string
		port         int
	}
	seen := make(map[shp]struct{}, len(hosts))
	hostSet := make(map[string]struct{}, len(hosts))
	var allHosts []string
	var full, schemeHost, hostPort, hostOnly []shp
	for _, h := range hosts {
		k := shp{h.Scheme, h.Hostname, h.Port}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		if _, ok := hostSet[h.Hostname]; !ok {
			hostSet[h.Hostname] = struct{}{}
			allHosts = append(allHosts, h.Hostname)
		}
		switch {
		case h.Scheme != "" && h.Port != 0:
			full = append(full, k)
		case h.Scheme != "":
			schemeHost = append(schemeHost, k)
		case h.Port != 0:
			hostPort = append(hostPort, k)
		default:
			hostOnly = append(hostOnly, k)
		}
	}

	var terms []string
	var args []interface{}
	values := func(n, width int) string {
		row := "(" + strings.TrimSuffix(strings.Repeat("?, ", width), ", ") + ")"
		rows := make([]string, n)
		for i := range rows {
			rows[i] = row
		}
		return strings.Join(rows, ", ")
	}
	if len(full) > 0 {
		terms = append(terms, "(scheme, hostname, port) IN (VALUES "+values(len(full), 3)+")")
		for _, k := range full {
			args = append(args, k.scheme, k.host, k.port)
		}
	}
	if len(schemeHost) > 0 {
		terms = append(terms, "(scheme, hostname) IN (VALUES "+values(len(schemeHost), 2)+")")
		for _, k := range schemeHost {
			args = append(args, k.scheme, k.host)
		}
	}
	if len(hostPort) > 0 {
		terms = append(terms, "(hostname, port) IN (VALUES "+values(len(hostPort), 2)+")")
		for _, k := range hostPort {
			args = append(args, k.host, k.port)
		}
	}
	if len(hostOnly) > 0 {
		names := make([]string, len(hostOnly))
		for i, k := range hostOnly {
			names[i] = k.host
		}
		terms = append(terms, "hostname IN (?)")
		args = append(args, bun.List(names))
	}
	q = q.Where("hostname IN (?)", bun.List(allHosts))
	return q.Where("("+strings.Join(terms, " OR ")+")", args...)
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

// SetRecordTechnology batch-writes the detected technology stack onto
// HTTPRecords identified by UUID, replacing whatever the column held.
//
// Replace rather than merge (the shape AppendRemarks uses) because technology is
// not accumulated analyst annotation: it is the fingerprint modules' verdict
// about the host, recomputed from scratch on every scan, and a merge would make
// a record carry a stack the target stopped running two scans ago.
//
// Records are grouped by their technology list before writing, because the
// source is host-scoped: every record on one host shares one list, so a corpus
// of N records over H hosts costs H UPDATEs rather than N. The per-value UUID
// set is still chunked so a single busy host cannot build an IN() clause past
// the driver's parameter limit.
func (r *Repository) SetRecordTechnology(ctx context.Context, technology map[string][]string) error {
	if len(technology) == 0 {
		return nil
	}

	// Group UUIDs by their technology list, keyed on a cheap join rather than on
	// the marshaled JSON. Marshaling to build the key would encode once per
	// RECORD to produce a handful of distinct values - on a 200k-record scan with
	// one detected stack that is 200k throwaway encodings to learn what five
	// would have said. The JSON is produced once per group, at the point it is
	// written.
	byValue := make(map[string][]string, len(technology))
	for uuid, tech := range technology {
		if uuid == "" || len(tech) == 0 {
			continue
		}
		byValue[strings.Join(tech, "\x00")] = append(byValue[strings.Join(tech, "\x00")], uuid)
	}
	if len(byValue) == 0 {
		return nil
	}

	const batchSize = 500
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		for key, uuids := range byValue {
			encoded, err := json.Marshal(strings.Split(key, "\x00"))
			if err != nil {
				continue
			}
			for chunk := range slices.Chunk(uuids, batchSize) {
				if _, err := tx.NewUpdate().
					Model((*HTTPRecord)(nil)).
					Set("technology = ?", string(encoded)).
					Where("uuid IN (?)", bun.List(chunk)).
					Exec(ctx); err != nil {
					return fmt.Errorf("failed to set record technology: %w", err)
				}
			}
		}
		return nil
	})
}

// AppendRemarks batch-appends remarks to HTTPRecords identified by UUID.
// Existing remarks are preserved and duplicates within each record are deduplicated.
//
// The read and the merged write happen in ONE transaction. Remarks are a growing
// set written by several analysis passes against the same records, and reading
// the current value outside the transaction turns every append into a read-
// modify-write race: two passes both read ["a"], both write their own merge, and
// whichever commits second silently drops the other's remark. The symptom is a
// missing annotation, which looks like the analysis never fired.
//
// SQLite's write lock serializes the transactions outright. On PostgreSQL the
// rows are locked FOR UPDATE, so a concurrent appender blocks on the read rather
// than proceeding from a stale copy.
func (r *Repository) AppendRemarks(ctx context.Context, annotations map[string][]string) error {
	if len(annotations) == 0 {
		return nil
	}

	uuids := make([]string, 0, len(annotations))
	for uuid, newRemarks := range annotations {
		if len(newRemarks) > 0 {
			uuids = append(uuids, uuid)
		}
	}
	if len(uuids) == 0 {
		return nil
	}

	// Track the first update failure so a systemic problem surfaces to the
	// caller (every caller logs the returned error) while a single bad record
	// doesn't abort annotation of the rest.
	var firstErr error
	err := r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		// Load the current remarks in the same transaction that writes the merge,
		// batched (rather than one SELECT per record) and chunked so a large
		// annotation pass does not build one enormous IN() list.
		existingByUUID := make(map[string][]string, len(uuids))
		for chunk := range slices.Chunk(uuids, SQLChunkSize) {
			var existing []HTTPRecord
			q := tx.NewSelect().
				Model(&existing).
				Column("uuid", "remarks").
				Where("uuid IN (?)", bun.List(chunk))
			if r.db.Driver() == "postgres" {
				q = q.For("UPDATE")
			}
			if err := q.Scan(ctx); err != nil {
				return fmt.Errorf("failed to load existing remarks: %w", err)
			}
			for i := range existing {
				existingByUUID[existing[i].UUID] = existing[i].Remarks
			}
		}

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

// Score columns on http_records that updateScoreColumn may write. They are
// package constants rather than caller-supplied strings because the column name
// is interpolated straight into the UPDATE statement: a name that could reach
// here from outside the package would be an injection point.
const (
	scoreColumnRisk    = "risk_score"
	scoreColumnSurface = "surface_score"
)

// UpdateRiskScores batch-updates risk_score on HTTPRecords identified by UUID.
// Uses CASE/WHEN SQL to update up to 500 records per statement, minimizing roundtrips.
func (r *Repository) UpdateRiskScores(ctx context.Context, scores map[string]int) error {
	return r.updateScoreColumn(ctx, scoreColumnRisk, scores)
}

// UpdateSurfaceScores batch-updates surface_score on HTTPRecords identified by
// UUID. Written by the surface_scoring passive module; see HTTPRecord.SurfaceScore
// for why this is a separate column from risk_score rather than a second writer
// of the same one.
func (r *Repository) UpdateSurfaceScores(ctx context.Context, scores map[string]int) error {
	return r.updateScoreColumn(ctx, scoreColumnSurface, scores)
}

// updateScoreColumn batch-updates one integer score column on HTTPRecords
// identified by UUID. column must be one of the scoreColumn* constants.
func (r *Repository) updateScoreColumn(ctx context.Context, column string, scores map[string]int) error {
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
			if err := updateScoreBatch(ctx, tx, column, scores, uuids[i:end]); err != nil {
				return err
			}
		}
		return nil
	})
}

// updateScoreBatch executes a single CASE/WHEN UPDATE for a batch of UUIDs.
func updateScoreBatch(ctx context.Context, tx bun.Tx, column string, scores map[string]int, uuids []string) error {
	// Build: UPDATE http_records SET <column> = CASE uuid WHEN ? THEN ? ... END WHERE uuid IN (?,...)
	// Each UUID contributes 2 args to CASE + 1 arg to IN = 3 args per UUID.
	// Batch of 500 = 1500 args, well within SQLITE_MAX_VARIABLE_NUMBER (999 default raised in modern builds).
	args := make([]interface{}, 0, len(uuids)*3)
	var caseSQL strings.Builder
	// ~16 bytes of "WHEN ? THEN ? " and ",?" per uuid plus the fixed clauses. A
	// 500-uuid batch builds ~8 KB, which from a zero-length Builder costs ~13
	// doubling reallocations and ~16 KB copied.
	caseSQL.Grow(len(uuids)*16 + 64)
	caseSQL.WriteString("UPDATE http_records SET ")
	caseSQL.WriteString(column)
	caseSQL.WriteString(" = CASE uuid ")
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
		return fmt.Errorf("failed to batch update %s: %w", column, err)
	}
	return nil
}
