package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// Canonical values for http_records.source. Kept here (rather than inline
// string literals at call sites) so the scan-on-receive filter and the
// ingest writers agree on a single set of labels.
const (
	RecordSourceIngestServer = "ingest-server" // POST /api/ingest-http
	// RecordSourceIngestContext marks ingested traffic for a host outside the
	// scope derived from its capture (SAFE-4): stored as context, never fed
	// to scan-on-receive (not in IngestRecordSources).
	RecordSourceIngestContext = "ingest-context"
	RecordSourceIngestProxy   = "ingest-proxy" // transparent ingest proxy capture
	RecordSourceIngestCLI     = "ingest-cli"   // `vigolium ingest ...` command
	RecordSourceScanner       = "scanner"      // executor feedback re-injection
	RecordSourceProbe         = "probe"        // `vigolium run probe` host sweep (one request per target, no fuzzing)
	RecordSourceFingerprint   = "fingerprint"  // `vigolium fingerprint`: the per-origin reads the fingerprint phase sent
	RecordSourceHarvest       = "harvest"      // external-harvest archive URL; request-only until harvest-probe completes it
	RecordSourceFinding       = "finding"      // request/response attached to a finding (native modules and known-issue scan)
	RecordSourceBurp          = "burp"         // Burp Suite, via the loopback bridge or a push to /api/ingest-http
	RecordSourceCaido         = "caido"        // Caido, via the loopback bridge or a push to /api/ingest-http
	RecordSourceParamMining   = "param-mining" // request carrying a hidden parameter the param-mining phase confirmed
)

// legacyKISEvidenceSource is the label known-issue-scan evidence was stored
// under before it used RecordSourceFinding. Read only by the one-time relabel
// in CreateSchema and by evidence filters that must still match old rows.
const legacyKISEvidenceSource = "spa"

// BridgeRecordSources lists the http_records.source values a loopback bridge
// listener can produce. Which one a given record gets is decided by the
// implementation identity the listener reports (see pkg/burpbridge), not by the
// flag spelling the user typed — --burp-bridge-url and --caido-bridge-url are
// one flag pointing at one protocol.
var BridgeRecordSources = []string{
	RecordSourceBurp,
	RecordSourceCaido,
}

// IsBridgeRecordSource reports whether a source label names a bridge vendor.
// Case-insensitive, since it answers both a user-typed --source and a header
// value written by a plugin.
//
// This is the single answer to "is this label a bridge vendor" — the traffic
// and replay record selection ask it to decide whether a --source filter can be
// satisfied by live bridge traffic at all, and the ingest endpoint asks it to
// decide whether a client may claim the label. A second copy of the list is how
// a third vendor ends up working on one path and not the other.
func IsBridgeRecordSource(source string) bool {
	return utils.StringSliceContains(BridgeRecordSources, source)
}

// EvidenceRecordSources are the http_records.source values stamped on a
// finding's own evidence row (the record kind of the result that saved it, and
// the legacy known-issue-scan label), as opposed to a record that was scanned.
// `finding verify` uses the difference to tell a finding's baseline from its
// payload request on rows written before findings.origin_record_uuid existed,
// and the assessment sources exclude them so a finding's payload-bearing
// request is never rescanned as input on the next run.
var EvidenceRecordSources = []string{RecordKindFinding, RecordKindCandidate, RecordKindObservation, legacyKISEvidenceSource}

// applyEvidenceExclusion drops finding-evidence rows (EvidenceRecordSources).
func applyEvidenceExclusion(q *bun.SelectQuery) *bun.SelectQuery {
	return q.Where("COALESCE(source, '') NOT IN (?)", bun.List(EvidenceRecordSources))
}

// IngestRecordSources lists the http_records.source values that represent
// user-ingested traffic. Scan-on-receive filters the DBInputSource by this
// list so it only processes traffic the user actually ingested — excluding
// scanner-produced artefacts that would otherwise cause fan-out.
//
// The bridge vendors belong here for the same reason ingest-server does: a
// record that arrived from Burp or Caido is traffic the user deliberately
// handed over, whether it was pulled in by `traffic --save-to-vigolium-db` /
// `import -B` or pushed to /api/ingest-http by the plugin. Omitting them is
// silent — the rows land in the database and scan-on-receive simply never
// polls them, with no error to explain why nothing was scanned.
var IngestRecordSources = []string{
	RecordSourceIngestServer,
	RecordSourceIngestProxy,
	RecordSourceIngestCLI,
	RecordSourceBurp,
	RecordSourceCaido,
}

// DBInputSource polls the database for HTTP records after the scan cursor and provides
// them as WorkItems. It implements source.InputSource.
type DBInputSource struct {
	db             *DB
	repo           *Repository
	scanUUID       string
	pollInterval   time.Duration
	oneShot        bool // when true, return io.EOF instead of polling when no records remain
	closed         atomic.Bool
	hostScopes     []HostTarget // when non-empty, only records matching these in-scope origins (scheme/host/port) are returned
	includeSources []string     // when non-empty, only records with source IN this list are returned
	pageSize       int
	idleTimeout    time.Duration // when > 0, Next returns io.EOF after this long without any new rows

	// lastActivityNs holds UnixNano of the most recent moment we observed a new
	// row from the database (or the source creation time if no rows have ever
	// been seen). Updated whenever fetchNextBatch returns rows. Read by Next()
	// to enforce idleTimeout, and by IdleFor() for status reporting.
	lastActivityNs atomic.Int64

	// onActivity, when set, is invoked from fetchNextBatch whenever a non-empty
	// batch is fetched. Lets the runner surface "scan started / scan resumed" log
	// lines without waiting for the next status tick. The recordCount is the
	// batch size and idleFor is how long we'd been quiet *before* this batch.
	// firstBatchSeen distinguishes the very first call from steady-state polls.
	onActivity     func(recordCount int, idleFor time.Duration, firstBatch bool)
	firstBatchSeen atomic.Bool

	mu             sync.Mutex
	buffer         []*HTTPRecord
	readCursorInit bool
	projectUUID    string // the owning scan's project; scopes record selection (resolved on init)
	readCursorAt   time.Time
	readCursorUUID string
	startAt        time.Time // the durable cursor this source started from
	nextSeq        uint64
	nextAckSeq     uint64
	pendingBySeq   map[uint64]*cursorAck

	// served remembers records already handed out whose created_at is inside
	// the lookback window, so the polling re-read (pollLookback) never serves
	// one twice. Pruned as the read cursor moves past the window.
	served map[string]time.Time
	// servedPrunedAt is the cursor second served was last pruned at.
	servedPrunedAt time.Time
	// ackMaxAt/ackMaxUUID are the furthest key the durable cursor was moved
	// to; a late record served from the lookback must never move it back.
	ackMaxAt   time.Time
	ackMaxUUID string

	// count is the eligible-record snapshot taken on the first fetch; see Count.
	count atomic.Int64
}

// pollLookback is how far behind the read cursor a polling source re-reads.
// On SQLite created_at has one-second resolution and the keyset tie-breaks on
// a random UUID, so a record committed in the cursor's second with a smaller
// UUID (or a little late, by another writer) sits behind the cursor and a
// strict keyset never serves it.
const pollLookback = 2 * time.Second

// maxLookbackRows bounds the lookback re-read per poll.
const maxLookbackRows = 512

type cursorAck struct {
	seq       uint64
	createdAt time.Time
	uuid      string
	acked     bool
}

// NewDBInputSource creates a new DBInputSource that polls for records after the scan cursor at the given interval.
func NewDBInputSource(db *DB, repo *Repository, scanUUID string, pollInterval time.Duration) *DBInputSource {
	s := &DBInputSource{
		db:           db,
		repo:         repo,
		scanUUID:     scanUUID,
		pollInterval: pollInterval,
	}
	s.lastActivityNs.Store(time.Now().UnixNano())
	return s
}

// NewOneShotDBInputSource creates a DBInputSource that returns io.EOF
// when no records remain after the cursor, instead of polling indefinitely.
func NewOneShotDBInputSource(db *DB, repo *Repository, scanUUID string) *DBInputSource {
	return &DBInputSource{
		db:       db,
		repo:     repo,
		scanUUID: scanUUID,
		oneShot:  true,
	}
}

// WithPageSize sets the number of records fetched from the database per batch.
func (s *DBInputSource) WithPageSize(pageSize int) *DBInputSource {
	if pageSize > 0 {
		s.pageSize = pageSize
	}
	return s
}

// WithHostScopes sets an in-scope origin filter so only records matching these
// (scheme, hostname, port) origins are returned. This keeps HTTP records from unrelated
// origins — including the same host on a different port left over from a previous scan
// (e.g. localhost:8080 when targeting localhost:3000) — out of the scan.
func (s *DBInputSource) WithHostScopes(hosts []HostTarget) *DBInputSource {
	s.hostScopes = hosts
	return s
}

// WithIncludeSources restricts the source to records whose http_records.source
// value is in the given list. Used by scan-on-receive shallow mode to exclude
// scanner-produced artefacts (source="finding", source="scanner", etc.) so
// the scan only processes user-ingested traffic and doesn't fan out across
// records that were created as byproducts of scanning itself.
// An empty slice disables the filter (default).
func (s *DBInputSource) WithIncludeSources(sources []string) *DBInputSource {
	s.includeSources = sources
	return s
}

// WithIdleTimeout configures the source to return io.EOF after this long without
// any new rows arriving from the database. Only honored in polling mode (not oneShot).
// Zero (the default) keeps the original behavior — poll forever. Typical use: one-shot
// scan-on-receive where the caller wants the scan to terminate once the ingestion
// pipeline has settled.
func (s *DBInputSource) WithIdleTimeout(timeout time.Duration) *DBInputSource {
	if timeout > 0 {
		s.idleTimeout = timeout
	}
	return s
}

// IdleFor returns how long it has been since the source last observed a new row
// (or since creation, if none have arrived yet). Useful for status reporting to
// tell the user "scan is idle — server is still listening for more records."
func (s *DBInputSource) IdleFor() time.Duration {
	last := s.lastActivityNs.Load()
	if last == 0 {
		return 0
	}
	return time.Since(time.Unix(0, last))
}

// WithOnActivity registers a callback invoked once per non-empty fetch batch.
// firstBatch is true for the very first batch ever returned by this source.
// idleFor is the duration the source had been quiet *before* this batch landed.
// Callers typically use this to print a "scan started / resumed" line so the
// user gets immediate feedback rather than waiting for the next status tick.
func (s *DBInputSource) WithOnActivity(fn func(recordCount int, idleFor time.Duration, firstBatch bool)) *DBInputSource {
	s.onActivity = fn
	return s
}

// Next returns the next record after the scan cursor as a WorkItem.
// It blocks (polling) until a record is available, the context is cancelled, or the source is closed.
func (s *DBInputSource) Next(ctx context.Context) (*work.WorkItem, error) {
	for {
		if s.closed.Load() {
			return nil, io.EOF
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		record, seq, err := s.nextBufferedRecord(ctx)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				if s.oneShot {
					return nil, io.EOF
				}
				// Opt-in: terminate after a quiet period with no new rows.
				// Needed for one-shot server runs; daemon mode leaves idleTimeout=0.
				if s.idleTimeout > 0 && s.IdleFor() >= s.idleTimeout {
					return nil, io.EOF
				}
				// No records after cursor — wait and retry
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(s.pollInterval):
					continue
				}
			}
			zap.L().Debug("DBInputSource: error fetching record", zap.Error(err))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(s.pollInterval):
				continue
			}
		}

		item, err := s.workItemFromRecord(record, seq)
		if err != nil {
			zap.L().Warn("DBInputSource: failed to convert record",
				zap.String("uuid", record.UUID), zap.Error(err))
			continue
		}
		return item, nil
	}
}

func (s *DBInputSource) nextBufferedRecord(ctx context.Context) (*HTTPRecord, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.buffer) == 0 {
		records, err := s.fetchNextBatch(ctx)
		if err != nil {
			return nil, 0, err
		}
		s.buffer = records
	}

	if len(s.buffer) == 0 {
		return nil, 0, sql.ErrNoRows
	}

	record := s.buffer[0]
	s.buffer = s.buffer[1:]
	s.nextSeq++
	if s.nextAckSeq == 0 {
		s.nextAckSeq = 1
	}
	if s.pendingBySeq == nil {
		s.pendingBySeq = make(map[uint64]*cursorAck)
	}
	s.pendingBySeq[s.nextSeq] = &cursorAck{
		seq:       s.nextSeq,
		createdAt: record.CreatedAt,
		uuid:      record.UUID,
	}
	return record, s.nextSeq, nil
}

// fetchNextRecord finds the next record after the scan's current cursor position
// and advances the cursor atomically within a single transaction.
func (s *DBInputSource) fetchNextBatch(ctx context.Context) ([]*HTTPRecord, error) {
	if !s.readCursorInit {
		scan, err := s.repo.GetScanByUUID(ctx, s.scanUUID)
		if err != nil {
			return nil, err
		}
		s.readCursorAt = scan.CursorAt
		s.readCursorUUID = scan.CursorUUID
		s.startAt = scan.CursorAt
		s.ackMaxAt, s.ackMaxUUID = scan.CursorAt, scan.CursorUUID
		s.projectUUID = scan.ProjectUUID
		s.readCursorInit = true
		s.captureCount(ctx)
	}

	// Select next records after cursor.
	// Format cursor as plain string to match SQLite's CURRENT_TIMESTAMP format —
	// bun serializes time.Time with timezone suffix that breaks text comparison.
	var records []*HTTPRecord
	// Project only scanRecordColumns — the columns the scan feed consumes —
	// avoiding the parameters/technology/remarks jsonb columns and ~25 unused
	// scalar columns per record. The hostname/source WHERE filters below don't
	// require selecting those columns. Modules receive the reconstructed
	// HttpRequestResponse, never the HTTPRecord, so no consumer reads the rest.
	q := s.applyEligibility(s.db.NewSelect().Model(&records).
		Column(scanRecordColumns...))

	limit := s.pageSize
	if limit <= 0 {
		limit = 128
	}
	if err := q.OrderExpr("created_at ASC, uuid ASC").Limit(int64(limit)).Scan(ctx); err != nil {
		return nil, err
	}
	if !s.oneShot {
		late, err := s.lookbackLocked(ctx)
		if err != nil {
			return nil, err
		}
		records = append(late, records...)
	}
	if len(records) == 0 {
		return nil, sql.ErrNoRows
	}

	for _, rec := range records {
		if s.served == nil {
			s.served = make(map[string]time.Time)
		}
		s.served[rec.UUID] = rec.CreatedAt
		if rec.CreatedAt.After(s.readCursorAt) || (rec.CreatedAt.Equal(s.readCursorAt) && rec.UUID > s.readCursorUUID) {
			s.readCursorAt = rec.CreatedAt
			s.readCursorUUID = rec.UUID
		}
	}
	s.pruneServedLocked()

	// Compute idle duration BEFORE updating lastActivityNs so the callback
	// reflects the gap that just ended, not zero.
	prevNs := s.lastActivityNs.Load()
	var idleFor time.Duration
	if prevNs > 0 {
		idleFor = time.Since(time.Unix(0, prevNs))
	}
	s.lastActivityNs.Store(time.Now().UnixNano())

	if s.onActivity != nil {
		firstBatch := s.firstBatchSeen.CompareAndSwap(false, true)
		s.onActivity(len(records), idleFor, firstBatch)
	}

	return records, nil
}

// lookbackLocked returns records inside the lookback window behind the read
// cursor (created_at >= cursor − pollLookback, at or before the cursor key)
// that were never served. It reads keys first and fetches the scan columns for
// unseen rows only, so a poll over a window of already-served records does not
// re-read their bodies. Caller holds s.mu.
func (s *DBInputSource) lookbackLocked(ctx context.Context) ([]*HTTPRecord, error) {
	if s.readCursorAt.IsZero() {
		return nil, nil
	}
	from := dbTimestampString(s.db.Driver(), s.readCursorAt.Add(-pollLookback))
	at := dbTimestampString(s.db.Driver(), s.readCursorAt)
	var keys []*HTTPRecord
	q := s.db.NewSelect().Model(&keys).Column("uuid", "created_at").
		Where("created_at >= ?", from).
		Where("(created_at < ? OR (created_at = ? AND uuid <= ?))", at, at, s.readCursorUUID)
	q = applyHostScopeFilter(q, s.hostScopes)
	q = applyProjectFilter(q, s.projectUUID)
	if len(s.includeSources) > 0 {
		q = q.Where("source IN (?)", bun.List(s.includeSources))
	}
	if err := q.OrderExpr("created_at ASC, uuid ASC").Limit(maxLookbackRows).Scan(ctx); err != nil {
		return nil, err
	}
	var unseen []string
	for _, k := range keys {
		if _, seen := s.served[k.UUID]; seen {
			continue
		}
		// A record at or before the durable cursor that was never served by
		// this source predates it (a resumed source's earlier run handled it).
		if !s.servedSince(k) {
			continue
		}
		unseen = append(unseen, k.UUID)
	}
	if len(unseen) == 0 {
		return nil, nil
	}
	var rows []*HTTPRecord
	if err := s.db.NewSelect().Model(&rows).Column(scanRecordColumns...).
		Where("uuid IN (?)", bun.List(unseen)).
		OrderExpr("created_at ASC, uuid ASC").Scan(ctx); err != nil {
		return nil, err
	}
	return rows, nil
}

// servedSince reports whether r could have been missed by this source: it was
// created after the cursor this source started from, minus the lookback.
// Records older than that belong to a previous run's committed range.
func (s *DBInputSource) servedSince(r *HTTPRecord) bool {
	return s.startAt.IsZero() || !r.CreatedAt.Before(s.startAt.Add(-pollLookback))
}

// pruneServedLocked forgets served records the lookback can no longer reach.
// The floor only moves when the read cursor enters a new second, so the map is
// walked at most once per second of cursor progress rather than every batch.
func (s *DBInputSource) pruneServedLocked() {
	sec := s.readCursorAt.Truncate(time.Second)
	if !sec.After(s.servedPrunedAt) {
		return
	}
	s.servedPrunedAt = sec
	floor := s.readCursorAt.Add(-2 * pollLookback)
	for id, at := range s.served {
		if at.Before(floor) {
			delete(s.served, id)
		}
	}
}

// applyEligibility restricts q to the records this source will serve: after the
// read cursor, in the in-scope origins, in the owning project, and from the
// allowed sources. One builder for both the page query and the Count snapshot,
// so the count is over exactly the rows iteration walks. Caller holds s.mu (it
// reads the cursor).
func (s *DBInputSource) applyEligibility(q *bun.SelectQuery) *bun.SelectQuery {
	if !s.readCursorAt.IsZero() {
		cursorAt := dbTimestampString(s.db.Driver(), s.readCursorAt)
		q = q.Where("(created_at > ? OR (created_at = ? AND uuid > ?))",
			cursorAt, cursorAt, s.readCursorUUID)
	}

	q = applyHostScopeFilter(q, s.hostScopes)
	q = applyProjectFilter(q, s.projectUUID)

	if len(s.includeSources) > 0 {
		q = q.Where("source IN (?)", bun.List(s.includeSources))
	}
	return q
}

// captureCount snapshots how many records are eligible right now, once, on the
// first fetch (when the cursor and project are first known). A failed count
// leaves the figure at 0 — "unknown" — rather than failing the fetch: the count
// is a progress reading, and the scan must not stop for the want of one. Caller
// holds s.mu.
func (s *DBInputSource) captureCount(ctx context.Context) {
	n, err := s.applyEligibility(s.db.NewSelect().Model((*HTTPRecord)(nil))).Count(ctx)
	if err != nil {
		zap.L().Debug("DBInputSource: count eligible records", zap.Error(err))
		return
	}
	s.count.Store(int64(n))
}

// Count implements source.Countable: the number of records that were eligible
// when the source first read from the database, or 0 before its first Next.
//
// An upper bound at the moment it is taken, not a promise: a polling source
// keeps serving records that arrive later, so Done can pass it, and a consumer
// reporting progress must clamp (the phase tracker does). It is deliberately
// NOT computed when the executor is built — callers size caches off a known
// total at construction, and a database round-trip there would change that
// behaviour for every DB-fed scan.
func (s *DBInputSource) Count() int64 {
	return s.count.Load()
}

func (s *DBInputSource) workItemFromRecord(record *HTTPRecord, seq uint64) (*work.WorkItem, error) {
	rr, err := s.recordToHttpRequestResponse(record)
	if err != nil {
		// A record that can't be converted will never succeed. Acknowledge its
		// cursor slot (ack marks it processed and drains the contiguous head)
		// rather than deleting it. Deleting left a permanent hole in pendingBySeq
		// when earlier records were still un-acked: the contiguous ack-drain stops
		// at that missing seq forever, freezing the durable cursor and
		// processed_count just before the malformed row for the source's lifetime.
		s.ack(seq)
		return nil, err
	}

	var once sync.Once
	item := work.NewWithCallback(rr, nil, func() {
		once.Do(func() {
			s.ack(seq)
		})
	})
	item.RecordUUID = record.UUID
	return item, nil
}

func (s *DBInputSource) ack(seq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ack, ok := s.pendingBySeq[seq]
	if !ok {
		return
	}
	ack.acked = true

	// Drain the contiguous run of acked records from the head, then advance the
	// cursor ONCE to the furthest record with delta = run length. The cursor
	// keyset is monotonic, so the final (createdAt, uuid) covers every record in
	// between and processed_count increments by the run length — identical to a
	// per-record advance, but one UPDATE instead of N. At the ingest rate, the
	// per-record UPDATE contended with the RecordWriter for the SQLite write
	// lock; coalescing collapses that to one write per drain. Still done under
	// s.mu so cursor advances stay serialized and monotonic.
	var (
		advanced int64
		lastAt   time.Time
		lastUUID string
	)
	for {
		head, ok := s.pendingBySeq[s.nextAckSeq]
		if !ok || !head.acked {
			break
		}
		delete(s.pendingBySeq, s.nextAckSeq)
		s.nextAckSeq++
		advanced++
		// The furthest key, not the last: a late record served from the
		// lookback sits behind keys already acknowledged.
		if head.createdAt.After(s.ackMaxAt) || (head.createdAt.Equal(s.ackMaxAt) && head.uuid > s.ackMaxUUID) {
			s.ackMaxAt, s.ackMaxUUID = head.createdAt, head.uuid
		}
		lastAt, lastUUID = s.ackMaxAt, s.ackMaxUUID
	}

	if advanced > 0 {
		if err := s.repo.AdvanceScanCursorBy(context.Background(), s.scanUUID, lastAt, lastUUID, advanced); err != nil {
			zap.L().Warn("DBInputSource: failed to acknowledge cursor", zap.Error(err))
		}
	}
}

// recordToHttpRequestResponse converts an HTTPRecord back to HttpRequestResponse.
func (s *DBInputSource) recordToHttpRequestResponse(record *HTTPRecord) (*httpmsg.HttpRequestResponse, error) {
	return recordToHttpRequestResponse(record)
}

// RecordToHttpRequestResponse converts an HTTPRecord back to HttpRequestResponse.
// Exported for use by the agent input normalizer and other packages.
func RecordToHttpRequestResponse(record *HTTPRecord) (*httpmsg.HttpRequestResponse, error) {
	return recordToHttpRequestResponse(record)
}

// recordToHttpRequestResponse converts an HTTPRecord back to HttpRequestResponse.
// The record's stored URL (which carries the original scheme) is preferred over
// re-parsing the raw request bytes, since origin-form HTTP requests on the wire
// don't encode the scheme and would otherwise default to http.
func recordToHttpRequestResponse(record *HTTPRecord) (*httpmsg.HttpRequestResponse, error) {
	// Prefer raw request if available
	if len(record.RawRequest) > 0 {
		var rr *httpmsg.HttpRequestResponse
		var err error
		if record.URL != "" {
			rr, err = httpmsg.ParseRawRequestWithURL(string(record.RawRequest), record.URL)
		} else {
			rr, err = httpmsg.ParseRawRequest(string(record.RawRequest))
		}
		if err != nil {
			return nil, err
		}
		// Attach response if present
		if resp := record.ParsedResponse(); resp != nil {
			rr = rr.WithResponse(resp)
		}
		return rr, nil
	}

	// Fallback: construct from URL
	if record.URL != "" {
		return httpmsg.GetRawRequestFromURL(record.URL)
	}

	return nil, io.EOF
}

// Close stops the source. After Close, Next will return io.EOF.
func (s *DBInputSource) Close() error {
	s.closed.Store(true)
	return nil
}

// applyProjectFilter scopes a record query to the owning scan's project, so a
// scan in one project can never consume another project's records even when both
// contain the same origin (host scope alone is not a tenancy boundary). An empty
// projectUUID (unknown/legacy) leaves the query unscoped, preserving prior
// behavior for single-project databases.
func applyProjectFilter(q *bun.SelectQuery, projectUUID string) *bun.SelectQuery {
	if projectUUID != "" {
		return q.Where("project_uuid = ?", projectUUID)
	}
	return q
}

// riskPrefetchBatchSize bounds how many records the RiskPrioritized source pulls
// from the database per round-trip. Mirrors DBInputSource's batched read so the
// single feed goroutine isn't serialized on one GetRecordByUUID query per item
// (the dynamic-assessment workers do no network I/O under SkipBaseline, so the
// per-item DB read+parse would otherwise be the throughput ceiling for large scans).
const riskPrefetchBatchSize = 128

// RiskPrioritizedDBInputSource processes high-risk records first, then falls back
// to normal cursor-based order. It implements source.InputSource.
//
// Delivery is AT-LEAST-ONCE. The durable cursor advances only once every item in
// the round has been acknowledged or written off, so a round cut short re-serves
// its tail on the next pass rather than skipping it — duplicate work being far
// cheaper than a silent coverage hole. Two consequences follow from that choice
// and are accepted rather than fixed here:
//
//   - The checkpoint is `processed_count = processed_count + ?`, which is not
//     idempotent. A write that commits but reports an error (a connection lost
//     after the server applied it) is retried by FlushCursor and can double-count
//     processed_count. The cursor position itself is an absolute (created_at,
//     uuid) assignment and stays correct; only the counter can overshoot, and a
//     wrong progress number is a far smaller problem than a cursor past
//     unprocessed records.
//   - A record served twice is scanned twice. Findings dedup downstream, so the
//     visible cost is time rather than duplicate results.
type RiskPrioritizedDBInputSource struct {
	db                   *DB
	repo                 *Repository
	scanUUID             string
	hostScopes           []HostTarget // when non-empty, only records matching these in-scope origins (scheme/host/port) are returned
	maxParamShapeSamples int          // when > 0, coalesce same-shape GET records to this many value-distinct samples
	closed               atomic.Bool
	mu                   sync.Mutex

	loaded      bool   // snapshot upper bound captured on first Next
	hasBound    bool   // false → no eligible records (empty snapshot); Next returns EOF
	projectUUID string // owning scan's project; scopes every page query
	boundAt     time.Time
	boundID     string
	// resume cursor: the durable scan cursor captured at snapshot start; only
	// records strictly after it are eligible this round.
	resumeAt time.Time
	resumeID string

	// Keyset cursor, ordered (risk_score DESC, surface_score DESC, created_at
	// ASC, uuid ASC): high-risk records first, then — within a risk score — the
	// larger attack surface, then chronological. It walks one (risk, surface)
	// BUCKET at a time: inside a bucket the page query is an equality on both
	// scores plus a (created_at, uuid) range, which the
	// idx_records_project_risk_order index serves in order with no sort; when a
	// bucket runs dry the cursor steps to the next lower bucket (ECON-10). The
	// old single query `risk_score < ? OR (risk_score = ? AND …)` could not use
	// an index for its order, so every 128-row page re-sorted the whole
	// equal-score block.
	bucketSet     bool // a bucket is selected
	bucketRisk    int
	bucketSurface int
	keyAt         time.Time // last served (created_at, uuid) inside the bucket
	keyID         string
	started       bool // keyAt/keyID valid for the current bucket
	// lastPageInBucket: the page just pulled was short, so the bucket is
	// drained once the keyset advances past it.
	lastPageInBucket bool
	everStarted      bool // any page has been served

	buffer  []*HTTPRecord // full records for the current page's coalescing survivors
	bufHead int           // read cursor into buffer; lets refill reuse the backing array

	coalescer *paramShapeCoalescer // nil when coalescing is disabled

	total            int   // coalescing survivors committed to (each ends acked or skipped)
	acked            int   // survivors a worker acknowledged
	skipped          int   // survivors that can't be served (parse fail, missing/deleted, fetch error)
	committed        bool  // guards the one-shot cursor advance so it can't fire twice
	streamsExhausted bool  // the stream is drained → total is final, so the commit can fire
	commitErr        error // the last failed checkpoint attempt, cleared on success

	// count is the snapshot window's size, taken once with the bound; see Count.
	count atomic.Int64

	// Coverage-ledger options (ECON-4). noCommit: never advance the durable
	// cursor (a tier pass before the last one). coverage: load each page's
	// stored progress; records whose tier_done >= coverageMinTier are resolved
	// without being served, the rest carry their coverage on the item.
	// presetBound: use the given snapshot bound instead of capturing one, so a
	// later pass covers exactly the earlier pass's window.
	noCommit        bool
	coverage        bool
	coverageMinTier int
	presetBound     bool
	presetAt        time.Time
	presetID        string
	coverageByUUID  map[string]RecordCoverage
	// hasProgress: the scan had ledger rows when the bound was captured; when
	// false no page reads the ledger (nothing in it to skip or carry).
	hasProgress bool

	// advanceCursor is the durable checkpoint write, injectable so the failure
	// path is testable without a broken database. Defaults to the repository's
	// AdvanceScanCursorBy.
	advanceCursor func(ctx context.Context, scanUUID string, at time.Time, id string, delta int64) error
}

// NewRiskPrioritizedDBInputSource creates a DBInputSource that processes
// records with risk_score > 0 first (highest risk first), then continues
// with the normal cursor-based order for remaining records.
func NewRiskPrioritizedDBInputSource(db *DB, repo *Repository, scanUUID string) *RiskPrioritizedDBInputSource {
	return &RiskPrioritizedDBInputSource{
		db:       db,
		repo:     repo,
		scanUUID: scanUUID,
	}
}

// WithoutCursorCommit keeps the durable scan cursor where it is (ECON-4): a
// tier pass that is not the round's last must not move the cursor past
// records the later passes still have to cover.
func (s *RiskPrioritizedDBInputSource) WithoutCursorCommit() *RiskPrioritizedDBInputSource {
	s.noCommit = true
	return s
}

// WithCoverage reads the coverage ledger for every page (ECON-4): a record
// whose tier_done >= minTier is resolved without being served; any other
// record is served with its stored coverage on WorkItem.Coverage so the
// executor skips the modules and passive stage it already finished.
func (s *RiskPrioritizedDBInputSource) WithCoverage(minTier int) *RiskPrioritizedDBInputSource {
	s.coverage, s.coverageMinTier = true, minTier
	return s
}

// WithBound fixes the snapshot's upper bound instead of capturing it, so a
// later tier pass serves exactly the window an earlier pass did.
func (s *RiskPrioritizedDBInputSource) WithBound(at time.Time, id string) *RiskPrioritizedDBInputSource {
	s.presetBound, s.presetAt, s.presetID = true, at, id
	return s
}

// Bound reports the snapshot bound this source captured (valid after the
// first Next); ok is false for an empty snapshot.
func (s *RiskPrioritizedDBInputSource) Bound() (at time.Time, id string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.boundAt, s.boundID, s.hasBound
}

// WithHostScopes sets an in-scope origin filter so only records matching these
// (scheme, hostname, port) origins are returned.
func (s *RiskPrioritizedDBInputSource) WithHostScopes(hosts []HostTarget) *RiskPrioritizedDBInputSource {
	s.hostScopes = hosts
	return s
}

// WithParamShapeCoalescing enables param-shape coalescing of the snapshot:
// records that share a param shape (host + path shape + method +
// query/form/JSON param-name-set; see paramShapeRepresentative) are reduced to
// at most maxSamples value-distinct representatives, cutting redundant
// dynamic-assessment fan-out over value-only-different requests (e.g.
// /search?q=1..N, /users/1..N). Records stay in
// the database; only this scan's iteration list is pruned. The scan cursor still
// advances past every record, so coalesced-away records are not re-scanned in a
// later feedback round. maxSamples <= 0 (the default) disables it.
func (s *RiskPrioritizedDBInputSource) WithParamShapeCoalescing(maxSamples int) *RiskPrioritizedDBInputSource {
	s.maxParamShapeSamples = maxSamples
	return s
}

// CoalescedDropped returns how many records the param-shape coalescing pass
// removed from this scan's iteration list. Valid after the snapshot loads (i.e.
// after the first Next / after Execute). Zero when coalescing is disabled.
func (s *RiskPrioritizedDBInputSource) CoalescedDropped() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.coalescer != nil {
		return s.coalescer.dropped
	}
	return 0
}

// riskPageRow is the per-record projection each lane page selects: identity +
// ordering columns, plus the coalescing columns only when coalescing is enabled.
type riskPageRow struct {
	UUID                 string          `bun:"uuid"`
	CreatedAt            time.Time       `bun:"created_at"`
	RiskScore            int             `bun:"risk_score"`
	SurfaceScore         int             `bun:"surface_score"`
	Method               string          `bun:"method"`
	URL                  string          `bun:"url"`
	RequestContentType   string          `bun:"request_content_type"`
	RequestContentLength int64           `bun:"request_content_length"`
	Parameters           []EmbeddedParam `bun:"parameters,type:jsonb"`
}

func (r riskPageRow) desc() recordURLDesc {
	return recordURLDesc{
		method:        r.Method,
		url:           r.URL,
		contentType:   r.RequestContentType,
		contentLength: r.RequestContentLength,
		params:        r.Parameters,
	}
}

// Next streams records high-risk-first then chronologically, via bounded keyset
// pages, so memory scales with the page size (not the whole eligible table).
func (s *RiskPrioritizedDBInputSource) Next(ctx context.Context) (*work.WorkItem, error) {
	if s.closed.Load() {
		return nil, io.EOF
	}

	s.mu.Lock()
	if !s.loaded {
		if err := s.captureBoundLocked(ctx); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		s.loaded = true
	}
	if !s.hasBound {
		s.mu.Unlock()
		return nil, io.EOF
	}

	for {
		// Serve from the current page buffer first. Advancing a read cursor (rather
		// than re-slicing) keeps buffer pointing at the full backing array so the
		// buffer[:0] reset on refill reuses it.
		if s.bufHead < len(s.buffer) {
			record := s.buffer[s.bufHead]
			s.bufHead++
			s.mu.Unlock()

			rr, err := recordToHttpRequestResponse(record)
			if err != nil {
				// Parse failure: drop but still resolve it so the acked+skipped ==
				// total commit can be reached (one bad row must never stall the cursor).
				s.mu.Lock()
				s.skipped++
				s.maybeCommitCursorLocked()
				continue
			}

			var once sync.Once
			item := work.NewWithCallback(rr, nil, func() {
				once.Do(func() {
					s.ackSnapshotItem()
				})
			})
			item.RecordUUID = record.UUID
			if s.coverage {
				s.mu.Lock()
				if c, ok := s.coverageByUUID[record.UUID]; ok {
					item.Coverage = &work.Coverage{TierDone: c.TierDone, PassiveDone: c.PassiveDone, DoneBits: c.DoneBits}
					delete(s.coverageByUUID, record.UUID)
				}
				s.mu.Unlock()
			}
			return item, nil
		}

		// Buffer empty — pull the next page (advancing lanes as needed).
		more, err := s.fillNextPageLocked(ctx)
		if err != nil {
			s.mu.Unlock()
			return nil, err
		}
		if !more {
			// Both lanes drained: total is now final, so a pending commit can fire.
			s.streamsExhausted = true
			s.maybeCommitCursorLocked()
			s.mu.Unlock()
			return nil, io.EOF
		}
		// Loop: serve from the freshly filled buffer.
	}
}

// captureBoundLocked records the resume cursor and the snapshot's upper bound —
// the greatest (created_at, uuid) among eligible records right now — so the
// stream only reads records at/before it and records ingested mid-round are
// deferred to the next round (deterministic coverage). Sets hasBound=false when
// nothing is eligible. Caller holds s.mu.
func (s *RiskPrioritizedDBInputSource) captureBoundLocked(ctx context.Context) error {
	scan, err := s.repo.GetScanByUUID(ctx, s.scanUUID)
	if err != nil {
		return err
	}
	s.resumeAt = scan.CursorAt
	s.resumeID = scan.CursorUUID
	s.projectUUID = scan.ProjectUUID
	s.coalescer = newParamShapeCoalescer(s.maxParamShapeSamples)
	if s.coverage {
		// A failed probe reads the ledger per page as before.
		has, err := s.repo.HasRecordProgress(ctx, s.projectUUID, s.scanUUID)
		s.hasProgress = has || err != nil
	}

	type boundRow struct {
		CreatedAt time.Time `bun:"created_at"`
		UUID      string    `bun:"uuid"`
	}
	q := s.db.NewSelect().Model((*HTTPRecord)(nil)).Column("created_at", "uuid")
	if !s.resumeAt.IsZero() {
		at := dbTimestampString(s.db.Driver(), s.resumeAt)
		q = q.Where("(created_at > ? OR (created_at = ? AND uuid > ?))", at, at, s.resumeID)
	}
	q = applyHostScopeFilter(q, s.hostScopes)
	q = applyProjectFilter(q, s.projectUUID)
	q = applyEvidenceExclusion(q)

	var rows []boundRow
	if s.presetBound {
		rows = []boundRow{{CreatedAt: s.presetAt, UUID: s.presetID}}
	} else if err := q.OrderExpr("created_at DESC, uuid DESC").Limit(1).Scan(ctx, &rows); err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil // empty snapshot; hasBound stays false
	}
	s.boundAt = rows[0].CreatedAt
	s.boundID = rows[0].UUID
	s.hasBound = true

	// The round's eligible window is now fixed, so its size is too: count it
	// with the same window and scope the page queries use. Coalescing can only
	// drop records from it, which makes this an upper bound on what the round
	// serves. A failed count is a missing progress reading, not a failed round.
	cq := applyHostScopeFilter(s.applyResumeAndBound(s.db.NewSelect().Model((*HTTPRecord)(nil))), s.hostScopes)
	if n, err := cq.Count(ctx); err == nil {
		s.count.Store(int64(n))
	} else {
		zap.L().Debug("RiskPrioritizedDBInputSource: count eligible records", zap.Error(err))
	}
	return nil
}

// Count implements source.Countable: the number of records in this round's
// snapshot window, or 0 before the first Next (and for an empty snapshot). An
// upper bound on what the round serves, since param-shape coalescing removes
// records from it as pages are read.
func (s *RiskPrioritizedDBInputSource) Count() int64 {
	return s.count.Load()
}

// pageColumns is the projection each lane page selects — coalescing columns are
// included only when coalescing is enabled (they cost a JSONB decode per row).
func (s *RiskPrioritizedDBInputSource) pageColumns() []string {
	cols := []string{"uuid", "created_at", "risk_score", "surface_score", "method", "url"}
	if s.coalescer != nil {
		cols = append(cols, "request_content_type", "request_content_length", "parameters")
	}
	return cols
}

// applyResumeAndBound restricts a page query to the eligible window: strictly
// after the durable resume cursor and at/before the captured snapshot bound.
func (s *RiskPrioritizedDBInputSource) applyResumeAndBound(q *bun.SelectQuery) *bun.SelectQuery {
	if !s.resumeAt.IsZero() {
		at := dbTimestampString(s.db.Driver(), s.resumeAt)
		q = q.Where("(created_at > ? OR (created_at = ? AND uuid > ?))", at, at, s.resumeID)
	}
	boundAt := dbTimestampString(s.db.Driver(), s.boundAt)
	q = q.Where("(created_at < ? OR (created_at = ? AND uuid <= ?))", boundAt, boundAt, s.boundID)
	return applyEvidenceExclusion(applyProjectFilter(q, s.projectUUID))
}

// nextPageRowsLocked returns the next keyset page of eligible rows, ordered
// (risk_score DESC, surface_score DESC, created_at ASC, uuid ASC), one
// (risk, surface) bucket at a time. Returns (nil, nil) once the stream is
// drained. Caller holds s.mu.
func (s *RiskPrioritizedDBInputSource) nextPageRowsLocked(ctx context.Context) ([]riskPageRow, error) {
	if s.streamsExhausted {
		return nil, nil
	}
	for {
		if !s.bucketSet {
			ok, err := s.nextBucketLocked(ctx)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, nil // caller marks the stream exhausted
			}
		}

		var rows []riskPageRow
		if err := s.bucketPageQueryLocked().Scan(ctx, &rows); err != nil {
			return nil, err
		}
		if len(rows) > 0 {
			// Do NOT advance the keyset here. The caller advances it
			// (advanceKeyLocked) only after the page's records are either
			// coalesced away or successfully fetched, so a transient bulk-fetch
			// failure re-pulls THIS exact page instead of stepping past it. A
			// short page is the bucket's last: advancing past it steps to the
			// next bucket without an empty page query.
			s.lastPageInBucket = len(rows) < riskPrefetchBatchSize
			return rows, nil
		}
		// Bucket drained: step to the next lower one.
		s.bucketSet = false
	}
}

// bucketPageQueryLocked is the page query inside the current bucket.
func (s *RiskPrioritizedDBInputSource) bucketPageQueryLocked() *bun.SelectQuery {
	q := s.db.NewSelect().Model((*HTTPRecord)(nil)).Column(s.pageColumns()...)
	q = s.applyResumeAndBound(q)
	q = q.Where("risk_score = ?", s.bucketRisk).Where("surface_score = ?", s.bucketSurface)
	if s.started {
		at := dbTimestampString(s.db.Driver(), s.keyAt)
		q = q.Where("(created_at > ? OR (created_at = ? AND uuid > ?))", at, at, s.keyID)
	}
	q = applyHostScopeFilter(q, s.hostScopes)
	return q.OrderExpr("created_at ASC, uuid ASC").Limit(riskPrefetchBatchSize)
}

// nextBucketLocked selects the highest (risk_score, surface_score) bucket in
// the window strictly below the current one (or the top bucket on the first
// call). Returns false when no bucket remains. Caller holds s.mu.
func (s *RiskPrioritizedDBInputSource) nextBucketLocked(ctx context.Context) (bool, error) {
	type bucketRow struct {
		RiskScore    int `bun:"risk_score"`
		SurfaceScore int `bun:"surface_score"`
	}
	q := s.db.NewSelect().Model((*HTTPRecord)(nil)).Column("risk_score", "surface_score")
	q = s.applyResumeAndBound(q)
	if s.everStarted {
		q = q.Where("(risk_score < ? OR (risk_score = ? AND surface_score < ?))",
			s.bucketRisk, s.bucketRisk, s.bucketSurface)
	}
	q = applyHostScopeFilter(q, s.hostScopes)
	q = q.OrderExpr("risk_score DESC, surface_score DESC").Limit(1)
	var rows []bucketRow
	if err := q.Scan(ctx, &rows); err != nil {
		return false, err
	}
	if len(rows) == 0 {
		return false, nil
	}
	s.bucketRisk, s.bucketSurface = rows[0].RiskScore, rows[0].SurfaceScore
	s.bucketSet, s.started, s.everStarted = true, false, true
	return true, nil
}

// advanceKeyLocked steps the keyset past the given page's last row, and past
// the bucket when that page was its last. Caller holds s.mu.
func (s *RiskPrioritizedDBInputSource) advanceKeyLocked(last riskPageRow) {
	s.keyAt, s.keyID, s.started = last.CreatedAt, last.UUID, true
	if s.lastPageInBucket {
		s.bucketSet = false
	}
}

// fillNextPageLocked pulls keyset pages (applying coalescing) until it has a
// non-empty buffer of full records, or the stream is drained. Returns false when
// there is nothing left to serve. Caller holds s.mu; the lock is briefly released
// only across the bulk record fetch so ack callbacks aren't blocked.
func (s *RiskPrioritizedDBInputSource) fillNextPageLocked(ctx context.Context) (bool, error) {
	for {
		rows, err := s.nextPageRowsLocked(ctx)
		if err != nil {
			return false, err
		}
		if rows == nil {
			return false, nil // stream drained
		}

		last := rows[len(rows)-1]

		// Coalesce the page in priority order; survivors are the UUIDs to scan.
		// Selection does not mutate the coalescer — choosing survivors consumes
		// per-shape sample slots, and the fetch below can still fail, so the plan is
		// only committed once this page is actually served. See keepPlan.
		surviving, plan := s.coalescer.selectKeepers(rows)
		if len(surviving) == 0 {
			// Whole page coalesced away — nothing to fetch, so it's safe to step the
			// keyset past it and pull the next page.
			s.advanceKeyLocked(last)
			continue
		}

		// Read the coverage ledger before fetching bodies, so records it shows
		// finished for this pass's tier are never fetched. One ledger read per
		// page; a failed read serves the page without coverage — the work is
		// redone, never skipped.
		toFetch := surviving
		var finished int
		var cov map[string]RecordCoverage
		if s.coverage && s.hasProgress {
			_ = RetryBusy(ctx, func() error {
				s.mu.Unlock()
				defer s.mu.Lock()
				var err error
				cov, err = s.repo.LoadRecordProgress(ctx, s.projectUUID, s.scanUUID, surviving)
				return err
			}, s.pageRetryPolicy(ctx, "coverage ledger read"))
			if len(cov) > 0 {
				toFetch = make([]string, 0, len(surviving))
				for _, uuid := range surviving {
					if c, ok := cov[uuid]; ok && c.TierDone >= s.coverageMinTier {
						finished++
						continue
					}
					toFetch = append(toFetch, uuid)
				}
			}
		}

		// Fetch full records for the survivors, with a bounded retry so a transient
		// DB error (SQLITE_BUSY, a brief failover) doesn't drop the page. Release the
		// lock across each attempt so worker ack callbacks (ackSnapshotItem) aren't
		// blocked. Next() has a single caller, so no other goroutine advances the
		// lane state meanwhile.
		var records []*HTTPRecord
		if len(toFetch) > 0 {
			ferr := RetryBusy(ctx, func() error {
				s.mu.Unlock()
				defer s.mu.Lock()
				var err error
				records, err = s.repo.GetScanRecordsByUUIDs(ctx, toFetch)
				return err
			}, s.pageRetryPolicy(ctx, "risk-prioritized page fetch"))
			if ferr != nil {
				// The keyset was NOT advanced, so re-pulling this page after the error is
				// surfaced retries the exact same survivors — a transient failure becomes
				// retryable coverage instead of a silent hole committed as "complete".
				// Return the error rather than counting survivors as skipped.
				//
				// The uncommitted plan is simply discarded: had those choices been
				// recorded, the re-pull would see every row as a duplicate of itself,
				// survive nothing, and fall into the "whole page coalesced away" branch
				// above — stepping the keyset past a page that was never served.
				return false, fmt.Errorf("risk-prioritized page record fetch failed: %w", ferr)
			}
		}
		// Fetch succeeded: the page is ours, so the coalescing choices stick and it
		// is safe to advance the keyset and count survivors. Ledger-finished
		// records are resolved as skipped without being served.
		s.coalescer.commit(plan)
		s.advanceKeyLocked(last)
		s.total += len(surviving)
		s.skipped += finished
		for uuid, c := range cov {
			if c.TierDone < s.coverageMinTier {
				if s.coverageByUUID == nil {
					s.coverageByUUID = make(map[string]RecordCoverage)
				}
				s.coverageByUUID[uuid] = c
			}
		}

		byUUID := make(map[string]*HTTPRecord, len(records))
		for _, rec := range records {
			byUUID[rec.UUID] = rec
		}
		if s.buffer == nil {
			s.buffer = make([]*HTTPRecord, 0, riskPrefetchBatchSize)
		} else {
			s.buffer = s.buffer[:0]
		}
		s.bufHead = 0
		for _, uuid := range surviving {
			if rec, ok := byUUID[uuid]; ok {
				s.buffer = append(s.buffer, rec)
			}
		}
		// UUIDs the DB no longer returns (deleted between listing and fetch) are
		// never served; resolve them so they can't stall the cursor commit.
		// (Ledger-finished records were already counted as skipped above.)
		if missing := len(toFetch) - len(s.buffer); missing > 0 {
			s.skipped += missing
			s.maybeCommitCursorLocked()
		}
		if len(s.buffer) == 0 {
			continue // every survivor was missing; pull the next page
		}
		return true, nil
	}
}

func (s *RiskPrioritizedDBInputSource) ackSnapshotItem() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acked++
	s.maybeCommitCursorLocked()
}

// maybeCommitCursorLocked advances the durable scan cursor to the snapshot's
// upper bound once BOTH lanes are fully drained AND every survivor has been
// resolved (acknowledged by a worker or skipped as unservable). Gating on
// streamsExhausted is essential: the total grows as pages stream in, so an
// early acked+skipped == total (before the last page is pulled) must NOT commit.
// One-shot (guarded by s.committed). Caller holds s.mu.
//
// committed is set only AFTER the write succeeds. It used to be set before, so a
// failed checkpoint latched the source shut and reported nothing: the scan went
// on to record a clean completion while its durable cursor still sat at the
// start of the round, and the whole round's work was silently re-served (or, with
// a cursor inherited by a later scan, silently skipped). A failure now leaves the
// commit pending and keeps the error for FlushCursor to retry and report.
func (s *RiskPrioritizedDBInputSource) maybeCommitCursorLocked() {
	if s.committed || !s.streamsExhausted || s.noCommit {
		return
	}
	if s.acked+s.skipped < s.total {
		return
	}
	if err := s.writeCursorLocked(context.Background()); err != nil {
		zap.L().Warn("RiskPrioritizedDBInputSource: failed to acknowledge snapshot", zap.Error(err))
	}
}

// writeCursorLocked performs the checkpoint write and records its result. Caller
// holds s.mu.
func (s *RiskPrioritizedDBInputSource) writeCursorLocked(ctx context.Context) error {
	advance := s.advanceCursor
	if advance == nil {
		advance = s.repo.AdvanceScanCursorBy
	}
	if err := advance(ctx, s.scanUUID, s.boundAt, s.boundID, int64(s.total)); err != nil {
		s.commitErr = err
		return err
	}
	s.committed = true
	s.commitErr = nil
	return nil
}

// cursorFlushAttempts and cursorFlushBackoff bound FlushCursor's retry. Three
// attempts with a linear back-off mirrors the page-fetch retry in
// fillNextPageLocked: enough to ride out a SQLITE_BUSY window or a brief
// failover, short enough that a genuinely unreachable database is reported
// rather than waited on.
const (
	cursorFlushAttempts = 3
	cursorFlushBackoff  = 100 * time.Millisecond
)

// FlushCursor makes one last, reported attempt to checkpoint the round's cursor.
//
// The steady path commits from the ack that resolves the final item, on a
// background context, and logs a failure at warn level. That is the right place
// for it — the cursor must advance whether or not anyone is watching — but it
// leaves a phase with no way to learn that the checkpoint never landed. This is
// that call: the phase runs it after its executor returns and can turn a failure
// into a reported partial run instead of a clean one whose cursor lies.
//
// A no-op once committed, and a no-op while items are still unresolved (the
// commit has not become due yet, so there is nothing to flush). Returns the last
// error when the retries are exhausted.
func (s *RiskPrioritizedDBInputSource) FlushCursor(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.committed || !s.hasBound || s.noCommit {
		return nil
	}
	if !s.streamsExhausted || s.acked+s.skipped < s.total {
		// Not due: the round ended with work still unresolved. Report the last
		// write failure if there was one, but do not invent a checkpoint for items
		// nobody finished — leaving the cursor behind them is the correct outcome.
		return s.commitErr
	}

	var lastErr error
	err := RetryBusy(ctx, func() error {
		// A concurrent ack may have succeeded while the lock was released for
		// the previous wait.
		if s.committed {
			return nil
		}
		lastErr = s.writeCursorLocked(ctx)
		return lastErr
	}, s.pageRetryPolicy(ctx, "scan cursor checkpoint"))
	if err != nil && ctx.Err() != nil && lastErr != nil {
		// Cancelled mid-wait: report the write failure that was being retried,
		// not the bare context error, which says nothing about the checkpoint.
		return lastErr
	}
	return err
}

// pageRetryPolicy is the bounded retry both DB round-trips of this source share:
// cursorFlushAttempts tries, backing off from cursorFlushBackoff. Unlike the
// default policy it retries ANY error while ctx is live — a brief failover is as
// transient as SQLITE_BUSY here, and the alternative is a silently dropped page
// or an unacknowledged round. Callers hold s.mu, so the wait releases it: worker
// ack callbacks must not stall behind a sleeping retry.
func (s *RiskPrioritizedDBInputSource) pageRetryPolicy(ctx context.Context, op string) RetryPolicy {
	return RetryPolicy{
		Op:          op,
		MaxAttempts: cursorFlushAttempts,
		BaseDelay:   cursorFlushBackoff,
		MaxDelay:    time.Duration(cursorFlushAttempts) * cursorFlushBackoff,
		Retryable:   func(error) bool { return ctx.Err() == nil },
		Wait: func(ctx context.Context, d time.Duration) error {
			s.mu.Unlock()
			defer s.mu.Lock()
			return sleepCtx(ctx, d)
		},
	}
}

// Unresolved reports how many of this round's items ended neither acknowledged
// nor skipped — items a worker took and never finished, because the phase was
// cancelled or ran out of budget. Valid after the round's executor has returned.
func (s *RiskPrioritizedDBInputSource) Unresolved() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.total - s.acked - s.skipped; n > 0 {
		return n
	}
	return 0
}

// Close stops the source.
func (s *RiskPrioritizedDBInputSource) Close() error {
	s.closed.Store(true)
	return nil
}

// UUIDListDBInputSource iterates over a pre-defined list of HTTP record UUIDs,
// fetching each from the database and converting to WorkItems.
// It implements source.InputSource.
type UUIDListDBInputSource struct {
	repo   *Repository
	uuids  []string
	mu     sync.Mutex // guards index; the Source contract requires Next be concurrency-safe
	index  int
	closed atomic.Bool
}

// NewUUIDListDBInputSource creates a new UUIDListDBInputSource for the given UUIDs.
func NewUUIDListDBInputSource(repo *Repository, uuids []string) *UUIDListDBInputSource {
	return &UUIDListDBInputSource{
		repo:  repo,
		uuids: uuids,
	}
}

// Next returns the next record from the UUID list as a WorkItem.
// Skips invalid or missing UUIDs. Returns io.EOF when all UUIDs have been processed.
func (s *UUIDListDBInputSource) Next(ctx context.Context) (*work.WorkItem, error) {
	for {
		if s.closed.Load() {
			return nil, io.EOF
		}

		// Claim the next index under the mutex so concurrent Next() callers (the
		// Source contract permits them) never read the same UUID or race s.index.
		s.mu.Lock()
		if s.index >= len(s.uuids) {
			s.mu.Unlock()
			return nil, io.EOF
		}
		uuid := s.uuids[s.index]
		s.index++
		s.mu.Unlock()

		record, err := s.repo.GetRecordByUUID(ctx, uuid)
		if err != nil {
			zap.L().Debug("UUIDListDBInputSource: skipping UUID",
				zap.String("uuid", uuid), zap.Error(err))
			continue
		}

		rr, err := recordToHttpRequestResponse(record)
		if err != nil {
			zap.L().Warn("UUIDListDBInputSource: failed to convert record",
				zap.String("uuid", uuid), zap.Error(err))
			continue
		}

		item := work.NewWithModules(rr, nil)
		item.RecordUUID = record.UUID
		return item, nil
	}
}

// Close stops the source. After Close, Next will return io.EOF.
func (s *UUIDListDBInputSource) Close() error {
	s.closed.Store(true)
	return nil
}
