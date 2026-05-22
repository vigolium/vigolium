package database

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// Canonical values for http_records.source. Kept here (rather than inline
// string literals at call sites) so the scan-on-receive filter and the
// ingest writers agree on a single set of labels.
const (
	RecordSourceIngestServer = "ingest-server" // POST /api/ingest-http
	RecordSourceIngestProxy  = "ingest-proxy"  // transparent ingest proxy capture
	RecordSourceIngestCLI    = "ingest-cli"    // `vigolium ingest ...` command
	RecordSourceScanner      = "scanner"       // executor feedback re-injection
	RecordSourceFinding      = "finding"       // request/response attached to a finding
)

// IngestRecordSources lists the http_records.source values that represent
// user-ingested traffic. Scan-on-receive filters the DBInputSource by this
// list so it only processes traffic the user actually ingested — excluding
// scanner-produced artefacts that would otherwise cause fan-out.
var IngestRecordSources = []string{
	RecordSourceIngestServer,
	RecordSourceIngestProxy,
	RecordSourceIngestCLI,
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
	hostnames      []string // when non-empty, only records matching these hostnames are returned
	includeSources []string // when non-empty, only records with source IN this list are returned
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
	readCursorAt   time.Time
	readCursorUUID string
	nextSeq        uint64
	nextAckSeq     uint64
	pendingBySeq   map[uint64]*cursorAck
}

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

// WithHostnames sets a hostname filter so only records matching these hostnames are returned.
// This ensures that HTTP records from unrelated hosts (e.g. leftover from previous scans)
// are not included when the CLI targets a specific host.
func (s *DBInputSource) WithHostnames(hostnames []string) *DBInputSource {
	s.hostnames = hostnames
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
		s.readCursorInit = true
	}

	// Select next records after cursor.
	// Format cursor as plain string to match SQLite's CURRENT_TIMESTAMP format —
	// bun serializes time.Time with timezone suffix that breaks text comparison.
	var records []*HTTPRecord
	q := s.db.NewSelect().Model(&records)

	if !s.readCursorAt.IsZero() {
		cursorAt := s.readCursorAt.UTC().Format("2006-01-02 15:04:05")
		q = q.Where("(created_at > ? OR (created_at = ? AND uuid > ?))",
			cursorAt, cursorAt, s.readCursorUUID)
	}

	if len(s.hostnames) > 0 {
		q = q.Where("hostname IN (?)", bun.In(s.hostnames))
	}

	if len(s.includeSources) > 0 {
		q = q.Where("source IN (?)", bun.In(s.includeSources))
	}

	limit := s.pageSize
	if limit <= 0 {
		limit = 128
	}
	if err := q.OrderExpr("created_at ASC, uuid ASC").Limit(limit).Scan(ctx); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, sql.ErrNoRows
	}

	last := records[len(records)-1]
	s.readCursorAt = last.CreatedAt
	s.readCursorUUID = last.UUID

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

func (s *DBInputSource) workItemFromRecord(record *HTTPRecord, seq uint64) (*work.WorkItem, error) {
	rr, err := s.recordToHttpRequestResponse(record)
	if err != nil {
		s.mu.Lock()
		delete(s.pendingBySeq, seq)
		if s.nextAckSeq == seq {
			s.nextAckSeq++
		}
		s.mu.Unlock()
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

	for {
		head, ok := s.pendingBySeq[s.nextAckSeq]
		if !ok || !head.acked {
			break
		}
		delete(s.pendingBySeq, s.nextAckSeq)
		s.nextAckSeq++
		if err := s.repo.AdvanceScanCursorBy(context.Background(), s.scanUUID, head.createdAt, head.uuid, 1); err != nil {
			zap.L().Warn("DBInputSource: failed to acknowledge cursor", zap.Error(err))
			return
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

// RiskPrioritizedDBInputSource processes high-risk records first, then falls back
// to normal cursor-based order. It implements source.InputSource.
type RiskPrioritizedDBInputSource struct {
	db             *DB
	repo           *Repository
	scanUUID       string
	hostnames      []string // when non-empty, only records matching these hostnames are returned
	closed         atomic.Bool
	mu             sync.Mutex
	loaded         bool
	index          int
	uuids          []string
	total          int
	acked          int
	commitCursorAt time.Time
	commitCursorID string
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

// WithHostnames sets a hostname filter so only records matching these hostnames are returned.
func (s *RiskPrioritizedDBInputSource) WithHostnames(hostnames []string) *RiskPrioritizedDBInputSource {
	s.hostnames = hostnames
	return s
}

// Next returns records prioritized by risk_score, then falls back to cursor order.
func (s *RiskPrioritizedDBInputSource) Next(ctx context.Context) (*work.WorkItem, error) {
	if s.closed.Load() {
		return nil, io.EOF
	}

	s.mu.Lock()
	if !s.loaded {
		if err := s.loadSnapshotLocked(ctx); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		s.loaded = true
	}
	for s.index < len(s.uuids) {
		uuid := s.uuids[s.index]
		s.index++
		s.mu.Unlock()

		record, err := s.repo.GetRecordByUUID(ctx, uuid)
		if err != nil {
			s.mu.Lock()
			continue
		}

		rr, err := recordToHttpRequestResponse(record)
		if err != nil {
			s.mu.Lock()
			continue
		}

		var once sync.Once
		item := work.NewWithCallback(rr, nil, func() {
			once.Do(func() {
				s.ackSnapshotItem()
			})
		})
		item.RecordUUID = record.UUID
		return item, nil
	}
	s.mu.Unlock()
	return nil, io.EOF
}

func (s *RiskPrioritizedDBInputSource) loadSnapshotLocked(ctx context.Context) error {
	scan, err := s.repo.GetScanByUUID(ctx, s.scanUUID)
	if err != nil {
		return err
	}

	type cursorRow struct {
		UUID      string    `bun:"uuid"`
		CreatedAt time.Time `bun:"created_at"`
	}

	var ordered []cursorRow
	orderedQ := s.db.NewSelect().Model((*HTTPRecord)(nil)).Column("uuid", "created_at")

	if !scan.CursorAt.IsZero() {
		cursorAt := scan.CursorAt.UTC().Format("2006-01-02 15:04:05")
		orderedQ = orderedQ.Where("(created_at > ? OR (created_at = ? AND uuid > ?))",
			cursorAt, cursorAt, scan.CursorUUID)
	}

	if len(s.hostnames) > 0 {
		orderedQ = orderedQ.Where("hostname IN (?)", bun.In(s.hostnames))
	}

	if err := orderedQ.OrderExpr("created_at ASC, uuid ASC").Scan(ctx, &ordered); err != nil {
		return err
	}
	if len(ordered) == 0 {
		return nil
	}

	var highRisk []string
	riskQ := s.db.NewSelect().Model((*HTTPRecord)(nil)).Column("uuid").
		Where("risk_score > 0").
		OrderExpr("risk_score DESC")

	if !scan.CursorAt.IsZero() {
		cursorAt := scan.CursorAt.UTC().Format("2006-01-02 15:04:05")
		riskQ = riskQ.Where("(created_at > ? OR (created_at = ? AND uuid > ?))",
			cursorAt, cursorAt, scan.CursorUUID)
	}

	if len(s.hostnames) > 0 {
		riskQ = riskQ.Where("hostname IN (?)", bun.In(s.hostnames))
	}

	if err := riskQ.Scan(ctx, &highRisk); err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(ordered))
	s.uuids = make([]string, 0, len(ordered))
	for _, uuid := range highRisk {
		if _, ok := seen[uuid]; ok {
			continue
		}
		seen[uuid] = struct{}{}
		s.uuids = append(s.uuids, uuid)
	}
	for _, row := range ordered {
		if _, ok := seen[row.UUID]; ok {
			continue
		}
		seen[row.UUID] = struct{}{}
		s.uuids = append(s.uuids, row.UUID)
	}

	last := ordered[len(ordered)-1]
	s.commitCursorAt = last.CreatedAt
	s.commitCursorID = last.UUID
	s.total = len(s.uuids)
	return nil
}

func (s *RiskPrioritizedDBInputSource) ackSnapshotItem() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.total == 0 {
		return
	}
	s.acked++
	if s.acked != s.total {
		return
	}
	if err := s.repo.AdvanceScanCursorBy(context.Background(), s.scanUUID, s.commitCursorAt, s.commitCursorID, int64(s.total)); err != nil {
		zap.L().Warn("RiskPrioritizedDBInputSource: failed to acknowledge snapshot", zap.Error(err))
	}
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

		if s.index >= len(s.uuids) {
			return nil, io.EOF
		}

		uuid := s.uuids[s.index]
		s.index++

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
