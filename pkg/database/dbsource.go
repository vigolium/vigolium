package database

import (
	"context"
	"database/sql"
	"io"
	"sync/atomic"
	"time"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// DBInputSource polls the database for HTTP records after the scan cursor and provides
// them as WorkItems. It implements source.InputSource.
type DBInputSource struct {
	db           *DB
	repo         *Repository
	scanUUID     string
	pollInterval time.Duration
	oneShot      bool // when true, return io.EOF instead of polling when no records remain
	closed       atomic.Bool
	hostnames    []string // when non-empty, only records matching these hostnames are returned
}

// NewDBInputSource creates a new DBInputSource that polls for records after the scan cursor at the given interval.
func NewDBInputSource(db *DB, repo *Repository, scanUUID string, pollInterval time.Duration) *DBInputSource {
	return &DBInputSource{
		db:           db,
		repo:         repo,
		scanUUID:     scanUUID,
		pollInterval: pollInterval,
	}
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

// WithHostnames sets a hostname filter so only records matching these hostnames are returned.
// This ensures that HTTP records from unrelated hosts (e.g. leftover from previous scans)
// are not included when the CLI targets a specific host.
func (s *DBInputSource) WithHostnames(hostnames []string) *DBInputSource {
	s.hostnames = hostnames
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

		// Fetch next record after cursor
		record, err := s.fetchNextRecord(ctx)
		if err != nil {
			if err == sql.ErrNoRows {
				if s.oneShot {
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

		// Convert record to HttpRequestResponse
		rr, err := s.recordToHttpRequestResponse(record)
		if err != nil {
			zap.L().Warn("DBInputSource: failed to convert record",
				zap.String("uuid", record.UUID), zap.Error(err))
			continue
		}

		item := work.NewWithModules(rr, nil)
		item.RecordUUID = record.UUID
		return item, nil
	}
}

// fetchNextRecord finds the next record after the scan's current cursor position
// and advances the cursor atomically within a single transaction.
func (s *DBInputSource) fetchNextRecord(ctx context.Context) (*HTTPRecord, error) {
	// Read current cursor
	scan, err := s.repo.GetScanByUUID(ctx, s.scanUUID)
	if err != nil {
		return nil, err
	}

	// Select next record after cursor.
	// Format cursor as plain string to match SQLite's CURRENT_TIMESTAMP format —
	// bun serializes time.Time with timezone suffix that breaks text comparison.
	record := &HTTPRecord{}
	q := s.db.NewSelect().Model(record)

	if !scan.CursorAt.IsZero() {
		cursorAt := scan.CursorAt.UTC().Format("2006-01-02 15:04:05")
		q = q.Where("(created_at > ? OR (created_at = ? AND uuid > ?))",
			cursorAt, cursorAt, scan.CursorUUID)
	}

	if len(s.hostnames) > 0 {
		q = q.Where("hostname IN (?)", bun.In(s.hostnames))
	}

	if err := q.OrderExpr("created_at ASC, uuid ASC").Limit(1).Scan(ctx); err != nil {
		return nil, err
	}

	// Advance cursor (already handles timezone formatting)
	if advErr := s.repo.AdvanceScanCursor(ctx, s.scanUUID, record.CreatedAt, record.UUID); advErr != nil {
		zap.L().Warn("DBInputSource: failed to advance cursor", zap.Error(advErr))
	}

	return record, nil
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
func recordToHttpRequestResponse(record *HTTPRecord) (*httpmsg.HttpRequestResponse, error) {
	// Prefer raw request if available
	if len(record.RawRequest) > 0 {
		rr, err := httpmsg.ParseRawRequest(string(record.RawRequest))
		if err != nil {
			return nil, err
		}
		// Attach response if present
		if record.HasResponse && len(record.RawResponse) > 0 {
			resp := httpmsg.NewHttpResponse(record.RawResponse)
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
	db           *DB
	repo         *Repository
	scanUUID     string
	highRiskDone atomic.Bool
	highRiskIdx  int
	highRiskUUIDs []string
	fallback     *DBInputSource
	hostnames    []string // when non-empty, only records matching these hostnames are returned
}

// NewRiskPrioritizedDBInputSource creates a DBInputSource that processes
// records with risk_score > 0 first (highest risk first), then continues
// with the normal cursor-based order for remaining records.
func NewRiskPrioritizedDBInputSource(db *DB, repo *Repository, scanUUID string) *RiskPrioritizedDBInputSource {
	return &RiskPrioritizedDBInputSource{
		db:       db,
		repo:     repo,
		scanUUID: scanUUID,
		fallback: &DBInputSource{
			db:       db,
			repo:     repo,
			scanUUID: scanUUID,
			oneShot:  true,
		},
	}
}

// WithHostnames sets a hostname filter so only records matching these hostnames are returned.
func (s *RiskPrioritizedDBInputSource) WithHostnames(hostnames []string) *RiskPrioritizedDBInputSource {
	s.hostnames = hostnames
	s.fallback.hostnames = hostnames
	return s
}

// Next returns records prioritized by risk_score, then falls back to cursor order.
func (s *RiskPrioritizedDBInputSource) Next(ctx context.Context) (*work.WorkItem, error) {
	if s.fallback.closed.Load() {
		return nil, io.EOF
	}

	// Phase 1: Serve high-risk records first
	if !s.highRiskDone.Load() {
		if s.highRiskUUIDs == nil {
			// Lazy-load high-risk UUIDs on first call
			uuids, err := s.loadHighRiskUUIDs(ctx)
			if err != nil {
				zap.L().Debug("RiskPrioritizedDBInputSource: failed to load high-risk UUIDs", zap.Error(err))
				s.highRiskUUIDs = []string{}
			} else {
				s.highRiskUUIDs = uuids
			}
		}

		for s.highRiskIdx < len(s.highRiskUUIDs) {
			uuid := s.highRiskUUIDs[s.highRiskIdx]
			s.highRiskIdx++

			record, err := s.repo.GetRecordByUUID(ctx, uuid)
			if err != nil {
				continue
			}

			rr, err := recordToHttpRequestResponse(record)
			if err != nil {
				continue
			}

			// Advance cursor past this record so fallback won't re-process it
			if advErr := s.repo.AdvanceScanCursor(ctx, s.scanUUID, record.CreatedAt, record.UUID); advErr != nil {
				zap.L().Debug("RiskPrioritizedDBInputSource: failed to advance cursor", zap.Error(advErr))
			}

			item := work.NewWithModules(rr, nil)
			item.RecordUUID = record.UUID
			return item, nil
		}

		s.highRiskDone.Store(true)
	}

	// Phase 2: Fall back to normal cursor-based order
	return s.fallback.Next(ctx)
}

// loadHighRiskUUIDs queries records with risk_score > 0 ordered by risk_score DESC.
func (s *RiskPrioritizedDBInputSource) loadHighRiskUUIDs(ctx context.Context) ([]string, error) {
	scan, err := s.repo.GetScanByUUID(ctx, s.scanUUID)
	if err != nil {
		return nil, err
	}

	var uuids []string
	q := s.db.NewSelect().Model((*HTTPRecord)(nil)).Column("uuid").
		Where("risk_score > 0").
		OrderExpr("risk_score DESC")

	if !scan.CursorAt.IsZero() {
		q = q.Where("(created_at > ? OR (created_at = ? AND uuid > ?))",
			scan.CursorAt, scan.CursorAt, scan.CursorUUID)
	}

	if len(s.hostnames) > 0 {
		q = q.Where("hostname IN (?)", bun.In(s.hostnames))
	}

	err = q.Scan(ctx, &uuids)
	return uuids, err
}

// Close stops the source.
func (s *RiskPrioritizedDBInputSource) Close() error {
	return s.fallback.Close()
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
